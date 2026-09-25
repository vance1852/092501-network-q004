from __future__ import annotations

import sqlite3
import unittest

from urban_network.models import Certificate, Reading, Segment, certificate_state
from urban_network.service import NetworkService

FROM = "2026-01-01T00:00:00+00:00"
TO = "2026-07-01T00:00:00+00:00"


class CalibrationTests(unittest.TestCase):
    def setUp(self):
        self.s = NetworkService()
        self.s.bootstrap()
        self.admin = self.s.auth.login("admin", "network-admin")
        self.quality = self.s.auth.login("quality", "network-quality")
        self.operator = self.s.auth.login("operator", "network-operator")
        self.s.register_segment(self.admin, Segment("S1", "east", "water", 100, 4))
        self.cert = Certificate("C1", "sensor-1", "市级计量院", FROM, TO, 0, 1000)
        self.s.register_certificate(self.admin, self.cert)

    def reading(self, rid="R1", when="2026-03-01T00:00:00+00:00", pressure=350, sensor="sensor-1", cert="C1", segment="S1"):
        return Reading(rid, segment, sensor, pressure, 20, 50, when, cert)

    def test_certificate_version_is_monotonic_and_duplicate_is_idempotent(self):
        again = self.s.register_certificate(self.admin, self.cert)
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["version"], 1)
        second = self.s.register_certificate(self.admin, Certificate("C2", "sensor-1", "市级计量院", TO, "2027-01-01T00:00:00+00:00", 0, 1000))
        self.assertEqual(second["version"], 2)
        changed = Certificate("C1", "sensor-1", "其他机构", FROM, TO, 0, 1000)
        with self.assertRaises(ValueError):
            self.s.register_certificate(self.admin, changed)
        history = self.s.sensor_certificates(self.quality, "sensor-1")
        self.assertEqual([c["version"] for c in history], [1, 2])

    def test_half_open_window_boundaries_have_one_answer(self):
        self.assertEqual(certificate_state(FROM, TO, None, FROM), "valid")
        self.assertEqual(certificate_state(FROM, TO, None, TO), "expired")
        # 两本首尾相接的证书在交界时刻只属于新证书
        self.s.register_certificate(self.admin, Certificate("C2", "sensor-1", "市级计量院", TO, "2027-01-01T00:00:00+00:00", 0, 1000))
        boundary = self.s.ingest_reading(self.admin, self.reading("AT-BOUNDARY", TO, cert="C2"))
        self.assertFalse(boundary["duplicate"])
        self.assertEqual(boundary["certificate_version"], 2)
        with self.assertRaises(ValueError):
            self.s.ingest_reading(self.admin, self.reading("AT-END", TO, cert="C1"))

    def test_reading_requires_valid_certificate_at_sampling_time(self):
        self.s.ingest_reading(self.admin, self.reading())
        with self.assertRaises(KeyError):
            self.s.ingest_reading(self.admin, self.reading("NO-CERT", cert="MISSING"))
        with self.assertRaises(ValueError):
            self.s.ingest_reading(self.admin, self.reading("WRONG-SENSOR", sensor="sensor-2"))
        with self.assertRaises(ValueError):
            self.s.ingest_reading(self.admin, self.reading("FUTURE", "2025-12-31T23:59:59+00:00"))
        with self.assertRaises(ValueError):
            self.s.ingest_reading(self.admin, self.reading("PAST", "2026-07-01T00:00:01+00:00"))
        with self.assertRaises(ValueError):
            self.s.ingest_reading(self.admin, self.reading("OVER-RANGE", pressure=1001))
        self.assertEqual(self.s.risk_report(self.quality, "S1")["readings"], 1)

    def test_revoked_certificate_cannot_serve_production_readings(self):
        self.s.register_certificate(self.admin, Certificate("C-REV", "sensor-rev", "市级计量院", "2026-01-01T00:00:00+00:00", "2027-01-01T00:00:00+00:00", 0, 1000))
        self.s.revoke_certificate(self.admin, "C-REV", "签发机构资质注销")
        with self.assertRaises(ValueError):
            self.s.ingest_reading(self.admin, self.reading("AFTER-REVOKE", "2026-09-26T00:00:00+00:00", sensor="sensor-rev", cert="C-REV"))
        again = self.s.revoke_certificate(self.admin, "C-REV", "重复撤销")
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["status"], "revoked")

    def test_revocation_boundary_is_half_open_in_model(self):
        revoked_at = "2026-04-01T00:00:00+00:00"
        self.assertEqual(certificate_state(FROM, TO, revoked_at, "2026-03-31T23:59:59+00:00"), "valid")
        self.assertEqual(certificate_state(FROM, TO, revoked_at, revoked_at), "revoked")

    def test_certificate_content_is_immutable_but_status_can_change(self):
        self.s.ingest_reading(self.admin, self.reading())
        with self.assertRaises(sqlite3.IntegrityError):
            self.s.db.execute("UPDATE calibration_certificates SET issuer='伪造机构' WHERE certificate_id='C1'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.s.db.execute("UPDATE calibration_certificates SET range_max_kpa=5000 WHERE certificate_id='C1'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.s.db.execute("DELETE FROM calibration_certificates WHERE certificate_id='C1'")
        self.s.db.rollback()

    def test_reissue_never_rewrites_snapshot_on_historical_readings(self):
        first = self.s.ingest_reading(self.admin, self.reading())
        self.assertEqual((first["certificate_id"], first["certificate_version"]), ("C1", 1))
        self.s.revoke_certificate(self.admin, "C1", "计量偏差调查")
        self.s.register_certificate(self.admin, Certificate("C3", "sensor-1", "市级计量院", "2026-04-01T00:00:00+00:00", "2027-01-01T00:00:00+00:00", 0, 1000))
        stored = self.s.db.execute("SELECT certificate_id,certificate_version FROM readings WHERE reading_id='R1'").fetchone()
        self.assertEqual(tuple(stored), ("C1", 1))
        detail = self.s.certificate_readings(self.quality, "C1")["readings"][0]
        self.assertEqual(detail["calibration_state_at_sampling"], "valid")
        self.assertEqual(detail["calibration_state_current"], "revoked")

    def test_quality_can_trace_affected_segments_readings_and_alerts(self):
        # 高压读数触发告警；证书事后撤销，告警与读数都应可追溯
        result = self.s.ingest_reading(self.admin, self.reading("BAD", pressure=600))
        self.assertIsNotNone(result["alert_id"])
        self.s.register_certificate(self.admin, Certificate("C2", "sensor-1", "市级计量院", TO, "2027-01-01T00:00:00+00:00", 0, 1000))
        self.s.ingest_reading(self.admin, self.reading("GOOD", "2026-07-02T00:00:00+00:00", pressure=350, cert="C2"))
        self.s.revoke_certificate(self.admin, "C1", "过期证书未及时下架")
        affected = self.s.affected_readings(self.quality, segment_id="S1")
        self.assertEqual(affected["segments"], [{"segment_id": "S1", "affected_readings": 1, "affected_alerts": 1}])
        self.assertEqual([r["reading_id"] for r in affected["readings"]], ["BAD"])
        self.assertTrue(affected["readings"][0]["raised_alert"])
        report = self.s.risk_report(self.quality, "S1")
        self.assertEqual(report["calibration_flagged_readings"], 1)
        alert = next(a for a in report["alerts"] if a["alert_id"] == result["alert_id"])
        self.assertEqual(alert["calibration_state_at_sampling"], "valid")
        self.assertEqual(alert["calibration_state_current"], "revoked")
        self.assertEqual(alert["certificate_id"], "C1")

    def test_role_boundaries_admin_revokes_quality_queries(self):
        with self.assertRaises(PermissionError):
            self.s.register_certificate(self.quality, self.cert)
        with self.assertRaises(PermissionError):
            self.s.revoke_certificate(self.quality, "C1", "质量人员无权撤销")
        with self.assertRaises(PermissionError):
            self.s.affected_readings(self.operator, segment_id="S1")
        self.assertEqual(self.s.affected_readings(self.quality, segment_id="S1")["readings"], [])

    def test_duplicate_reading_with_different_id_is_rejected_deterministically(self):
        self.s.ingest_reading(self.admin, self.reading("DUP-1"))
        with self.assertRaises(ValueError):
            self.s.ingest_reading(self.admin, self.reading("DUP-2"))
        # 同一 reading_id 重放仍然是幂等成功
        replay = self.s.ingest_reading(self.admin, self.reading("DUP-1"))
        self.assertTrue(replay["duplicate"])


if __name__ == "__main__":
    unittest.main()
