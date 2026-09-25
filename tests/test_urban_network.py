import sqlite3
import unittest
from urban_network.models import Certificate, Reading, Sensor, Segment
from urban_network.risk import score_reading
from urban_network.service import CalibrationError, NetworkService

CERT = ("CERT-1", "sensor", 1, "2025-01-01T00:00:00+00:00", "2027-01-01T00:00:00+00:00", 0.0, 1000.0, "metrology-lab")

class UrbanNetworkTests(unittest.TestCase):
    def setUp(self):
        self.s = NetworkService(); self.s.bootstrap()
        self.t = self.s.auth.login("admin", "network-admin")
        self.s.register_segment(self.t, Segment("S1", "east", "drainage", 100, 4))
        self.s.register_sensor(self.t, Sensor("sensor", "S1", "PT-3000"))
        self.s.issue_certificate(self.t, Certificate(*CERT))
        self.quality = self.s.auth.create_user("qa", "quality-pass", "quality")
        self.qt = self.s.auth.login("qa", "quality-pass")

    # ---- 基线流程仍成立 ----
    def test_risk_and_idempotent_reading(self):
        r = Reading("R1", "S1", "sensor", 120, 250, 90, "2026-01-01T00:00:00+00:00")
        a = self.s.ingest_reading(self.t, r); b = self.s.ingest_reading(self.t, r)
        self.assertFalse(a["duplicate"]); self.assertTrue(b["duplicate"])
        self.assertEqual((a["certificate_id"], a["certificate_version"]), ("CERT-1", 1))
        self.assertEqual(self.s.risk_report(self.t, "S1")["readings"], 1)

    def test_work_order_and_allocation(self):
        r = self.s.ingest_reading(self.t, Reading("R2", "S1", "sensor", 100, 250, 90, "2026-01-01T00:00:00+00:00"))
        o = self.s.create_work_order(self.t, "S1", r["alert_id"], "crew")
        self.s.transition_work_order(self.t, o["work_order_id"], "assigned", "crew accepted")
        self.s.add_resource(self.t, "R1", "pump", "east", 2)
        self.assertFalse(self.s.allocate(self.t, "R1", o["work_order_id"], 1)["duplicate"])
        self.assertEqual(self.s.resource(self.t, "R1")["available"], 1)

    def test_risk_validation(self):
        with self.assertRaises(ValueError): score_reading(-1, 1, 1, 2)

    # ---- 设备台账 ----
    def test_sensor_ledger_required_and_mounted_on_segment(self):
        with self.assertRaises(CalibrationError):
            self.s.ingest_reading(self.t, Reading("R3", "S1", "ghost", 100, 1, 1, "2026-01-01T00:00:00+00:00"))
        self.s.register_segment(self.t, Segment("S2", "west", "water", 50, 2))
        with self.assertRaises(CalibrationError):
            self.s.ingest_reading(self.t, Reading("R4", "S2", "sensor", 100, 1, 1, "2026-01-01T00:00:00+00:00"))

    def test_sensor_registration_is_deterministic(self):
        first = self.s.register_sensor(self.t, Sensor("sensor", "S1", "PT-3000"))
        again = self.s.register_sensor(self.t, Sensor("sensor", "S1", "PT-3000"))
        self.assertEqual(first["sensor_id"], again["sensor_id"]); self.assertTrue(again["duplicate"])
        with self.assertRaises(ValueError):
            self.s.register_sensor(self.t, Sensor("sensor", "S1", "PT-9999"))

    # ---- 证书签发与重复登记 ----
    def test_certificate_fields_and_duplicate_registration(self):
        again = self.s.issue_certificate(self.t, Certificate(*CERT))
        self.assertTrue(again["duplicate"])
        stored = self.s.certificate(self.t, "CERT-1")
        self.assertEqual((stored["issuer"], stored["version"], stored["range_min"], stored["range_max"], stored["revoked"]),
                         ("metrology-lab", 1, 0.0, 1000.0, False))
        self.assertEqual(len(stored["record_hash"]), 64)

    def test_certificate_conflicts_are_rejected(self):
        with self.assertRaises(ValueError):  # 同号不同内容
            self.s.issue_certificate(self.t, Certificate("CERT-1", "sensor", 1, CERT[3], CERT[4], 0.0, 900.0, "other-lab"))
        with self.assertRaises(ValueError):  # 同传感器同版本不同证号
            self.s.issue_certificate(self.t, Certificate("CERT-1B", "sensor", 1, CERT[3], CERT[4], 0.0, 1000.0, "metrology-lab"))
        with self.assertRaises(ValueError):  # 版本号必须严格递增
            self.s.issue_certificate(self.t, Certificate("CERT-2", "sensor", 1, CERT[3], CERT[4], 0.0, 1000.0, "metrology-lab"))

    def test_certificate_interval_and_range_validation(self):
        with self.assertRaises(ValueError):
            self.s.issue_certificate(self.t, Certificate("CERT-BAD1", "sensor", 2, "2027-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00", 0, 1, "lab"))
        with self.assertRaises(ValueError):
            self.s.issue_certificate(self.t, Certificate("CERT-BAD2", "sensor", 2, "2026-01-01T00:00:00+00:00", None, 9, 1, "lab"))

    # ---- 读数接收时的证书校验 ----
    def test_reading_requires_certificate_valid_at_sample_time(self):
        self.s.issue_certificate(self.t, Certificate("CERT-EXPIRED", "sensor", 2, "2020-01-01T00:00:00+00:00", "2020-06-01T00:00:00+00:00", 0, 1000, "lab"))
        with self.assertRaises(CalibrationError):  # 未来才生效
            self.s.ingest_reading(self.t, Reading("R5", "S1", "sensor", 100, 1, 1, "2024-12-31T23:59:59+00:00"))
        with self.assertRaises(CalibrationError):  # 已过期
            self.s.ingest_reading(self.t, Reading("R6", "S1", "sensor", 100, 1, 1, "2027-01-02T00:00:00+00:00"))

    def test_boundary_moments_are_deterministic(self):
        # 有效区间为闭区间：端点时刻仍可用于生产读数
        ok_from = self.s.ingest_reading(self.t, Reading("R7", "S1", "sensor", 100, 1, 1, "2025-01-01T00:00:00+00:00"))
        ok_to = self.s.ingest_reading(self.t, Reading("R8", "S1", "sensor", 100, 1, 1, "2027-01-01T00:00:00+00:00"))
        self.assertEqual(ok_from["certificate_version"], ok_to["certificate_version"])
        # 量程边界同样是闭区间
        edge = self.s.ingest_reading(self.t, Reading("R9", "S1", "sensor", 1000.0, 1, 1, "2026-02-01T00:00:00+00:00"))
        self.assertFalse(edge["duplicate"])
        with self.assertRaises(CalibrationError):
            self.s.ingest_reading(self.t, Reading("R10", "S1", "sensor", 1000.5, 1, 1, "2026-02-01T00:01:00+00:00"))

    def test_revocation_boundary_blocks_ingestion_at_exact_instant(self):
        # 撤销自 revoked_at 整时刻起失效；该时刻的读数被拒绝
        self.s.revoke_certificate(self.t, "CERT-1", "batch recall")
        rev = self.s.db.execute("SELECT revoked_at FROM certificate_revocations WHERE certificate_id='CERT-1'").fetchone()["revoked_at"]
        with self.assertRaises(CalibrationError):
            self.s.ingest_reading(self.t, Reading("R11", "S1", "sensor", 100, 1, 1, rev))
        self.assertTrue(self.s.certificate(self.t, "CERT-1")["revoked"])

    def test_revocation_is_admin_only_and_deterministic(self):
        with self.assertRaises(PermissionError):
            self.s.revoke_certificate(self.qt, "CERT-1", "quality cannot revoke")
        first = self.s.revoke_certificate(self.t, "CERT-1", "batch recall")
        again = self.s.revoke_certificate(self.t, "CERT-1", "batch recall")
        self.assertFalse(first["duplicate"]); self.assertTrue(again["duplicate"])
        with self.assertRaises(ValueError):
            self.s.revoke_certificate(self.t, "CERT-1", "a different reason")
        with self.assertRaises(KeyError):
            self.s.revoke_certificate(self.t, "CERT-MISSING", "x")

    # ---- 不可变版本 ----
    def test_certificate_records_are_immutable(self):
        with self.assertRaises(sqlite3.Error):
            self.s.db.execute("UPDATE certificates SET issuer='hacker' WHERE certificate_id='CERT-1'")
        self.s.db.rollback()
        with self.assertRaises(sqlite3.Error):
            self.s.db.execute("DELETE FROM certificates WHERE certificate_id='CERT-1'")
        self.s.db.rollback()
        self.s.revoke_certificate(self.t, "CERT-1", "batch recall")
        with self.assertRaises(sqlite3.Error):
            self.s.db.execute("DELETE FROM certificate_revocations WHERE certificate_id='CERT-1'")
        self.s.db.rollback()
        with self.assertRaises(sqlite3.Error):
            self.s.db.execute("UPDATE certificate_revocations SET reason='x' WHERE certificate_id='CERT-1'")
        self.s.db.rollback()

    def test_reissued_certificate_cannot_rewrite_historical_reference(self):
        r = self.s.ingest_reading(self.t, Reading("R12", "S1", "sensor", 100, 1, 1, "2026-03-01T00:00:00+00:00"))
        self.assertEqual(r["certificate_version"], 1)
        self.s.issue_certificate(self.t, Certificate("CERT-2", "sensor", 2, "2026-06-01T00:00:00+00:00", "2028-01-01T00:00:00+00:00", 0, 1000, "lab"))
        stored = self.s.db.execute("SELECT certificate_id,certificate_version FROM readings WHERE reading_id='R12'").fetchone()
        self.assertEqual((stored["certificate_id"], stored["certificate_version"]), ("CERT-1", 1))
        with self.assertRaises(sqlite3.Error):  # 历史读数引用被冻结
            self.s.db.execute("UPDATE readings SET certificate_version=2 WHERE reading_id='R12'")
        self.s.db.rollback()
        # 补发证书生效后，新读数引用新版本
        new = self.s.ingest_reading(self.t, Reading("R13", "S1", "sensor", 100, 1, 1, "2026-07-01T00:00:00+00:00"))
        self.assertEqual((new["certificate_id"], new["certificate_version"]), ("CERT-2", 2))
        # 但旧证书覆盖期内的读数仍按当时最高版本 v1 解析
        old_window = self.s.ingest_reading(self.t, Reading("R14", "S1", "sensor", 100, 1, 1, "2026-05-01T00:00:00+00:00"))
        self.assertEqual(old_window["certificate_version"], 1)

    # ---- 质量追溯 ----
    def test_quality_can_trace_revoked_and_expired_readings(self):
        self.s.ingest_reading(self.t, Reading("R15", "S1", "sensor", 100, 1, 1, "2026-04-01T00:00:00+00:00"))
        self.s.revoke_certificate(self.t, "CERT-1", "batch recall")
        affected = self.s.affected_readings(self.qt, "S1")
        self.assertEqual({x["reading_id"] for x in affected}, {"R15"})
        self.assertTrue(all(x["reason"] == "revoked" for x in affected))
        summary = self.s.affected_segments(self.qt)
        row = next(x for x in summary if x["segment_id"] == "S1" and x["certificate_id"] == "CERT-1")
        self.assertEqual(row["reading_count"], 1)

    def test_expired_certificate_readings_are_traced(self):
        self.s.register_sensor(self.t, Sensor("sensor2", "S1", "PT-100"))
        self.s.issue_certificate(self.t, Certificate("CERT-OLD", "sensor2", 1, "2020-01-01T00:00:00+00:00", "2020-12-31T00:00:00+00:00", 0, 1000, "lab"))
        self.s.ingest_reading(self.t, Reading("R16", "S1", "sensor2", 100, 1, 1, "2020-06-01T00:00:00+00:00"))
        row = next(x for x in self.s.affected_segments(self.qt) if x["certificate_id"] == "CERT-OLD")
        self.assertEqual(row["reason"], "expired")

    def test_risk_report_flags_alert_calibration_status(self):
        r = self.s.ingest_reading(self.t, Reading("R17", "S1", "sensor", 100, 250, 90, "2026-04-02T00:00:00+00:00"))
        self.assertEqual(self.s.risk_report(self.qt, "S1")["alerts"][0]["calibration_status"], "valid")
        self.s.revoke_certificate(self.t, "CERT-1", "batch recall")
        alert = next(a for a in self.s.risk_report(self.qt, "S1")["alerts"] if a["alert_id"] == r["alert_id"])
        self.assertEqual(alert["calibration_status"], "revoked")

    def test_operator_cannot_issue_certificates_or_query_quality_views(self):
        ot = self.s.auth.login("operator", "network-operator")
        with self.assertRaises(PermissionError):
            self.s.issue_certificate(ot, Certificate("CERT-X", "sensor", 9, "2026-01-01T00:00:00+00:00", None, 0, 1, "lab"))
        with self.assertRaises(PermissionError):
            self.s.affected_readings(ot)

if __name__ == "__main__":
    unittest.main()
