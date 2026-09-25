"""离线命令行验收入口。"""
from __future__ import annotations
import argparse,json
from .models import Certificate,Reading,Sensor,Segment
from .service import NetworkService
def run():
    s=NetworkService(); s.bootstrap(); t=s.auth.login("admin","network-admin")
    s.register_segment(t,Segment("SEG-DEMO","north","water",680,5))
    s.register_sensor(t,Sensor("sensor-01","SEG-DEMO","PT-3000"))
    s.issue_certificate(t,Certificate("CERT-DEMO-1","sensor-01",1,"2026-09-01T00:00:00+00:00","2027-09-01T00:00:00+00:00",0.0,1000.0,"metrology-lab-A"))
    r=s.ingest_reading(t,Reading("RD-DEMO","SEG-DEMO","sensor-01",160,230,88,"2026-09-24T10:00:00+00:00"))
    report=s.risk_report(t,"SEG-DEMO")
    order=s.create_work_order(t,"SEG-DEMO",r["alert_id"],"crew-north",1); s.add_resource(t,"PUMP-01","mobile-pump","north",2); allocation=s.allocate(t,"PUMP-01",order["work_order_id"],1)
    # 证书事后被撤销：历史读数保留当时引用的版本，告警与质量查询立即标红。
    s.revoke_certificate(t,"CERT-DEMO-1","过期批次，计量复核不合格")
    report_after=s.risk_report(t,"SEG-DEMO"); affected=s.affected_readings(t,"SEG-DEMO")
    return {"status":"ok","segment":"SEG-DEMO","severity":r["risk"]["severity"],"probability":report["leak_probability"],"allocation":allocation["allocation_id"],"certificate_id":r["certificate_id"],"certificate_version":r["certificate_version"],"alert_calibration_status":report_after["alerts"][0]["calibration_status"],"affected_readings":len(affected)}
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--workspace",default="."); parser.parse_args(); print(json.dumps(run(),ensure_ascii=False))
if __name__=="__main__":main()
