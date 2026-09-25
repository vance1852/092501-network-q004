"""离线命令行验收入口。"""
from __future__ import annotations
import argparse,json
from .models import Reading,Segment,Certificate
from .service import NetworkService
def run():
    s=NetworkService(); s.bootstrap(); t=s.auth.login("admin","network-admin"); s.register_segment(t,Segment("SEG-DEMO","north","water",680,5))
    s.register_certificate(t,Certificate("CERT-DEMO","sensor-01","市级计量院","2025-01-01T00:00:00+00:00","2027-01-01T00:00:00+00:00",0,1000))
    r=s.ingest_reading(t,Reading("RD-DEMO","SEG-DEMO","sensor-01",160,230,88,"2026-09-24T10:00:00+00:00","CERT-DEMO"))
    report=s.risk_report(t,"SEG-DEMO"); order=s.create_work_order(t,"SEG-DEMO",r["alert_id"],"crew-north",1); s.add_resource(t,"PUMP-01","mobile-pump","north",2); allocation=s.allocate(t,"PUMP-01",order["work_order_id"],1)
    s.revoke_certificate(t,"CERT-DEMO","证书签发机构资质注销,演示撤销追溯")
    affected=s.affected_readings(t,segment_id="SEG-DEMO")
    return {"status":"ok","segment":"SEG-DEMO","severity":r["risk"]["severity"],"probability":report["leak_probability"],"allocation":allocation["allocation_id"],"certificate_version":r["certificate_version"],"affected_readings":affected["segments"][0]["affected_readings"] if affected["segments"] else 0}
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--workspace",default="."); parser.parse_args(); print(json.dumps(run(),ensure_ascii=False))
if __name__=="__main__":main()
