"""依赖标准库的 JSON HTTP API。"""
from __future__ import annotations
import argparse,json,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlparse,parse_qs
from .models import Certificate,Reading,Sensor,Segment
from .service import NetworkService
class Handler(BaseHTTPRequestHandler):
    service=NetworkService()
    lock=threading.Lock()  # 单个 SQLite 连接上的请求串行执行，保证事务边界
    def _send(self,status,payload):
        data=json.dumps(payload,ensure_ascii=False).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def _token(self):return self.headers.get("Authorization","").removeprefix("Bearer ")
    def do_GET(self):
        with Handler.lock: self._get()
    def do_POST(self):
        with Handler.lock: self._post()
    def _get(self):
        try:
            parsed=urlparse(self.path); path=parsed.path; query=parse_qs(parsed.query)
            if path=="/health":return self._send(200,{"status":"ok","service":"urban-network"})
            if path=="/quality/affected-segments":return self._send(200,{"segments":self.service.affected_segments(self._token())})
            if path=="/quality/affected-readings":
                segment_id=query.get("segment_id",[None])[0]; return self._send(200,{"readings":self.service.affected_readings(self._token(),segment_id)})
            if path.startswith("/segments/") and path.endswith("/risk"):return self._send(200,self.service.risk_report(self._token(),path.split("/")[2]))
            if path.startswith("/segments/"):return self._send(200,self.service.segment(self._token(),path.split("/",2)[2]))
            if path.startswith("/sensors/"):return self._send(200,self.service.sensor(self._token(),path.split("/")[2]))
            if path.startswith("/certificates/"):return self._send(200,self.service.certificate(self._token(),path.split("/")[2]))
            return self._send(404,{"error":"not found"})
        except PermissionError as e:return self._send(403,{"error":str(e)})
        except Exception as e:return self._send(400,{"error":str(e)})
    def _post(self):
        try:
            body=json.loads(self.rfile.read(int(self.headers.get("Content-Length","0"))) or b"{}")
            if self.path=="/login":return self._send(200,{"token":self.service.auth.login(body["user_id"],body["password"])})
            token=self._token()
            if self.path=="/segments":return self._send(201,self.service.register_segment(token,Segment(body["segment_id"],body["district"],body["network_type"],body["length_m"],body["criticality"])))
            if self.path.startswith("/segments/") and self.path.endswith("/sensors"):
                sid=self.path.split("/")[2]; return self._send(201,self.service.register_sensor(token,Sensor(body["sensor_id"],sid,body["model"])))
            if self.path.startswith("/sensors/") and self.path.endswith("/certificates"):
                sid=self.path.split("/")[2]; c=Certificate(body["certificate_id"],sid,body["version"],body["valid_from"],body.get("valid_to"),body["range_min"],body["range_max"],body["issuer"]); return self._send(201,self.service.issue_certificate(token,c))
            if self.path.startswith("/certificates/") and self.path.endswith("/revocation"):
                cid=self.path.split("/")[2]; return self._send(200,self.service.revoke_certificate(token,cid,body["reason"]))
            if self.path.startswith("/segments/") and self.path.endswith("/readings"):
                sid=self.path.split("/")[2]; r=Reading(body["reading_id"],sid,body["sensor_id"],body["pressure_kpa"],body["flow_lps"],body["acoustic_db"],body["observed_at"]); return self._send(201,self.service.ingest_reading(token,r))
            if self.path.startswith("/segments/") and self.path.endswith("/work-orders"):
                return self._send(201,self.service.create_work_order(token,self.path.split("/")[2],body["alert_id"],body["assignee"],body.get("priority",3)))
            return self._send(404,{"error":"not found"})
        except PermissionError as e:return self._send(403,{"error":str(e)})
        except Exception as e:return self._send(400,{"error":str(e)})
def main():
    p=argparse.ArgumentParser(); p.add_argument("--database",default=":memory:"); p.add_argument("--host",default="127.0.0.1"); p.add_argument("--port",type=int,default=8080); a=p.parse_args(); Handler.service=NetworkService(a.database); Handler.service.bootstrap(); ThreadingHTTPServer((a.host,a.port),Handler).serve_forever()
if __name__=="__main__":main()
