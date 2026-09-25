"""依赖标准库的 JSON HTTP API。"""
from __future__ import annotations
import argparse,json
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import parse_qs,urlsplit
from .models import Reading,Segment,Certificate
from .service import NetworkService
class Handler(BaseHTTPRequestHandler):
    service=NetworkService()
    def _send(self,status,payload):
        data=json.dumps(payload,ensure_ascii=False).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def _token(self):return self.headers.get("Authorization","").removeprefix("Bearer ")
    def _query(self):return {k:v[0] for k,v in parse_qs(urlsplit(self.path).query).items()}
    def _path(self):return urlsplit(self.path).path
    def do_GET(self):
        try:
            path=self._path(); token=self._token()
            if path=="/health":return self._send(200,{"status":"ok","service":"urban-network"})
            if path.startswith("/segments/") and path.endswith("/risk"):return self._send(200,self.service.risk_report(token,path.split("/")[2]))
            if path.startswith("/segments/"):return self._send(200,self.service.segment(token,path.split("/",2)[2]))
            if path.startswith("/certificates/") and path.endswith("/readings"):return self._send(200,self.service.certificate_readings(token,path.split("/")[2]))
            if path.startswith("/certificates/"):return self._send(200,self.service.certificate(token,path.split("/")[2]))
            if path.startswith("/sensors/") and path.endswith("/certificates"):return self._send(200,{"certificates":self.service.sensor_certificates(token,path.split("/")[2])})
            if path=="/quality/affected":
                q=self._query(); return self._send(200,self.service.affected_readings(token,q.get("segment_id"),q.get("sensor_id")))
            return self._send(404,{"error":"not found"})
        except PermissionError as e:return self._send(403,{"error":str(e)})
        except KeyError as e:return self._send(404,{"error":str(e).strip("'")})
        except Exception as e:return self._send(400,{"error":str(e)})
    def do_POST(self):
        try:
            body=json.loads(self.rfile.read(int(self.headers.get("Content-Length","0"))) or b"{}")
            path=self._path()
            if path=="/login":return self._send(200,{"token":self.service.auth.login(body["user_id"],body["password"])})
            token=self._token()
            if path=="/segments":return self._send(201,self.service.register_segment(token,Segment(body["segment_id"],body["district"],body["network_type"],body["length_m"],body["criticality"])))
            if path=="/certificates":
                cert=Certificate(body["certificate_id"],body["sensor_id"],body["issuer"],body["valid_from"],body["valid_to"],body["range_min_kpa"],body["range_max_kpa"]); return self._send(201,self.service.register_certificate(token,cert))
            if path.startswith("/certificates/") and path.endswith("/revoke"):return self._send(200,self.service.revoke_certificate(token,path.split("/")[2],body["reason"]))
            if path.startswith("/segments/") and path.endswith("/readings"):
                sid=path.split("/")[2]; r=Reading(body["reading_id"],sid,body["sensor_id"],body["pressure_kpa"],body["flow_lps"],body["acoustic_db"],body["observed_at"],body["certificate_id"]); return self._send(201,self.service.ingest_reading(token,r))
            if path.startswith("/segments/") and path.endswith("/work-orders"):
                return self._send(201,self.service.create_work_order(token,path.split("/")[2],body["alert_id"],body["assignee"],body.get("priority",3)))
            return self._send(404,{"error":"not found"})
        except PermissionError as e:return self._send(403,{"error":str(e)})
        except KeyError as e:return self._send(404,{"error":str(e).strip("'")})
        except Exception as e:return self._send(400,{"error":str(e)})
def main():
    p=argparse.ArgumentParser(); p.add_argument("--database",default=":memory:"); p.add_argument("--host",default="127.0.0.1"); p.add_argument("--port",type=int,default=8080); a=p.parse_args(); Handler.service=NetworkService(a.database); Handler.service.bootstrap(); ThreadingHTTPServer((a.host,a.port),Handler).serve_forever()
if __name__=="__main__":main()
