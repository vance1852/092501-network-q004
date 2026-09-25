"""协调管网监测、告警、工单和应急资源分配的应用服务。"""
from __future__ import annotations
import hashlib,uuid
from .auth import Auth
from .models import Reading,Segment,Certificate,certificate_state,parse_time,as_dict,utcnow
from .risk import leak_probability,score_reading
from .storage import audit,connect,rows,transaction
_CERT_FIELDS=("sensor_id","issuer","valid_from","valid_to","range_min_kpa","range_max_kpa")
def _fingerprint(segment_id,sensor_id,observed_at): return hashlib.sha256(f"{segment_id}|{sensor_id}|{observed_at}".encode()).hexdigest()
class NetworkService:
    def __init__(self,database=":memory:"): self.db=connect(database); self.auth=Auth(self.db)
    def bootstrap(self):
        for uid,pwd,role in (("admin","network-admin","admin"),("operator","network-operator","operator"),("quality","network-quality","quality")):
            try:self.auth.create_user(uid,pwd,role)
            except Exception:pass
    def register_segment(self,token,segment):
        actor=self.auth.require(token,"admin"); segment.validate(); now=utcnow()
        with transaction(self.db):
            self.db.execute("INSERT INTO segments VALUES(?,?,?,?,?,?,?,?)",(segment.segment_id,segment.district,segment.network_type,segment.length_m,segment.criticality,segment.status,now,now)); audit(self.db,"segment",segment.segment_id,"created",actor.user_id,as_dict(segment))
        return self.segment(token,segment.segment_id)
    def segment(self,token,segment_id):
        self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM segments WHERE segment_id=?",(segment_id,)).fetchone()
        if not row:raise KeyError(segment_id)
        return dict(row)
    def register_certificate(self,token,certificate):
        """登记校准证书。内容不可变，版本按传感器单调递增；重复登记返回既有记录。"""
        actor=self.auth.require(token,"admin"); certificate.validate()
        with transaction(self.db):
            row=self.db.execute("SELECT * FROM calibration_certificates WHERE certificate_id=?",(certificate.certificate_id,)).fetchone()
            if row:
                if tuple(row[k] for k in _CERT_FIELDS)!=tuple(getattr(certificate,k) for k in _CERT_FIELDS): raise ValueError("certificate id already registered with different content")
                result=dict(row); result["duplicate"]=True; return result
            latest=self.db.execute("SELECT COALESCE(MAX(version),0) FROM calibration_certificates WHERE sensor_id=?",(certificate.sensor_id,)).fetchone()[0]
            version=latest+1; now=utcnow()
            self.db.execute("INSERT INTO calibration_certificates VALUES(?,?,?,?,?,?,?,?,?,?,?)",(certificate.certificate_id,certificate.sensor_id,version,certificate.issuer,certificate.valid_from,certificate.valid_to,certificate.range_min_kpa,certificate.range_max_kpa,"active",now,None))
            audit(self.db,"certificate",certificate.certificate_id,"registered",actor.user_id,{"version":version,**as_dict(certificate)})
        return self.certificate(token,certificate.certificate_id)
    def certificate(self,token,certificate_id):
        self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM calibration_certificates WHERE certificate_id=?",(certificate_id,)).fetchone()
        if not row:raise KeyError(certificate_id)
        return dict(row)
    def sensor_certificates(self,token,sensor_id):
        self.auth.require(token,"read"); return rows(self.db,"SELECT * FROM calibration_certificates WHERE sensor_id=? ORDER BY version",(sensor_id,))
    def revoke_certificate(self,token,certificate_id,reason):
        """管理员撤销证书；撤销时刻起生效，重复撤销返回既有结果且不再写审计。"""
        actor=self.auth.require(token,"admin")
        if not reason.strip():raise ValueError("revocation reason is required")
        with transaction(self.db):
            row=self.db.execute("SELECT status FROM calibration_certificates WHERE certificate_id=?",(certificate_id,)).fetchone()
            if not row:raise KeyError(certificate_id)
            if row[0]=="revoked":
                result=self.db.execute("SELECT * FROM calibration_certificates WHERE certificate_id=?",(certificate_id,)).fetchone(); result=dict(result); result["duplicate"]=True; return result
            now=utcnow()
            self.db.execute("UPDATE calibration_certificates SET status='revoked',revoked_at=? WHERE certificate_id=?",(now,certificate_id)); audit(self.db,"certificate",certificate_id,"revoked",actor.user_id,{"reason":reason,"revoked_at":now})
        return self.certificate(token,certificate_id)
    def _certified(self,reading):
        cert=self.db.execute("SELECT * FROM calibration_certificates WHERE certificate_id=?",(reading.certificate_id,)).fetchone()
        if not cert:raise KeyError(reading.certificate_id)
        if cert["sensor_id"]!=reading.sensor_id:raise ValueError("certificate does not belong to the reading sensor")
        state=certificate_state(cert["valid_from"],cert["valid_to"],cert["revoked_at"],reading.observed_at)
        if state!="valid":raise ValueError(f"certificate {state} at sampling time; reading rejected")
        if not cert["range_min_kpa"]<=reading.pressure_kpa<=cert["range_max_kpa"]:raise ValueError("pressure reading outside certified range")
        return cert
    def ingest_reading(self,token,reading):
        actor=self.auth.require(token,"measure"); reading.validate(); seg=self.db.execute("SELECT criticality FROM segments WHERE segment_id=?",(reading.segment_id,)).fetchone()
        if not seg:raise KeyError(reading.segment_id)
        risk=score_reading(reading.pressure_kpa,reading.flow_lps,reading.acoustic_db,seg[0]); fingerprint=_fingerprint(reading.segment_id,reading.sensor_id,reading.observed_at)
        with transaction(self.db):
            existing=self.db.execute("SELECT reading_id FROM readings WHERE reading_id=?",(reading.reading_id,)).fetchone()
            if existing:return {"reading_id":reading.reading_id,"duplicate":True,"risk":as_dict(risk)}
            cert=self._certified(reading)
            clash=self.db.execute("SELECT reading_id FROM readings WHERE segment_id=? AND sensor_id=? AND observed_at=?",(reading.segment_id,reading.sensor_id,reading.observed_at)).fetchone()
            if clash:raise ValueError("same segment, sensor and sampling time already recorded under another reading id")
            self.db.execute("INSERT INTO readings VALUES(?,?,?,?,?,?,?,?,?)",(reading.reading_id,reading.segment_id,reading.sensor_id,reading.pressure_kpa,reading.flow_lps,reading.acoustic_db,reading.observed_at,reading.certificate_id,cert["version"])); alert_id=None
            if risk.severity in {"high","critical"}:
                alert_id="alert-"+fingerprint[:18]; self.db.execute("INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?,?,?,?)",(alert_id,reading.segment_id,fingerprint,risk.severity,risk.score,"open",utcnow(),None))
            audit(self.db,"reading",reading.reading_id,"ingested",actor.user_id,{"risk":as_dict(risk),"alert_id":alert_id,"certificate_id":reading.certificate_id,"certificate_version":cert["version"]})
        return {"reading_id":reading.reading_id,"duplicate":False,"risk":as_dict(risk),"alert_id":alert_id,"certificate_id":reading.certificate_id,"certificate_version":cert["version"]}
    def _calibrated_readings(self,reading_rows,at=None):
        """为读数附加采样当时与当前的证书状态，并关联告警指纹。"""
        moment=at or utcnow(); certs={r["certificate_id"]:dict(r) for r in self.db.execute("SELECT * FROM calibration_certificates").fetchall()}
        fingerprints={r[0] for r in self.db.execute("SELECT fingerprint FROM alerts").fetchall()}
        enriched=[]
        for r in reading_rows:
            item=dict(r); cert=certs.get(r["certificate_id"]); item["certificate_issuer"]=cert["issuer"] if cert else None
            if cert:
                then_state=certificate_state(cert["valid_from"],cert["valid_to"],cert["revoked_at"],r["observed_at"])
                now_state=certificate_state(cert["valid_from"],cert["valid_to"],cert["revoked_at"],moment)
            else:then_state=now_state="unknown"
            item["calibration_state_at_sampling"]=then_state; item["calibration_state_current"]=now_state
            item["raised_alert"]=_fingerprint(r["segment_id"],r["sensor_id"],r["observed_at"]) in fingerprints
            enriched.append(item)
        return enriched
    def risk_report(self,token,segment_id):
        self.auth.require(token,"analyze"); reading_rows=rows(self.db,"SELECT * FROM readings WHERE segment_id=? ORDER BY observed_at",(segment_id,)); alerts=rows(self.db,"SELECT * FROM alerts WHERE segment_id=? ORDER BY created_at",(segment_id,))
        readings=self._calibrated_readings(reading_rows)
        flagged=[r for r in readings if r["calibration_state_current"]!="valid"]; by_fingerprint={_fingerprint(r["segment_id"],r["sensor_id"],r["observed_at"]):r for r in readings}
        for alert in alerts:
            r=by_fingerprint.get(alert["fingerprint"])
            if r:alert.update({"sensor_id":r["sensor_id"],"certificate_id":r["certificate_id"],"certificate_version":r["certificate_version"],"calibration_state_at_sampling":r["calibration_state_at_sampling"],"calibration_state_current":r["calibration_state_current"]})
        return {"segment_id":segment_id,"readings":len(readings),"readings_detail":readings,"alerts":alerts,"calibration_flagged_readings":len(flagged),"leak_probability":leak_probability(alerts)}
    def affected_readings(self,token,segment_id=None,sensor_id=None):
        """质量追溯：证书事后被撤销或到期时，找出受影响的读数、管段和告警。"""
        self.auth.require(token,"analyze")
        sql="SELECT * FROM readings WHERE 1=1"; args=[]
        if segment_id:sql+=" AND segment_id=?"; args.append(segment_id)
        if sensor_id:sql+=" AND sensor_id=?"; args.append(sensor_id)
        sql+=" ORDER BY observed_at"
        readings=[r for r in self._calibrated_readings(rows(self.db,sql,tuple(args))) if r["calibration_state_at_sampling"]=="valid" and r["calibration_state_current"]!="valid"]
        segments={}
        for r in readings:
            summary=segments.setdefault(r["segment_id"],{"segment_id":r["segment_id"],"affected_readings":0,"affected_alerts":0})
            summary["affected_readings"]+=1; summary["affected_alerts"]+=1 if r["raised_alert"] else 0
        return {"segments":sorted(segments.values(),key=lambda x:x["segment_id"]),"readings":readings}
    def certificate_readings(self,token,certificate_id):
        self.auth.require(token,"analyze")
        cert=self.certificate(token,certificate_id)
        reading_rows=rows(self.db,"SELECT * FROM readings WHERE certificate_id=? ORDER BY observed_at",(certificate_id,))
        return {"certificate":cert,"readings":self._calibrated_readings(reading_rows)}
    def create_work_order(self,token,segment_id,alert_id,assignee,priority=3):
        actor=self.auth.require(token,"work_order")
        if not assignee.strip() or not 1<=priority<=5:raise ValueError("assignee and priority are invalid")
        if not self.db.execute("SELECT 1 FROM alerts WHERE alert_id=? AND segment_id=?",(alert_id,segment_id)).fetchone():raise KeyError(alert_id)
        wid="wo-"+uuid.uuid4().hex[:16]
        with transaction(self.db): self.db.execute("INSERT INTO work_orders VALUES(?,?,?,?,?,?,?,?)",(wid,segment_id,alert_id,assignee,"open",priority,utcnow(),utcnow())); audit(self.db,"work_order",wid,"created",actor.user_id,{"segment_id":segment_id,"alert_id":alert_id})
        return self.work_order(token,wid)
    def work_order(self,token,work_order_id):
        self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM work_orders WHERE work_order_id=?",(work_order_id,)).fetchone()
        if not row:raise KeyError(work_order_id)
        return dict(row)
    def transition_work_order(self,token,work_order_id,target,reason):
        actor=self.auth.require(token,"work_order"); allowed={"open":{"assigned","cancelled"},"assigned":{"in_progress","cancelled"},"in_progress":{"completed","blocked"},"blocked":{"in_progress","cancelled"},"completed":set(),"cancelled":set()}
        if not reason.strip():raise ValueError("transition reason is required")
        with transaction(self.db):
            row=self.db.execute("SELECT status FROM work_orders WHERE work_order_id=?",(work_order_id,)).fetchone()
            if not row:raise KeyError(work_order_id)
            if target not in allowed.get(row[0],set()):raise ValueError("invalid work order transition")
            self.db.execute("UPDATE work_orders SET status=?,updated_at=? WHERE work_order_id=?",(target,utcnow(),work_order_id)); audit(self.db,"work_order",work_order_id,"transition",actor.user_id,{"from":row[0],"to":target,"reason":reason})
        return self.work_order(token,work_order_id)
    def add_resource(self,token,resource_id,kind,district,capacity):
        actor=self.auth.require(token,"admin")
        if capacity<=0 or not kind.strip() or not district.strip():raise ValueError("resource fields are invalid")
        with transaction(self.db):self.db.execute("INSERT INTO resources VALUES(?,?,?,?,?)",(resource_id,kind,district,capacity,capacity)); audit(self.db,"resource",resource_id,"created",actor.user_id,{"kind":kind,"district":district,"capacity":capacity})
        return self.resource(token,resource_id)
    def resource(self,token,resource_id):
        self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM resources WHERE resource_id=?",(resource_id,)).fetchone()
        if not row:raise KeyError(resource_id)
        return dict(row)
    def allocate(self,token,resource_id,work_order_id,quantity):
        actor=self.auth.require(token,"allocate")
        if quantity<=0:raise ValueError("quantity must be positive")
        aid="alloc-"+uuid.uuid4().hex[:16]
        with transaction(self.db):
            resource=self.db.execute("SELECT available FROM resources WHERE resource_id=?",(resource_id,)).fetchone()
            if not resource:raise KeyError(resource_id)
            if not self.db.execute("SELECT 1 FROM work_orders WHERE work_order_id=?",(work_order_id,)).fetchone():raise KeyError(work_order_id)
            if resource[0]<quantity:raise ValueError("resource capacity exceeded")
            old=self.db.execute("SELECT allocation_id FROM allocations WHERE resource_id=? AND work_order_id=?",(resource_id,work_order_id)).fetchone()
            if old:return {"allocation_id":old[0],"duplicate":True}
            self.db.execute("INSERT INTO allocations VALUES(?,?,?,?,?)",(aid,resource_id,work_order_id,quantity,utcnow())); self.db.execute("UPDATE resources SET available=available-? WHERE resource_id=?",(quantity,resource_id)); audit(self.db,"resource",resource_id,"allocated",actor.user_id,{"work_order_id":work_order_id,"quantity":quantity})
        return {"allocation_id":aid,"duplicate":False,"resource_id":resource_id,"quantity":quantity}
    def audit_events(self,token,entity_type,entity_id): self.auth.require(token,"read"); return rows(self.db,"SELECT * FROM audit_events WHERE entity_type=? AND entity_id=? ORDER BY event_id",(entity_type,entity_id))
