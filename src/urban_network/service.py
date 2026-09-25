"""协调管网监测、校准证书、告警、工单和应急资源分配的应用服务。"""
from __future__ import annotations
import hashlib,sqlite3,uuid
from .auth import Auth
from .models import Certificate,Reading,Sensor,Segment,as_dict,canonical_time,parse_time,utcnow
from .risk import leak_probability,score_reading
from .storage import audit,connect,rows,transaction

def _fingerprint(segment_id,sensor_id,observed_at): return hashlib.sha256(f"{segment_id}|{sensor_id}|{observed_at}".encode()).hexdigest()
def _certificate_hash(cert):
    valid_to="" if cert.valid_to is None else canonical_time(cert.valid_to)
    material="|".join((cert.sensor_id,str(cert.version),canonical_time(cert.valid_from),valid_to,repr(cert.range_min),repr(cert.range_max),cert.issuer))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()

class CalibrationError(ValueError):
    """读数在采样时刻没有可用的有效校准证书，或压力超出证书量程。"""

class NetworkService:
    def __init__(self,database=":memory:"): self.db=connect(database); self.auth=Auth(self.db)
    def bootstrap(self):
        for uid,pwd,role in (("admin","network-admin","admin"),("operator","network-operator","operator")):
            try:self.auth.create_user(uid,pwd,role)
            except Exception:pass

    # ---- 设备台账 ----
    def register_sensor(self,token,sensor):
        actor=self.auth.require(token,"admin"); sensor.validate(); now=utcnow()
        with transaction(self.db):
            if not self.db.execute("SELECT 1 FROM segments WHERE segment_id=?",(sensor.segment_id,)).fetchone(): raise KeyError(sensor.segment_id)
            old=self.db.execute("SELECT segment_id,model FROM sensors WHERE sensor_id=?",(sensor.sensor_id,)).fetchone()
            if old:
                if old["segment_id"]==sensor.segment_id and old["model"]==sensor.model: return {"sensor_id":sensor.sensor_id,"duplicate":True}
                raise ValueError("sensor already registered with different segment or model")
            self.db.execute("INSERT INTO sensors VALUES(?,?,?,?)",(sensor.sensor_id,sensor.segment_id,sensor.model,now)); audit(self.db,"sensor",sensor.sensor_id,"registered",actor.user_id,as_dict(sensor))
        return self.sensor(token,sensor.sensor_id)
    def sensor(self,token,sensor_id):
        self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM sensors WHERE sensor_id=?",(sensor_id,)).fetchone()
        if not row:raise KeyError(sensor_id)
        return dict(row)

    # ---- 校准证书（只追加、带版本与内容指纹）----
    def issue_certificate(self,token,cert):
        actor=self.auth.require(token,"admin"); cert.validate()
        valid_from=canonical_time(cert.valid_from); valid_to=None if cert.valid_to is None else canonical_time(cert.valid_to)
        normalized=Certificate(cert.certificate_id,cert.sensor_id,cert.version,valid_from,valid_to,cert.range_min,cert.range_max,cert.issuer); record_hash=_certificate_hash(normalized)
        with transaction(self.db):
            if not self.db.execute("SELECT 1 FROM sensors WHERE sensor_id=?",(cert.sensor_id,)).fetchone(): raise KeyError(cert.sensor_id)
            same_id=self.db.execute("SELECT sensor_id,version,record_hash FROM certificates WHERE certificate_id=?",(cert.certificate_id,)).fetchone()
            if same_id:
                if same_id["sensor_id"]==cert.sensor_id and same_id["version"]==cert.version and same_id["record_hash"]==record_hash: return {"certificate_id":cert.certificate_id,"duplicate":True,"version":cert.version}
                raise ValueError("certificate_id already registered with different content")
            clash=self.db.execute("SELECT certificate_id FROM certificates WHERE sensor_id=? AND version=?",(cert.sensor_id,cert.version)).fetchone()
            if clash: raise ValueError("certificate version already used for this sensor under a different id")
            latest=self.db.execute("SELECT MAX(version) AS v FROM certificates WHERE sensor_id=?",(cert.sensor_id,)).fetchone()["v"]
            if latest is not None and cert.version<=latest: raise ValueError("certificate version must be strictly greater than previous versions")
            self.db.execute("INSERT INTO certificates VALUES(?,?,?,?,?,?,?,?,?,?)",(cert.certificate_id,cert.sensor_id,cert.version,valid_from,valid_to,cert.range_min,cert.range_max,cert.issuer,record_hash,utcnow()))
            audit(self.db,"certificate",cert.certificate_id,"issued",actor.user_id,{**as_dict(normalized),"record_hash":record_hash})
        return self.certificate(token,cert.certificate_id)
    def certificate(self,token,certificate_id):
        self.auth.require(token,"read"); row=self._certificate_row(certificate_id)
        if not row:raise KeyError(certificate_id)
        out=dict(row); out["revoked"]=self.db.execute("SELECT 1 FROM certificate_revocations WHERE certificate_id=?",(certificate_id,)).fetchone() is not None; return out
    def _certificate_row(self,certificate_id):
        return self.db.execute("SELECT * FROM certificates WHERE certificate_id=?",(certificate_id,)).fetchone()
    def revoke_certificate(self,token,certificate_id,reason):
        actor=self.auth.require(token,"admin")
        if not reason or not reason.strip(): raise ValueError("revocation reason is required")
        reason=reason.strip(); now=utcnow()
        with transaction(self.db):
            if not self._certificate_row(certificate_id): raise KeyError(certificate_id)
            old=self.db.execute("SELECT reason FROM certificate_revocations WHERE certificate_id=?",(certificate_id,)).fetchone()
            if old:
                if old["reason"]==reason: return {"certificate_id":certificate_id,"duplicate":True,"revoked":True}
                raise ValueError("certificate has already been revoked with a different reason; records are append-only")
            self.db.execute("INSERT INTO certificate_revocations VALUES(?,?,?,?,?)",(certificate_id,reason,actor.user_id,now,now)); audit(self.db,"certificate",certificate_id,"revoked",actor.user_id,{"reason":reason,"revoked_at":now})
        return {"certificate_id":certificate_id,"duplicate":False,"revoked":True,"reason":reason,"revoked_at":now}

    def _resolve_certificate(self,sensor_id,observed_at):
        """返回采样时刻有效的最高版本证书。

        边界规则确定：valid_from/valid_to 为闭区间（端点时刻仍有效）；
        撤销自 revoked_at 整时刻起失效（t < revoked_at 才有效）。
        """
        t=canonical_time(observed_at)
        return self.db.execute(
            "SELECT c.* FROM certificates c LEFT JOIN certificate_revocations r ON r.certificate_id=c.certificate_id "
            "WHERE c.sensor_id=? AND c.valid_from<=? AND (c.valid_to IS NULL OR ?<=c.valid_to) "
            "AND (r.certificate_id IS NULL OR ?<r.revoked_at) ORDER BY c.version DESC LIMIT 1",
            (sensor_id,t,t,t)).fetchone()

    # ---- 管段与读数 ----
    def register_segment(self,token,segment):
        actor=self.auth.require(token,"admin"); segment.validate(); now=utcnow()
        with transaction(self.db):
            old=self.db.execute("SELECT district,network_type,length_m,criticality FROM segments WHERE segment_id=?",(segment.segment_id,)).fetchone()
            if old:
                if (old["district"],old["network_type"],old["length_m"],old["criticality"])==(segment.district,segment.network_type,segment.length_m,segment.criticality): return self.segment(token,segment.segment_id)
                raise ValueError("segment already registered with different attributes")
            self.db.execute("INSERT INTO segments VALUES(?,?,?,?,?,?,?,?)",(segment.segment_id,segment.district,segment.network_type,segment.length_m,segment.criticality,segment.status,now,now)); audit(self.db,"segment",segment.segment_id,"created",actor.user_id,as_dict(segment))
        return self.segment(token,segment.segment_id)
    def segment(self,token,segment_id):
        self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM segments WHERE segment_id=?",(segment_id,)).fetchone()
        if not row:raise KeyError(segment_id)
        return dict(row)
    def ingest_reading(self,token,reading):
        actor=self.auth.require(token,"measure"); reading.validate()
        seg=self.db.execute("SELECT criticality FROM segments WHERE segment_id=?",(reading.segment_id,)).fetchone()
        if not seg:raise KeyError(reading.segment_id)
        sensor=self.db.execute("SELECT segment_id FROM sensors WHERE sensor_id=?",(reading.sensor_id,)).fetchone()
        if not sensor:raise CalibrationError(f"sensor {reading.sensor_id} is not registered in the equipment ledger")
        if sensor["segment_id"]!=reading.segment_id:raise CalibrationError(f"sensor {reading.sensor_id} is not mounted on segment {reading.segment_id}")
        risk=score_reading(reading.pressure_kpa,reading.flow_lps,reading.acoustic_db,seg[0]); fingerprint=_fingerprint(reading.segment_id,reading.sensor_id,reading.observed_at)
        with transaction(self.db):
            if self.db.execute("SELECT reading_id FROM readings WHERE reading_id=?",(reading.reading_id,)).fetchone(): return {"reading_id":reading.reading_id,"duplicate":True,"risk":as_dict(risk)}
            cert=self._resolve_certificate(reading.sensor_id,reading.observed_at)
            if not cert:raise CalibrationError(f"sensor {reading.sensor_id} held no valid calibration certificate at {canonical_time(reading.observed_at)}")
            if not cert["range_min"]<=reading.pressure_kpa<=cert["range_max"]:raise CalibrationError(f"pressure {reading.pressure_kpa} kPa is outside certificate {cert['certificate_id']} range [{cert['range_min']},{cert['range_max']}]")
            self.db.execute("INSERT INTO readings VALUES(?,?,?,?,?,?,?,?,?)",(reading.reading_id,reading.segment_id,reading.sensor_id,reading.pressure_kpa,reading.flow_lps,reading.acoustic_db,reading.observed_at,cert["certificate_id"],cert["version"])); alert_id=None
            if risk.severity in {"high","critical"}:
                alert_id="alert-"+fingerprint[:18]; self.db.execute("INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?,?,?,?)",(alert_id,reading.segment_id,fingerprint,risk.severity,risk.score,"open",utcnow(),None))
            audit(self.db,"reading",reading.reading_id,"ingested",actor.user_id,{"risk":as_dict(risk),"alert_id":alert_id,"certificate_id":cert["certificate_id"],"certificate_version":cert["version"]})
        return {"reading_id":reading.reading_id,"duplicate":False,"risk":as_dict(risk),"alert_id":alert_id,"certificate_id":cert["certificate_id"],"certificate_version":cert["version"]}
    def _calibration_state(self,cert_row,now):
        if cert_row["revoked_at"]: return "revoked"
        if cert_row["valid_to"] is not None and cert_row["valid_to"]<now: return "expired"
        return "valid"
    def risk_report(self,token,segment_id):
        self.auth.require(token,"analyze"); now=canonical_time(utcnow())
        readings=rows(self.db,
            "SELECT rd.*,c.valid_from,c.valid_to,rv.revoked_at FROM readings rd "
            "JOIN certificates c ON c.certificate_id=rd.certificate_id "
            "LEFT JOIN certificate_revocations rv ON rv.certificate_id=rd.certificate_id "
            "WHERE rd.segment_id=? ORDER BY rd.observed_at",(segment_id,))
        alerts=rows(self.db,"SELECT * FROM alerts WHERE segment_id=? ORDER BY created_at",(segment_id,))
        status_by_fingerprint={_fingerprint(r["segment_id"],r["sensor_id"],r["observed_at"]):self._calibration_state(r,now) for r in readings}
        for alert in alerts:
            alert["calibration_status"]=status_by_fingerprint.get(alert["fingerprint"],"unknown")
        affected=sum(1 for r in readings if self._calibration_state(r,now)!="valid")
        return {"segment_id":segment_id,"readings":len(readings),"readings_with_unverified_calibration":affected,"alerts":alerts,"leak_probability":leak_probability(alerts)}

    # ---- 质量追溯：受影响管段与读数 ----
    def affected_segments(self,token,at=None):
        self.auth.require(token,"analyze"); now=canonical_time(at or utcnow())
        return rows(self.db,
            "SELECT rd.segment_id,rd.sensor_id,rd.certificate_id,rd.certificate_version,"
            "CASE WHEN rv.certificate_id IS NOT NULL THEN 'revoked' WHEN c.valid_to IS NOT NULL AND c.valid_to<? THEN 'expired' END AS reason,"
            "COUNT(*) AS reading_count,MIN(rd.observed_at) AS first_reading_at,MAX(rd.observed_at) AS last_reading_at "
            "FROM readings rd JOIN certificates c ON c.certificate_id=rd.certificate_id "
            "LEFT JOIN certificate_revocations rv ON rv.certificate_id=rd.certificate_id "
            "WHERE rv.certificate_id IS NOT NULL OR (c.valid_to IS NOT NULL AND c.valid_to<?) "
            "GROUP BY rd.segment_id,rd.sensor_id,rd.certificate_id ORDER BY rd.segment_id,rd.sensor_id,rd.certificate_version",(now,now))
    def affected_readings(self,token,segment_id=None):
        self.auth.require(token,"analyze"); now=canonical_time(utcnow())
        sql=("SELECT rd.reading_id,rd.segment_id,rd.sensor_id,rd.pressure_kpa,rd.observed_at,rd.certificate_id,rd.certificate_version,"
             "CASE WHEN rv.certificate_id IS NOT NULL THEN 'revoked' WHEN c.valid_to IS NOT NULL AND c.valid_to<? THEN 'expired' END AS reason,"
             "rv.revoked_at,c.valid_to FROM readings rd JOIN certificates c ON c.certificate_id=rd.certificate_id "
             "LEFT JOIN certificate_revocations rv ON rv.certificate_id=rd.certificate_id "
             "WHERE rv.certificate_id IS NOT NULL OR (c.valid_to IS NOT NULL AND c.valid_to<?)")
        args=[now,now]
        if segment_id: sql+=" AND rd.segment_id=?"; args.append(segment_id)
        return rows(self.db,sql+" ORDER BY rd.observed_at",tuple(args))

    # ---- 工单与应急资源（沿用基线流程）----
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
