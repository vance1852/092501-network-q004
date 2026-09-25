"""SQLite 结构、事务和审计事件辅助函数。"""
from __future__ import annotations
import json, sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(user_id TEXT PRIMARY KEY,role TEXT NOT NULL,salt TEXT NOT NULL,password_hash TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires_at TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS segments(segment_id TEXT PRIMARY KEY,district TEXT NOT NULL,network_type TEXT NOT NULL,length_m REAL NOT NULL,criticality INTEGER NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS calibration_certificates(certificate_id TEXT PRIMARY KEY,sensor_id TEXT NOT NULL,version INTEGER NOT NULL,issuer TEXT NOT NULL,valid_from TEXT NOT NULL,valid_to TEXT NOT NULL,range_min_kpa REAL NOT NULL,range_max_kpa REAL NOT NULL,status TEXT NOT NULL DEFAULT 'active',registered_at TEXT NOT NULL,revoked_at TEXT,UNIQUE(sensor_id,version));
CREATE TABLE IF NOT EXISTS readings(reading_id TEXT PRIMARY KEY,segment_id TEXT NOT NULL REFERENCES segments(segment_id),sensor_id TEXT NOT NULL,pressure_kpa REAL NOT NULL,flow_lps REAL NOT NULL,acoustic_db REAL NOT NULL,observed_at TEXT NOT NULL,certificate_id TEXT NOT NULL REFERENCES calibration_certificates(certificate_id),certificate_version INTEGER NOT NULL,UNIQUE(segment_id,sensor_id,observed_at));
CREATE TRIGGER IF NOT EXISTS certificate_immutable_update BEFORE UPDATE ON calibration_certificates
WHEN NEW.version<>OLD.version OR NEW.sensor_id<>OLD.sensor_id OR NEW.issuer<>OLD.issuer OR NEW.valid_from<>OLD.valid_from OR NEW.valid_to<>OLD.valid_to OR NEW.range_min_kpa<>OLD.range_min_kpa OR NEW.range_max_kpa<>OLD.range_max_kpa
BEGIN SELECT RAISE(ABORT,'calibration certificate content is immutable'); END;
CREATE TRIGGER IF NOT EXISTS certificate_immutable_delete BEFORE DELETE ON calibration_certificates
WHEN EXISTS(SELECT 1 FROM readings WHERE readings.certificate_id=OLD.certificate_id)
BEGIN SELECT RAISE(ABORT,'calibration certificate referenced by readings cannot be deleted'); END;
CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY,segment_id TEXT NOT NULL REFERENCES segments(segment_id),fingerprint TEXT NOT NULL UNIQUE,severity TEXT NOT NULL,score REAL NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,resolved_at TEXT);
CREATE TABLE IF NOT EXISTS work_orders(work_order_id TEXT PRIMARY KEY,segment_id TEXT NOT NULL,alert_id TEXT NOT NULL,assignee TEXT NOT NULL,status TEXT NOT NULL,priority INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS resources(resource_id TEXT PRIMARY KEY,kind TEXT NOT NULL,district TEXT NOT NULL,capacity INTEGER NOT NULL,available INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS allocations(allocation_id TEXT PRIMARY KEY,resource_id TEXT NOT NULL,work_order_id TEXT NOT NULL,quantity INTEGER NOT NULL,created_at TEXT NOT NULL,UNIQUE(resource_id,work_order_id));
CREATE TABLE IF NOT EXISTS audit_events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,entity_type TEXT NOT NULL,entity_id TEXT NOT NULL,action TEXT NOT NULL,actor TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL);
"""
def utcnow() -> str: return datetime.now(timezone.utc).isoformat()
def connect(path: str = ":memory:") -> sqlite3.Connection:
    db=sqlite3.connect(path,timeout=10,check_same_thread=False); db.row_factory=sqlite3.Row; db.execute("PRAGMA foreign_keys=ON"); db.execute("PRAGMA journal_mode=WAL"); db.executescript(SCHEMA)
    columns={row[1] for row in db.execute("PRAGMA table_info(readings)")}
    if "certificate_id" not in columns:
        db.execute("ALTER TABLE readings ADD COLUMN certificate_id TEXT REFERENCES calibration_certificates(certificate_id)")
        db.execute("ALTER TABLE readings ADD COLUMN certificate_version INTEGER")
    db.commit(); return db
@contextmanager
def transaction(db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try: db.execute("BEGIN IMMEDIATE"); yield db; db.commit()
    except Exception: db.rollback(); raise
def audit(db, entity_type, entity_id, action, actor, payload):
    db.execute("INSERT INTO audit_events(entity_type,entity_id,action,actor,payload,created_at) VALUES(?,?,?,?,?,?)",(entity_type,entity_id,action,actor,json.dumps(payload,ensure_ascii=False,sort_keys=True),utcnow()))
def rows(db, query, args=()): return [dict(r) for r in db.execute(query,args).fetchall()]
