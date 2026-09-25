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
CREATE TABLE IF NOT EXISTS sensors(sensor_id TEXT PRIMARY KEY,segment_id TEXT NOT NULL REFERENCES segments(segment_id),model TEXT NOT NULL,registered_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS certificates(certificate_id TEXT PRIMARY KEY,sensor_id TEXT NOT NULL REFERENCES sensors(sensor_id),version INTEGER NOT NULL,valid_from TEXT NOT NULL,valid_to TEXT,range_min REAL NOT NULL,range_max REAL NOT NULL,issuer TEXT NOT NULL,record_hash TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(sensor_id,version));
CREATE TABLE IF NOT EXISTS certificate_revocations(certificate_id TEXT PRIMARY KEY REFERENCES certificates(certificate_id),reason TEXT NOT NULL,actor TEXT NOT NULL,revoked_at TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS readings(reading_id TEXT PRIMARY KEY,segment_id TEXT NOT NULL REFERENCES segments(segment_id),sensor_id TEXT NOT NULL,pressure_kpa REAL NOT NULL,flow_lps REAL NOT NULL,acoustic_db REAL NOT NULL,observed_at TEXT NOT NULL,certificate_id TEXT NOT NULL REFERENCES certificates(certificate_id),certificate_version INTEGER NOT NULL,UNIQUE(segment_id,sensor_id,observed_at));
CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY,segment_id TEXT NOT NULL REFERENCES segments(segment_id),fingerprint TEXT NOT NULL UNIQUE,severity TEXT NOT NULL,score REAL NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,resolved_at TEXT);
CREATE TABLE IF NOT EXISTS work_orders(work_order_id TEXT PRIMARY KEY,segment_id TEXT NOT NULL,alert_id TEXT NOT NULL,assignee TEXT NOT NULL,status TEXT NOT NULL,priority INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS resources(resource_id TEXT PRIMARY KEY,kind TEXT NOT NULL,district TEXT NOT NULL,capacity INTEGER NOT NULL,available INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS allocations(allocation_id TEXT PRIMARY KEY,resource_id TEXT NOT NULL,work_order_id TEXT NOT NULL,quantity INTEGER NOT NULL,created_at TEXT NOT NULL,UNIQUE(resource_id,work_order_id));
CREATE TABLE IF NOT EXISTS audit_events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,entity_type TEXT NOT NULL,entity_id TEXT NOT NULL,action TEXT NOT NULL,actor TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL);
-- 证书与撤销记录只追加、永不修改；历史读数引用的证书版本冻结在采样时刻。
CREATE TRIGGER IF NOT EXISTS certificates_no_update BEFORE UPDATE ON certificates
BEGIN SELECT RAISE(ABORT,'certificate records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS certificates_no_delete BEFORE DELETE ON certificates
BEGIN SELECT RAISE(ABORT,'certificate records are immutable'); END;
CREATE TRIGGER IF NOT EXISTS revocations_no_update BEFORE UPDATE ON certificate_revocations
BEGIN SELECT RAISE(ABORT,'revocation records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS revocations_no_delete BEFORE DELETE ON certificate_revocations
BEGIN SELECT RAISE(ABORT,'revocation records are immutable'); END;
CREATE TRIGGER IF NOT EXISTS readings_no_update BEFORE UPDATE ON readings
BEGIN SELECT RAISE(ABORT,'ingested readings and their certificate references are frozen'); END;
"""
def utcnow() -> str: return datetime.now(timezone.utc).isoformat()
def connect(path: str = ":memory:") -> sqlite3.Connection:
    db=sqlite3.connect(path,timeout=10,check_same_thread=False); db.row_factory=sqlite3.Row; db.execute("PRAGMA foreign_keys=ON"); db.execute("PRAGMA journal_mode=WAL"); db.executescript(SCHEMA); db.commit(); return db
@contextmanager
def transaction(db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try: db.execute("BEGIN IMMEDIATE"); yield db; db.commit()
    except Exception: db.rollback(); raise
def audit(db, entity_type, entity_id, action, actor, payload):
    db.execute("INSERT INTO audit_events(entity_type,entity_id,action,actor,payload,created_at) VALUES(?,?,?,?,?,?)",(entity_type,entity_id,action,actor,json.dumps(payload,ensure_ascii=False,sort_keys=True),utcnow()))
def rows(db, query, args=()): return [dict(r) for r in db.execute(query,args).fetchall()]
