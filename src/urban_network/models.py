"""管段、读数、告警、工单、资源和校准证书的领域模型。"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)

@dataclass(frozen=True)
class Segment:
    segment_id: str; district: str; network_type: str; length_m: float; criticality: int; status: str = "normal"
    def validate(self) -> None:
        if not self.segment_id.strip() or not self.district.strip(): raise ValueError("segment id and district are required")
        if self.network_type not in {"water", "drainage", "gas"}: raise ValueError("unsupported network type")
        if self.length_m <= 0 or not 1 <= self.criticality <= 5: raise ValueError("segment dimensions are invalid")

@dataclass(frozen=True)
class Reading:
    reading_id: str; segment_id: str; sensor_id: str; pressure_kpa: float; flow_lps: float; acoustic_db: float; observed_at: str; certificate_id: str
    def validate(self) -> None:
        if not self.reading_id.strip() or not self.segment_id.strip() or not self.sensor_id.strip(): raise ValueError("reading identifiers are required")
        if not self.certificate_id.strip(): raise ValueError("calibration certificate is required")
        if min(self.pressure_kpa, self.flow_lps, self.acoustic_db) < 0: raise ValueError("reading values cannot be negative")
        parse_time(self.observed_at)

@dataclass(frozen=True)
class Certificate:
    """传感器校准证书；内容一经登记不可变，补发须登记新证书。"""
    certificate_id: str; sensor_id: str; issuer: str; valid_from: str; valid_to: str; range_min_kpa: float; range_max_kpa: float
    def validate(self) -> None:
        if not self.certificate_id.strip() or not self.sensor_id.strip() or not self.issuer.strip(): raise ValueError("certificate identifiers and issuer are required")
        start, end = parse_time(self.valid_from), parse_time(self.valid_to)
        if start >= end: raise ValueError("certificate validity window must be a non-empty half-open interval [valid_from, valid_to)")
        if self.range_min_kpa > self.range_max_kpa: raise ValueError("certificate pressure range is invalid")

def certificate_state(valid_from: str, valid_to: str, revoked_at: str | None, at: str) -> str:
    """证书在时刻 at 的状态。有效区间为半开 [valid_from, valid_to)：起点有效、终点失效。

    撤销自 revoked_at 时刻起生效且优先于其他状态，因此边界时刻总有唯一结果。
    """
    moment = parse_time(at)
    if revoked_at and moment >= parse_time(revoked_at): return "revoked"
    if moment < parse_time(valid_from): return "not_yet_valid"
    if moment >= parse_time(valid_to): return "expired"
    return "valid"

def as_dict(value: Any) -> dict[str, Any]:
    return {name: getattr(value, name) for name in value.__dataclass_fields__} if hasattr(value, "__dataclass_fields__") else dict(value)
