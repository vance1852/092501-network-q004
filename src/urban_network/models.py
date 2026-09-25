"""管段、传感器、校准证书、读数、告警、工单和资源的领域模型。"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)

def canonical_time(value: str) -> str:
    """把任意 ISO 8601 时间归一化为 UTC，保证区间比较确定。"""
    return parse_time(value).isoformat()

@dataclass(frozen=True)
class Segment:
    segment_id: str; district: str; network_type: str; length_m: float; criticality: int; status: str = "normal"
    def validate(self) -> None:
        if not self.segment_id.strip() or not self.district.strip(): raise ValueError("segment id and district are required")
        if self.network_type not in {"water", "drainage", "gas"}: raise ValueError("unsupported network type")
        if self.length_m <= 0 or not 1 <= self.criticality <= 5: raise ValueError("segment dimensions are invalid")

@dataclass(frozen=True)
class Sensor:
    sensor_id: str; segment_id: str; model: str
    def validate(self) -> None:
        if not self.sensor_id.strip() or not self.segment_id.strip() or not self.model.strip(): raise ValueError("sensor id, segment and model are required")

@dataclass(frozen=True)
class Certificate:
    certificate_id: str; sensor_id: str; version: int; valid_from: str; valid_to: str | None; range_min: float; range_max: float; issuer: str
    def validate(self) -> None:
        if not self.certificate_id.strip() or not self.sensor_id.strip() or not self.issuer.strip(): raise ValueError("certificate id, sensor and issuer are required")
        if not isinstance(self.version,int) or self.version < 1: raise ValueError("certificate version must be a positive integer")
        start=parse_time(self.valid_from)
        if self.valid_to is not None and parse_time(self.valid_to) < start: raise ValueError("certificate valid interval is inverted")
        if self.range_min > self.range_max: raise ValueError("certificate measurement range is inverted")

@dataclass(frozen=True)
class Reading:
    reading_id: str; segment_id: str; sensor_id: str; pressure_kpa: float; flow_lps: float; acoustic_db: float; observed_at: str
    certificate_id: str = ""; certificate_version: int = 0
    def validate(self) -> None:
        if not self.reading_id.strip() or not self.segment_id.strip() or not self.sensor_id.strip(): raise ValueError("reading identifiers are required")
        if min(self.pressure_kpa, self.flow_lps, self.acoustic_db) < 0: raise ValueError("reading values cannot be negative")
        parse_time(self.observed_at)

def as_dict(value: Any) -> dict[str, Any]:
    return {name: getattr(value, name) for name in value.__dataclass_fields__} if hasattr(value, "__dataclass_fields__") else dict(value)
