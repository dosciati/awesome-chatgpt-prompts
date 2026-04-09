from __future__ import annotations

from datetime import datetime
from enum import Enum
from ipaddress import IPv4Network
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class ScanMode(str, Enum):
    FAST = "fast"
    BALANCED = "balanced"
    DEEP = "deep"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class DeviceFingerprint(BaseModel):
    open_ports: list[int] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    os_guess: str | None = None
    banners: dict[int, str] = Field(default_factory=dict)


class ClassificationResult(BaseModel):
    device_type: str = "unknown"
    confidence: float = 0.0
    reason: str = "Insufficient evidence"
    evidence_scores: dict[str, float] = Field(default_factory=dict)


class NetworkDevice(BaseModel):
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    os_guess: str | None = None
    device_type: str | None = None
    confidence: float = 0.0
    open_ports: list[int] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    discovery_methods: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    classification_reason: str | None = None

    def merge(self, other: "NetworkDevice") -> None:
        self.mac = self.mac or other.mac
        self.vendor = self.vendor or other.vendor
        self.hostname = self.hostname or other.hostname
        self.os_guess = self.os_guess or other.os_guess
        self.device_type = self.device_type or other.device_type
        self.confidence = max(self.confidence, other.confidence)
        self.open_ports = sorted(set(self.open_ports + other.open_ports))
        self.services = sorted(set(self.services + other.services))
        self.discovery_methods = sorted(set(self.discovery_methods + other.discovery_methods))
        self.raw_evidence = {**self.raw_evidence, **other.raw_evidence}
        self.last_seen = other.last_seen or self.last_seen
        self.first_seen = self.first_seen or other.first_seen
        self.classification_reason = self.classification_reason or other.classification_reason


class ScanRequest(BaseModel):
    subnet: str | None = None
    mode: ScanMode = ScanMode.FAST
    timeout_seconds: float = 1.0
    max_concurrency: int = 64
    port_list: list[int] = Field(default_factory=lambda: [22, 53, 80, 135, 139, 443, 445, 515, 631, 9100, 554, 8008, 8080])
    dry_run: bool = False
    use_external_vendor_api: bool = False
    external_vendor_timeout: float = 1.2
    include_nmap: bool = False

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, value: str | None) -> str | None:
        if value is None:
            return value
        IPv4Network(value, strict=False)
        return value


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    subnet: str
    mode: ScanMode
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    devices: dict[str, NetworkDevice] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    scan_id: str
    subnet: str
    status: ScanStatus
    started_at: datetime
    completed_at: datetime | None
    device_count: int


class ScanComparison(BaseModel):
    base_scan_id: str
    target_scan_id: str
    new_ips: list[str]
    removed_ips: list[str]
    unchanged_ips: list[str]
