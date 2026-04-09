from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from core.models import ClassificationResult, NetworkDevice


@dataclass
class HeuristicRule:
    device_type: str
    weight: float
    matcher: Callable[[NetworkDevice], float]
    reason: str


class DeviceClassifier:
    def __init__(self, gateway_candidates: set[str] | None = None) -> None:
        self.gateway_candidates = gateway_candidates or set()
        self.vendor_printer = {"hp", "brother", "epson", "xerox", "canon", "lexmark"}
        self.vendor_network = {"cisco", "mikrotik", "ubiquiti", "aruba", "huawei", "tp-link", "netgear", "juniper"}
        self.vendor_mobile = {"apple", "samsung", "xiaomi", "motorola", "oneplus", "google"}
        self.vendor_tv = {"lg", "samsung", "sony", "tcl", "roku", "hisense", "philips"}
        self.vendor_camera = {"hikvision", "dahua", "axis", "reolink", "uniview"}

    def classify(self, device: NetworkDevice) -> ClassificationResult:
        signals: dict[str, float] = {
            "printer": self._score_printer(device),
            "router": self._score_router(device),
            "switch": self._score_switch(device),
            "access_point": self._score_ap(device),
            "camera_ip": self._score_camera(device),
            "smart_tv": self._score_tv(device),
            "smartphone": self._score_smartphone(device),
            "server": self._score_server(device),
            "computer": self._score_computer(device),
            "iot_generic": self._score_iot(device),
        }
        winner, score = max(signals.items(), key=lambda item: item[1])
        if score < 0.25:
            return ClassificationResult(device_type="unknown", confidence=0.2, reason="Sem evidências suficientes", evidence_scores=signals)
        reason = self._build_reason(device, winner)
        return ClassificationResult(device_type=winner, confidence=min(1.0, round(score, 2)), reason=reason, evidence_scores=signals)

    def _contains_vendor(self, device: NetworkDevice, words: set[str]) -> bool:
        return bool(device.vendor and any(w in device.vendor.lower() for w in words))

    def _has_ports(self, device: NetworkDevice, ports: set[int]) -> int:
        return len(set(device.open_ports) & ports)

    def _score_printer(self, d: NetworkDevice) -> float:
        score = 0.0
        score += 0.45 if self._has_ports(d, {9100, 515, 631}) >= 1 else 0
        score += 0.3 if d.hostname and any(k in d.hostname.lower() for k in ("print", "hp", "epson", "brother")) else 0
        score += 0.25 if self._contains_vendor(d, self.vendor_printer) else 0
        return score

    def _score_router(self, d: NetworkDevice) -> float:
        score = 0.0
        score += 0.35 if d.ip in self.gateway_candidates else 0
        score += 0.3 if self._has_ports(d, {53, 80, 443, 8291, 23}) >= 2 else 0
        score += 0.2 if self._contains_vendor(d, self.vendor_network) else 0
        score += 0.15 if d.hostname and any(k in d.hostname.lower() for k in ("router", "gateway", "gw")) else 0
        return score

    def _score_switch(self, d: NetworkDevice) -> float:
        score = 0.0
        score += 0.35 if self._contains_vendor(d, self.vendor_network) else 0
        score += 0.3 if self._has_ports(d, {22, 80, 443, 161}) >= 2 else 0
        score += 0.2 if d.hostname and "switch" in d.hostname.lower() else 0
        return score

    def _score_ap(self, d: NetworkDevice) -> float:
        score = 0.0
        score += 0.3 if self._contains_vendor(d, self.vendor_network) else 0
        score += 0.3 if d.hostname and any(k in d.hostname.lower() for k in ("ap", "wifi", "wlan")) else 0
        score += 0.2 if self._has_ports(d, {80, 443, 8080}) >= 1 else 0
        return score

    def _score_camera(self, d: NetworkDevice) -> float:
        score = 0.0
        score += 0.5 if self._has_ports(d, {554, 8000, 8080, 80, 8899}) >= 2 else 0
        score += 0.25 if self._contains_vendor(d, self.vendor_camera) else 0
        score += 0.2 if d.hostname and any(k in d.hostname.lower() for k in ("cam", "ipc", "nvr")) else 0
        return score

    def _score_tv(self, d: NetworkDevice) -> float:
        score = 0.0
        score += 0.35 if self._contains_vendor(d, self.vendor_tv) else 0
        score += 0.25 if self._has_ports(d, {8008, 8009, 9080, 5353}) >= 1 else 0
        score += 0.2 if d.hostname and any(k in d.hostname.lower() for k in ("tv", "chromecast", "roku")) else 0
        return score

    def _score_smartphone(self, d: NetworkDevice) -> float:
        score = 0.0
        score += 0.35 if self._contains_vendor(d, self.vendor_mobile) else 0
        score += 0.2 if len(d.open_ports) <= 2 else 0
        score += 0.2 if d.hostname and any(k in d.hostname.lower() for k in ("iphone", "android", "phone")) else 0
        return score

    def _score_server(self, d: NetworkDevice) -> float:
        score = 0.0
        score += 0.4 if self._has_ports(d, {22, 80, 443, 445, 3389, 5432, 3306}) >= 3 else 0
        score += 0.25 if d.os_guess and any(k in d.os_guess.lower() for k in ("linux", "windows")) else 0
        score += 0.15 if d.hostname and any(k in d.hostname.lower() for k in ("srv", "server", "db", "nas")) else 0
        return score

    def _score_computer(self, d: NetworkDevice) -> float:
        score = 0.0
        score += 0.35 if self._has_ports(d, {22, 139, 445, 3389}) >= 1 else 0
        score += 0.2 if d.hostname and any(k in d.hostname.lower() for k in ("desktop", "laptop", "pc", "note")) else 0
        score += 0.15 if d.os_guess is not None else 0
        return score

    def _score_iot(self, d: NetworkDevice) -> float:
        score = 0.0
        score += 0.3 if self._has_ports(d, {1883, 8883, 5683}) >= 1 else 0
        score += 0.2 if len(d.open_ports) <= 3 and len(d.services) <= 3 else 0
        score += 0.2 if d.hostname and any(k in d.hostname.lower() for k in ("esp", "iot", "sensor", "smart")) else 0
        return score

    def _build_reason(self, device: NetworkDevice, winner: str) -> str:
        parts: list[str] = []
        if device.vendor:
            parts.append(f"vendor={device.vendor}")
        if device.hostname:
            parts.append(f"hostname={device.hostname}")
        if device.open_ports:
            parts.append(f"ports={sorted(device.open_ports)}")
        if device.os_guess:
            parts.append(f"os={device.os_guess}")
        if not parts:
            return f"Classificação {winner} por sinais fracos"
        return f"Classificação {winner} baseada em " + ", ".join(parts[:3])
