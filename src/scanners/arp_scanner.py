from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from scapy.all import ARP, Ether, srp  # type: ignore

from core.models import NetworkDevice

logger = logging.getLogger(__name__)


class ARPScanner:
    def __init__(self, timeout_seconds: float = 1.0) -> None:
        self.timeout_seconds = timeout_seconds

    async def scan(self, subnet: str) -> list[NetworkDevice]:
        return await asyncio.to_thread(self._scan_blocking, subnet)

    def _scan_blocking(self, subnet: str) -> list[NetworkDevice]:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(packet, timeout=self.timeout_seconds, verbose=False)
        found: list[NetworkDevice] = []
        now = datetime.utcnow()
        for _, recv in answered:
            found.append(
                NetworkDevice(
                    ip=recv.psrc,
                    mac=(recv.hwsrc or "").lower() or None,
                    discovery_methods=["arp"],
                    first_seen=now,
                    last_seen=now,
                    raw_evidence={"arp": {"answered": True}},
                )
            )
        logger.info("ARP scan concluído", extra={"event": "arp_scan", "subnet": subnet})
        return found
