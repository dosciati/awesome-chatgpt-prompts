from __future__ import annotations

import asyncio
import ipaddress
import socket
from datetime import datetime

from core.models import NetworkDevice


class PingScanner:
    def __init__(self, timeout_seconds: float = 0.4, max_concurrency: int = 128) -> None:
        self.timeout_seconds = timeout_seconds
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def scan(self, subnet: str, ports: list[int] | None = None) -> list[NetworkDevice]:
        network = ipaddress.IPv4Network(subnet, strict=False)
        ports = ports or [80, 443, 22, 53]
        now = datetime.utcnow()

        async def probe(ip: str) -> NetworkDevice | None:
            async with self.semaphore:
                open_ports: list[int] = []
                for port in ports:
                    if await self._tcp_ping(ip, port):
                        open_ports.append(port)
                        break
                if open_ports:
                    return NetworkDevice(
                        ip=ip,
                        discovery_methods=["tcp_ping"],
                        open_ports=open_ports,
                        first_seen=now,
                        last_seen=now,
                        raw_evidence={"ping": {"reachable": True}},
                    )
            return None

        tasks = [probe(str(host)) for host in network.hosts()]
        results = await asyncio.gather(*tasks)
        return [item for item in results if item]

    async def _tcp_ping(self, ip: str, port: int) -> bool:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=self.timeout_seconds)
            writer.close()
            await writer.wait_closed()
            return True
        except (TimeoutError, OSError, socket.gaierror):
            return False
