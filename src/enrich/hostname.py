from __future__ import annotations

import asyncio
import socket


class HostnameEnricher:
    def __init__(self, timeout_seconds: float = 0.8) -> None:
        self.timeout_seconds = timeout_seconds

    async def reverse_dns(self, ip: str) -> str | None:
        try:
            result = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), timeout=self.timeout_seconds)
            return result[0]
        except (TimeoutError, OSError, socket.herror, socket.gaierror):
            return None

    async def enrich(self, ip: str) -> tuple[str | None, list[str]]:
        hostname = await self.reverse_dns(ip)
        evidence = []
        if hostname:
            evidence.append("reverse_dns")
        return hostname, evidence
