from __future__ import annotations

import asyncio
import re

from core.models import DeviceFingerprint


SERVICE_MAP = {
    22: "ssh",
    53: "dns",
    80: "http",
    135: "msrpc",
    139: "netbios",
    443: "https",
    445: "smb",
    515: "lpd",
    631: "ipp",
    554: "rtsp",
    9100: "jetdirect",
}


class FingerprintEnricher:
    def __init__(self, timeout_seconds: float = 0.35, max_concurrency: int = 64) -> None:
        self.timeout_seconds = timeout_seconds
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def scan_ports(self, ip: str, ports: list[int]) -> DeviceFingerprint:
        open_ports: list[int] = []
        services: list[str] = []
        banners: dict[int, str] = {}

        async def probe(port: int) -> None:
            async with self.semaphore:
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=self.timeout_seconds)
                    open_ports.append(port)
                    service = SERVICE_MAP.get(port)
                    if service:
                        services.append(service)
                    banner = await self._grab_banner(reader, writer, service)
                    if banner:
                        banners[port] = banner
                except (TimeoutError, OSError):
                    return

        await asyncio.gather(*[probe(port) for port in ports])
        os_guess = self._infer_os(open_ports, banners)
        return DeviceFingerprint(open_ports=sorted(set(open_ports)), services=sorted(set(services)), os_guess=os_guess, banners=banners)

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, service: str | None) -> str | None:
        try:
            if service in {"http", "https"}:
                writer.write(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
                await writer.drain()
            data = await asyncio.wait_for(reader.read(120), timeout=0.2)
            writer.close()
            await writer.wait_closed()
            cleaned = data.decode(errors="ignore").strip()
            return cleaned[:100] if cleaned else None
        except (TimeoutError, OSError):
            return None

    def _infer_os(self, open_ports: list[int], banners: dict[int, str]) -> str | None:
        text = " ".join(banners.values()).lower()
        if any(p in open_ports for p in (139, 445, 3389)):
            return "Windows-like"
        if 22 in open_ports and re.search(r"openssh|ubuntu|debian|centos", text):
            return "Linux/Unix-like"
        if re.search(r"mikrotik|routeros", text):
            return "Network Appliance"
        return None
