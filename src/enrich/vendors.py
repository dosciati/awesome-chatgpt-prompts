from __future__ import annotations

import asyncio
import csv
import logging
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)


def normalize_mac(mac: str) -> str:
    return mac.upper().replace(":", "").replace("-", "")


class VendorLookupProvider:
    async def lookup(self, mac: str) -> str | None:
        raise NotImplementedError


class LocalOuiLookup(VendorLookupProvider):
    def __init__(self, oui_file: str) -> None:
        self.oui_map: dict[str, str] = {}
        self._load(oui_file)

    def _load(self, oui_file: str) -> None:
        path = Path(oui_file)
        if not path.exists():
            logger.warning("Arquivo OUI local não encontrado", extra={"event": "missing_oui", "path": oui_file})
            return
        with path.open("r", encoding="utf-8") as fp:
            reader = csv.DictReader(fp)
            for row in reader:
                prefix = row["prefix"].upper().replace(":", "")[:6]
                self.oui_map[prefix] = row["vendor"].strip()

    async def lookup(self, mac: str) -> str | None:
        prefix = normalize_mac(mac)[:6]
        return self.oui_map.get(prefix)


class ExternalMacVendorApiLookup(VendorLookupProvider):
    def __init__(self, timeout_seconds: float = 1.2, max_rps: float = 4.0) -> None:
        self.timeout_seconds = timeout_seconds
        self.min_interval = 1 / max_rps if max_rps > 0 else 0.25
        self._last_call = 0.0
        self._lock = asyncio.Lock()

    async def lookup(self, mac: str) -> str | None:
        async with self._lock:
            now = asyncio.get_running_loop().time()
            delay = self.min_interval - (now - self._last_call)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_call = asyncio.get_running_loop().time()
        url = f"https://api.macvendors.com/{mac}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    return response.text.strip()
        except httpx.HTTPError:
            return None
        return None


class VendorService:
    def __init__(self, local_provider: VendorLookupProvider, external_provider: VendorLookupProvider | None = None) -> None:
        self.local_provider = local_provider
        self.external_provider = external_provider

    async def lookup(self, mac: str | None, allow_external: bool = False) -> str | None:
        if not mac:
            return None
        local = await self.local_provider.lookup(mac)
        if local:
            return local
        if allow_external and self.external_provider:
            return await self.external_provider.lookup(mac)
        return None
