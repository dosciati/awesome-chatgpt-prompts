from __future__ import annotations

import asyncio
import csv
import io
import logging
from collections import OrderedDict
from datetime import datetime

from classify.device_classifier import DeviceClassifier
from core.config import Settings
from core.models import NetworkDevice, ScanComparison, ScanMode, ScanRequest, ScanResult, ScanStatus, ScanSummary
from enrich.fingerprint import FingerprintEnricher
from enrich.hostname import HostnameEnricher
from enrich.vendors import ExternalMacVendorApiLookup, LocalOuiLookup, VendorService
from scanners.arp_scanner import ARPScanner
from scanners.ping_scanner import PingScanner
from utils.network import compute_gateway_candidates, infer_local_subnet

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.arp_scanner = ARPScanner(timeout_seconds=settings.default_timeout_seconds)
        self.ping_scanner = PingScanner(timeout_seconds=0.35, max_concurrency=settings.default_max_concurrency)
        local_vendor = LocalOuiLookup(settings.vendor_oui_file)
        external_vendor = ExternalMacVendorApiLookup(timeout_seconds=1.2)
        self.vendor_service = VendorService(local_provider=local_vendor, external_provider=external_vendor)
        self.hostname_enricher = HostnameEnricher()
        self.fingerprint_enricher = FingerprintEnricher(max_concurrency=settings.default_max_concurrency)
        self.scans: OrderedDict[str, ScanResult] = OrderedDict()
        self._lock = asyncio.Lock()

    async def start_scan(self, req: ScanRequest) -> ScanResult:
        subnet = req.subnet or infer_local_subnet()
        scan = ScanResult(subnet=subnet, mode=req.mode, status=ScanStatus.PENDING)
        async with self._lock:
            self.scans[scan.scan_id] = scan
            while len(self.scans) > self.settings.history_limit:
                self.scans.popitem(last=False)
        asyncio.create_task(self._run_scan(scan.scan_id, req))
        return scan

    async def _run_scan(self, scan_id: str, req: ScanRequest) -> None:
        scan = self.scans[scan_id]
        scan.status = ScanStatus.RUNNING
        try:
            if req.dry_run:
                await self._run_dry_scan(scan, req)
            else:
                await self._run_real_scan(scan, req)
            scan.status = ScanStatus.COMPLETED
        except Exception as exc:  # noqa: BLE001
            scan.status = ScanStatus.FAILED
            scan.errors.append(str(exc))
            logger.exception("Scan falhou", extra={"scan_id": scan_id, "event": "scan_failed"})
        finally:
            scan.completed_at = datetime.utcnow()

    async def _run_dry_scan(self, scan: ScanResult, req: ScanRequest) -> None:
        samples = [
            NetworkDevice(ip="192.168.1.1", mac="a4:2b:b0:aa:11:22", discovery_methods=["dry_run"]),
            NetworkDevice(ip="192.168.1.20", mac="3c:52:82:33:44:55", discovery_methods=["dry_run"]),
            NetworkDevice(ip="192.168.1.77", mac="28:6d:97:aa:bb:cc", discovery_methods=["dry_run"]),
        ]
        for dev in samples:
            await self._enrich_and_upsert(scan, dev, req)
            await asyncio.sleep(0.02)

    async def _run_real_scan(self, scan: ScanResult, req: ScanRequest) -> None:
        found = await self.arp_scanner.scan(scan.subnet)
        if not found:
            fallback = await self.ping_scanner.scan(scan.subnet, ports=[80, 443, 22, 53])
            for dev in fallback:
                await self._upsert_device(scan, dev)
        else:
            for dev in found:
                await self._upsert_device(scan, dev)

        tasks = [self._enrich_existing(scan, ip, req) for ip in list(scan.devices.keys())]
        await asyncio.gather(*tasks)

    async def _enrich_existing(self, scan: ScanResult, ip: str, req: ScanRequest) -> None:
        base = scan.devices[ip]
        await self._enrich_and_upsert(scan, base, req)

    async def _enrich_and_upsert(self, scan: ScanResult, base: NetworkDevice, req: ScanRequest) -> None:
        ip = base.ip
        base.vendor = await self.vendor_service.lookup(base.mac, allow_external=req.use_external_vendor_api)

        hostname, methods = await self.hostname_enricher.enrich(ip)
        if hostname:
            base.hostname = hostname
            base.discovery_methods.extend(methods)

        if req.mode in {ScanMode.BALANCED, ScanMode.DEEP}:
            fingerprint = await self.fingerprint_enricher.scan_ports(ip, req.port_list)
            base.open_ports = sorted(set(base.open_ports + fingerprint.open_ports))
            base.services = sorted(set(base.services + fingerprint.services))
            base.os_guess = fingerprint.os_guess
            base.raw_evidence["banners"] = fingerprint.banners

        classifier = DeviceClassifier(gateway_candidates=compute_gateway_candidates(scan.subnet))
        classification = classifier.classify(base)
        base.device_type = classification.device_type
        base.confidence = classification.confidence
        base.classification_reason = classification.reason
        base.raw_evidence["classification"] = classification.evidence_scores
        base.last_seen = datetime.utcnow()
        base.first_seen = base.first_seen or base.last_seen
        await self._upsert_device(scan, base)

    async def _upsert_device(self, scan: ScanResult, dev: NetworkDevice) -> None:
        existing = scan.devices.get(dev.ip)
        if existing:
            existing.merge(dev)
        else:
            scan.devices[dev.ip] = dev

    async def get_scan(self, scan_id: str) -> ScanResult | None:
        return self.scans.get(scan_id)

    async def list_scan_summaries(self) -> list[ScanSummary]:
        return [
            ScanSummary(
                scan_id=scan.scan_id,
                subnet=scan.subnet,
                status=scan.status,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                device_count=len(scan.devices),
            )
            for scan in reversed(self.scans.values())
        ]

    async def get_devices(self) -> list[NetworkDevice]:
        merged: dict[str, NetworkDevice] = {}
        for scan in self.scans.values():
            for ip, device in scan.devices.items():
                if ip in merged:
                    merged[ip].merge(device)
                else:
                    merged[ip] = device.model_copy(deep=True)
        return sorted(merged.values(), key=lambda d: d.ip)

    async def get_device(self, ip: str) -> NetworkDevice | None:
        devices = await self.get_devices()
        for device in devices:
            if device.ip == ip:
                return device
        return None

    async def compare_scans(self, base_scan_id: str, target_scan_id: str) -> ScanComparison:
        base = self.scans[base_scan_id]
        target = self.scans[target_scan_id]
        base_ips = set(base.devices.keys())
        target_ips = set(target.devices.keys())
        return ScanComparison(
            base_scan_id=base_scan_id,
            target_scan_id=target_scan_id,
            new_ips=sorted(target_ips - base_ips),
            removed_ips=sorted(base_ips - target_ips),
            unchanged_ips=sorted(base_ips & target_ips),
        )

    async def export_scan(self, scan_id: str, fmt: str) -> tuple[str, str]:
        scan = self.scans[scan_id]
        devices = list(scan.devices.values())
        if fmt == "json":
            return "application/json", scan.model_dump_json(indent=2)
        if fmt == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["ip", "mac", "vendor", "hostname", "os_guess", "device_type", "confidence", "open_ports", "services"])
            for device in devices:
                writer.writerow(
                    [
                        device.ip,
                        device.mac,
                        device.vendor,
                        device.hostname,
                        device.os_guess,
                        device.device_type,
                        device.confidence,
                        "|".join(map(str, device.open_ports)),
                        "|".join(device.services),
                    ]
                )
            return "text/csv", output.getvalue()
        raise ValueError("Formato inválido. Use json ou csv")
