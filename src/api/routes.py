from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from core.models import ScanRequest
from services.scan_service import ScanService


def build_router(scan_service: ScanService) -> APIRouter:
    router = APIRouter()

    @router.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @router.post("/scan")
    async def create_scan(request: ScanRequest) -> dict:
        scan = await scan_service.start_scan(request)
        return scan.model_dump(mode="json")

    @router.get("/scan/{scan_id}")
    async def get_scan(scan_id: str) -> dict:
        scan = await scan_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan não encontrado")
        return scan.model_dump(mode="json")

    @router.get("/scan")
    async def list_scans() -> list[dict]:
        scans = await scan_service.list_scan_summaries()
        return [s.model_dump(mode="json") for s in scans]

    @router.get("/scan/{scan_id}/export", response_class=PlainTextResponse)
    async def export_scan(scan_id: str, fmt: str = Query(default="json", pattern="^(json|csv)$")) -> PlainTextResponse:
        try:
            media_type, payload = await scan_service.export_scan(scan_id, fmt)
            return PlainTextResponse(content=payload, media_type=media_type)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Scan não encontrado") from exc

    @router.get("/scan/{base_scan_id}/compare/{target_scan_id}")
    async def compare_scans(base_scan_id: str, target_scan_id: str) -> dict:
        try:
            result = await scan_service.compare_scans(base_scan_id, target_scan_id)
            return result.model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Scan para comparação não encontrado") from exc

    @router.get("/devices")
    async def list_devices() -> list[dict]:
        devices = await scan_service.get_devices()
        return [d.model_dump(mode="json") for d in devices]

    @router.get("/devices/{ip}")
    async def get_device(ip: str) -> dict:
        device = await scan_service.get_device(ip)
        if not device:
            raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
        return device.model_dump(mode="json")

    return router
