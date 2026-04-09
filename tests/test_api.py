import time

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health() -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_scan_dry_run_flow() -> None:
    start = client.post("/scan", json={"mode": "balanced", "dry_run": True})
    assert start.status_code == 200
    scan_id = start.json()["scan_id"]

    for _ in range(30):
        scan = client.get(f"/scan/{scan_id}")
        payload = scan.json()
        if payload["status"] in {"completed", "failed"}:
            break
        time.sleep(0.05)

    assert payload["status"] == "completed"
    assert len(payload["devices"]) >= 1

    devices = client.get("/devices")
    assert devices.status_code == 200
    assert isinstance(devices.json(), list)
