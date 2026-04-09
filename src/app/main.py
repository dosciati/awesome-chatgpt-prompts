from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from api.routes import build_router
from core.config import get_settings
from core.logging import configure_logging
from services.scan_service import ScanService

settings = get_settings()
configure_logging(settings.log_level)

scan_service = ScanService(settings)
app = FastAPI(title=settings.app_name, version="0.1.0")
app.include_router(build_router(scan_service))


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return """
<!DOCTYPE html>
<html>
<head>
  <meta charset=\"utf-8\"/>
  <title>LAN Discovery</title>
  <style>
    body {font-family: Arial; margin: 20px;}
    table {border-collapse: collapse; width: 100%;}
    th, td {border: 1px solid #ddd; padding: 8px; font-size: 13px;}
    th {background: #f3f3f3;}
  </style>
</head>
<body>
  <h2>LAN Asset Discovery</h2>
  <button onclick=\"startScan()\">Iniciar scan rápido</button>
  <p id=\"status\">Aguardando...</p>
  <table>
    <thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>Tipo</th><th>Confiança</th><th>Portas</th></tr></thead>
    <tbody id=\"rows\"></tbody>
  </table>
<script>
let scanId = null;
let timer = null;
async function startScan() {
  const res = await fetch('/scan', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({mode: 'fast'})
  });
  const data = await res.json();
  scanId = data.scan_id;
  document.getElementById('status').innerText = 'Scan em execução: ' + scanId;
  timer = setInterval(refresh, 1000);
}
async function refresh() {
  if (!scanId) return;
  const res = await fetch('/scan/' + scanId);
  const data = await res.json();
  const rows = document.getElementById('rows');
  rows.innerHTML = '';
  Object.values(data.devices).forEach(dev => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${dev.ip||''}</td><td>${dev.mac||''}</td><td>${dev.vendor||''}</td><td>${dev.hostname||''}</td><td>${dev.device_type||''}</td><td>${dev.confidence||0}</td><td>${(dev.open_ports||[]).join(',')}</td>`;
    rows.appendChild(tr);
  });
  if (data.status === 'completed' || data.status === 'failed') {
    clearInterval(timer);
    document.getElementById('status').innerText = 'Status: ' + data.status + ' / dispositivos: ' + Object.keys(data.devices).length;
  }
}
</script>
</body>
</html>
    """
