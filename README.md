# LAN Asset Discovery (FastAPI + Python)

Aplicação para descoberta e inventário de dispositivos em redes LAN autorizadas, com arquitetura em camadas:
- Descoberta rápida (ARP com fallback TCP ping)
- Enriquecimento (vendor, hostname, fingerprint leve)
- Classificação por heurísticas com score de confiança

## Aviso legal
Use **somente** em redes autorizadas.

## Recursos
- Descoberta automática da subnet local
- Scan manual de subnet (`192.168.0.0/24`)
- Modos `fast`, `balanced`, `deep`
- Resultados incrementais via `GET /scan/{id}`
- Histórico em memória e comparação entre scans
- Exportação de scan para JSON/CSV
- Modo `dry_run` para testes
- Fallback para ambientes sem privilégios de raw socket

## Estrutura
```text
src/
  app/main.py
  api/routes.py
  core/{config.py,logging.py,models.py}
  scanners/{arp_scanner.py,ping_scanner.py}
  enrich/{vendors.py,hostname.py,fingerprint.py}
  classify/device_classifier.py
  services/scan_service.py
  utils/network.py
  data/oui_sample.csv
tests/
docs/
```

## Instalação
### Linux/macOS
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .[dev]
```

## Execução
```bash
uvicorn app.main:app --app-dir src --host 0.0.0.0 --port 8000
```
Abra `http://127.0.0.1:8000`.

## Endpoints
- `POST /scan`
- `GET /scan`
- `GET /scan/{id}`
- `GET /scan/{id}/export?fmt=json|csv`
- `GET /scan/{base_id}/compare/{target_id}`
- `GET /devices`
- `GET /devices/{ip}`
- `GET /health`

### Exemplo de scan rápido
```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "content-type: application/json" \
  -d '{"mode":"fast","subnet":"192.168.1.0/24"}'
```

## Permissões ARP/raw socket
- Linux: execute com privilégios adequados (root/sudo) ou capability de raw sockets.
- Windows: execute terminal como administrador.
- Sem permissão ARP, o serviço faz fallback para TCP ping scan limitado.

## Testes
```bash
pytest
```

## Roadmap por fases
- **Fase 1**: modelos + ARP + vendor local + API + incremental.
- **Fase 2**: hostname + classificação + export + testes.
- **Fase 3**: integração opcional com Nmap + UX + diff de scans.
