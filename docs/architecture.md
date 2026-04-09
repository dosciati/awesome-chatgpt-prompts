# Arquitetura

## Camada 1 — Descoberta rápida
- `ARPScanner` usa broadcast ARP para obter IP/MAC rapidamente.
- `PingScanner` faz fallback de conectividade por TCP quando ARP indisponível.

## Camada 2 — Enriquecimento
- `VendorService` com provider local OUI e fallback opcional de API externa com rate-limit.
- `HostnameEnricher` via reverse DNS.
- `FingerprintEnricher` com varredura limitada de portas e inferência de serviço/OS.

## Camada 3 — Classificação
- `DeviceClassifier` agrega sinais por regras ponderadas.
- Gera tipo, score de confiança e justificativa curta.

## Serviço de orquestração
- `ScanService` gerencia ciclo do scan em background (`asyncio.create_task`),
  atualiza resultados incrementalmente e mantém histórico em memória.
