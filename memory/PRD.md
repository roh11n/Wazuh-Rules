# OSINT Automation Pipeline — PRD

## Original problem statement
Build a full-stack OSINT reconnaissance platform that scans a target domain across 11 phases
(RDAP, DNS, subdomains, HTTP probing, TLS, tech fingerprinting, screenshots, IP intelligence,
TCP port scanning, passive DNS, VirusTotal reputation, Google dorking) and produces a risk
score plus downloadable HTML report. User chose: React + FastAPI + MongoDB, Playwright screenshots
enabled, keys optional (set via Settings UI), Google dorking kept as best-effort.

## Architecture
- **Backend** `/app/backend/`
  - `server.py` — FastAPI, routes under `/api`
  - `osint/` — pipeline package
    - `orchestrator.py` — 11-phase async runner with progress callback
    - `collectors/` — rdap.py, whois_fallback.py, passive_subdomains.py (crt.sh + OTX + HackerTarget), dorking.py
    - `processors/` — dns_records.py, dns_resolver.py, http_probe.py, tls_cert.py, tech_fingerprint.py, screenshots.py (Playwright), port_scanner.py (async TCP connect on 25 common ports + banner grab)
    - `enrichment/` — ipinfo_adapter.py, reputation.py (AbuseIPDB), virustotal_adapter.py, ip_whois.py (RDAP), passive_dns_otx.py
    - `scoring.py`, `models.py`, `report.py` (Jinja2 HTML), `config.py`, `utils.py`
  - MongoDB collections: `scans` (full result JSON + progress), `settings` (API keys)
- **Frontend** `/app/frontend/src/`
  - Dark terminal aesthetic, zinc-950 bg, cyan accent, IBM Plex Sans + JetBrains Mono
  - Pages: Landing (/), History (/scans), Detail (/scans/:id), Settings (/settings)
  - Components: Topbar, SeverityBadge, ScanProgress (11-phase stepper with scan-line animation), section cards
  - Polling: detail polls every 2s until done; history polls every 5s

## What's been implemented (2026-04-20)
- ✅ All 8 original modules + 2 extra (port scanner + extra subdomain sources)
- ✅ REST API: POST/GET/DELETE /api/scans, GET /api/scans/{id}/status|report, GET/PUT /api/settings
- ✅ Risk scoring: domain age, TLD, DNSSEC, SPF/DMARC, MX, flagged IPs, sensitive ports,
  expired/self-signed TLS, VT reputation, pDNS churn, domain status
- ✅ HTML report at /api/scans/{id}/report
- ✅ Tested end-to-end on example.com (completes ~10-20s with skip_dorking+skip_screenshots)
- ✅ Testing agent: 11/11 backend pass, 100% frontend pass

## User personas
1. **Security analyst** — needs quick domain recon + risk assessment
2. **Threat researcher** — wants passive DNS + WHOIS to correlate infra
3. **Bug bounty hunter** — uses subdomain enum + tech fingerprint + dorking

## Core requirements (static)
- Risk severity must be color-coded (green/yellow/orange/red)
- Monospace font for all technical data (IPs, hashes, DNS)
- Progress visible during long scans
- HTML report downloadable
- API keys stored server-side, never exposed to frontend plaintext

## Backlog (P0/P1/P2)
- **P1** — WebSocket progress instead of polling
- **P1** — Bulk scan / CSV import of targets
- **P2** — Scheduled recurring scans with diff alerts
- **P2** — PDF export (needs weasyprint system deps)
- **P2** — Authentication (JWT / Emergent Google Auth)
- **P2** — Diff view between two scans of same target
- **P2** — Shodan / Censys enrichment
- **P2** — Discord/Slack alert integration (endpoint stored, not yet wired)

## Next tasks
- Enable Discord webhook firing on MEDIUM+ scans (already stored, just needs call)
- Add retry logic for RDAP/OTX 429 responses
- Add scan comparison view
