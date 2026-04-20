# OSINT Automation Pipeline — PRD

## Original problem statement
Build a full-stack OSINT reconnaissance platform supporting 4 distinct scan modes
(Domain / Website / IP / Dork), each with its own focused pipeline. Integrations
requested by the user: Shodan (API key provided), OTX (API key provided), plus
directory enumeration per subdomain, RDAP status codes with meaningful display,
and all standard OSINT sources.

## Architecture
- **Backend** `/app/backend/`
  - `server.py` — FastAPI, `/api` routes, dispatches scans by `mode`
  - `osint/`
    - `orchestrator.py` — 4 mode-specific pipelines:
      - `_domain_scan` — RDAP → DNS → subs (crt.sh + OTX + HackerTarget) → resolve → HTTP → TLS+Tech+SS → IP intel → Shodan → Ports → Dirs → pDNS → VT → dorking → risk
      - `_website_scan` — single-host: DNS → Tech/TLS/SS → IPInfo → ports → dirs
      - `_ip_scan` — IPInfo + AbuseIPDB → IP WHOIS → Shodan (with IP record enrichment) → ports → OTX passive DNS replication
      - `_dork_scan` — Google dorking only
    - `collectors/` — rdap, whois_fallback, passive_subdomains (crt.sh + OTX + HackerTarget), dorking
    - `processors/` — dns_records, dns_resolver, http_probe, tls_cert, tech_fingerprint, screenshots (Playwright), port_scanner (async TCP on 25 common ports), **directory_enum** (44 common paths)
    - `enrichment/` — ipinfo, reputation (AbuseIPDB), virustotal, ip_whois (RDAP), passive_dns_otx, **shodan_adapter**
    - `scoring.py`, `models.py`, `report.py`, `config.py`, `utils.py`
  - MongoDB collections: `scans` (+ `mode` field), `settings`
- **Frontend** `/app/frontend/src/`
  - Dark terminal UI, zinc-950 bg, cyan accent, IBM Plex Sans + JetBrains Mono
  - **Landing** — 4 mode tabs (Domain/Website/IP/Dork) with per-mode validation, conditional toggles (Skip SS / Dork / Ports / Dirs)
  - **History** — scans list with mode badge column
  - **Detail** — sections: Risk, Domain (with colored RDAP status pills + tooltips), DNS, Subs, Live Hosts, TLS, IPs, Ports, **Shodan Intel** (with vulns/services table), **Directory Enum**, pDNS, Tech, Screenshots, Dorking. Download HTML report.
  - **Settings** — 6 API key fields (IPInfo, AbuseIPDB, VirusTotal, OTX, **Shodan**, Discord)

## What's been implemented (2026-04-20)
- ✅ 4 scan modes (domain/website/ip/dork) with per-mode pipelines
- ✅ Shodan integration — open ports, banners, vulns, service details, SSL cert issuer
- ✅ OTX passive DNS for both domain and IP indicators
- ✅ Directory enumeration (44 common paths: /.env, /.git, /admin, /wp-admin, /api, /swagger, /backup*, etc.)
- ✅ RDAP statuses with color-coded pills + hover tooltips
- ✅ Shodan → IP record auto-enrichment when IPInfo missing
- ✅ Testing agent: 13/13 backend pass, 100% frontend pass
- ✅ End-to-end verified: 8.8.8.8 IP scan (Shodan Google LLC, 55 services), github.com domain scan (28 IPs, 88 dir entries, 51 subs)

## Next tasks / P1–P2
- P1 — Discord webhook firing on MEDIUM+ scans (setting stored, needs send call)
- P1 — Bulk CSV target import
- P2 — Scheduled recurring scans with diff alerts
- P2 — PDF export (needs weasyprint)
- P2 — Emergent Google Auth / JWT for multi-user
- P2 — Shodan search queries (beyond host lookup)
- P2 — Subfinder / Amass subdomain source parity (already have 3 sources)
