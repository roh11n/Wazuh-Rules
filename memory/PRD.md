# OSINT Automation Pipeline — PRD

## Original problem statement
Full-stack OSINT reconnaissance platform with 5 scan modes (Domain / Website / IP / Dork / Shodan Search),
CVE/NVD enrichment for Shodan-reported vulnerabilities, and directory enumeration.
User-provided keys: Shodan + OTX (live in `.env`).

## Architecture
- **Backend** `/app/backend/`
  - `server.py` — FastAPI `/api` routes, mode-aware scan dispatch, Mongo `scans`/`settings`/`cve_cache` collections
  - `osint/orchestrator.py` — 5 mode-specific pipelines + NVD enrichment pass
  - `osint/collectors/` — rdap, whois_fallback, passive_subdomains (crt.sh+OTX+HackerTarget), dorking
  - `osint/processors/` — dns_records, dns_resolver, http_probe, tls_cert, tech_fingerprint, screenshots (Playwright), port_scanner (25 TCP ports), directory_enum (44 paths)
  - `osint/enrichment/` — ipinfo, reputation (AbuseIPDB), virustotal, ip_whois (RDAP), passive_dns_otx, shodan_adapter, shodan_search, **nvd_adapter** (Mongo-cached)
  - `osint/scoring.py` — risk scoring with **CVE severity boosts** (+15 per CRITICAL CVE, cap 30; +5 per HIGH, cap 15)
  - `osint/report.py` — Jinja2 HTML report with all sections including CVEs & Shodan Search
- **Frontend** `/app/frontend/src/`
  - Dark terminal UI, cyan accent, IBM Plex Sans + JetBrains Mono
  - **Landing** — 5 mode tabs with conditional form fields + Shodan query examples card (incl. `vuln:CVE-2021-44228`)
  - **History** — mode badge column
  - **Detail** — mode-aware section rendering (hides irrelevant empty sections). Sections: Risk, Shodan Search Results, **CVE / NVD** (sorted by CVSS desc, NVD hyperlinks, severity-colored badges), Domain Intel (with RDAP status pills), DNS, Subs, Live Hosts, TLS, IPs, Ports, Shodan Intel, Dirs, pDNS, Tech, Screenshots, Dorking
  - **Settings** — 6 API keys (IPInfo, AbuseIPDB, VirusTotal, OTX, Shodan, Discord)

## What's been implemented (2026-04-20)
- ✅ 5 scan modes (domain/website/ip/dork/shodan_search)
- ✅ Shodan host lookup (with vulns, services, SSL cert issuer)
- ✅ Shodan search API (query Shodan by product, port, country, cert, org, vuln)
- ✅ NVD CVE enrichment (CVSS score, severity, description, vector, published date, NVD URL)
- ✅ Mongo `cve_cache` collection for NVD results (avoids rate limits)
- ✅ Risk scoring boost for CRITICAL/HIGH CVEs
- ✅ Mode-aware Detail page (hides empty sections for shodan_search mode)
- ✅ Testing agent: 21/21 backend, 100% frontend on all sections
- ✅ Live validated: 8.8.8.8 (Google LLC Shodan), apache country:"NL" port:80 (150K Apache search), CVE-2021-44228 Log4Shell CRITICAL/10.0 via NVD

## Next tasks / P1–P2
- P1 — Discord webhook firing on MEDIUM+ scans
- P1 — Bulk CSV target import
- P2 — Scheduled recurring scans with diff alerts
- P2 — PDF export (weasyprint)
- P2 — Emergent Google Auth / JWT for multi-user
- P2 — Scan comparison / diff view (same target over time)
- P2 — CVE EPSS exploit-probability enrichment
- P2 — ExploitDB / Metasploit module references for each CVE
