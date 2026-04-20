"""Main pipeline orchestrator — supports domain | website | ip | dork modes."""
import asyncio
import re
from typing import Callable, Awaitable
from osint.models import ScanRequest, ScanResult, IPIntelRecord
from osint.scoring import compute_risk
from osint.utils import apex_of

from osint.collectors.rdap import RDAPCollector
from osint.collectors.whois_fallback import WhoisFallbackCollector
from osint.collectors.passive_subdomains import PassiveSubdomainCollector
from osint.collectors.dorking import GoogleDorker

from osint.processors.dns_records import DNSRecordCollector
from osint.processors.dns_resolver import DNSResolver
from osint.processors.http_probe import HTTPProbe
from osint.processors.tls_cert import TLSCertCollector
from osint.processors.tech_fingerprint import TechFingerprintCollector
from osint.processors.screenshots import ScreenshotService
from osint.processors.port_scanner import PortScanner
from osint.processors.directory_enum import DirectoryEnumerator

from osint.enrichment.ipinfo_adapter import IPInfoAdapter
from osint.enrichment.reputation import AbuseIPDBAdapter
from osint.enrichment.virustotal_adapter import VirusTotalAdapter
from osint.enrichment.ip_whois import IPWhoisCollector
from osint.enrichment.passive_dns_otx import PassiveDNSOTX
from osint.enrichment.shodan_adapter import ShodanAdapter


ProgressCallback = Callable[[str, int, str], Awaitable[None]]
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


class Orchestrator:
    def __init__(self):
        self.rdap = RDAPCollector()
        self.whois = WhoisFallbackCollector()
        self.subs = PassiveSubdomainCollector()
        self.dorker = GoogleDorker()

        self.dns_rec = DNSRecordCollector()
        self.dns_res = DNSResolver()
        self.http = HTTPProbe()
        self.tls = TLSCertCollector()
        self.tech = TechFingerprintCollector()
        self.screenshots = ScreenshotService()
        self.ports = PortScanner()
        self.dirs = DirectoryEnumerator()

        self.ipinfo = IPInfoAdapter()
        self.abuse = AbuseIPDBAdapter()
        self.vt = VirusTotalAdapter()
        self.ip_whois = IPWhoisCollector()
        self.passive_dns = PassiveDNSOTX()
        self.shodan = ShodanAdapter()

    async def run(self, req: ScanRequest, progress: ProgressCallback | None = None) -> ScanResult:
        mode = (req.mode or "domain").lower()
        result = ScanResult(target=req.target)

        async def _p(phase: str, pct: int, msg: str):
            if progress:
                try:
                    await progress(phase, pct, msg)
                except Exception:
                    pass

        if mode == "ip":
            await self._ip_scan(req, result, _p)
        elif mode == "website":
            await self._website_scan(req, result, _p)
        elif mode == "dork":
            await self._dork_scan(req, result, _p)
        else:
            await self._domain_scan(req, result, _p)

        await _p("risk", 98, "Computing risk score")
        result.risk = compute_risk(result)
        await _p("done", 100, "Complete")
        return result

    # ───────────────────────── DOMAIN ─────────────────────────
    async def _domain_scan(self, req: ScanRequest, result: ScanResult, _p: ProgressCallback):
        target = req.target

        await _p("domain", 5, "RDAP + DNS records")
        phase1 = await asyncio.gather(
            self._safe(self.rdap.collect(target)),
            self._safe(self.dns_rec.collect(target)),
        )
        result.domain = phase1[0] or await self._safe(self.whois.collect(target))
        if phase1[1]:
            result.dns_records = phase1[1]

        await _p("subdomains", 15, "Enumerating subdomains (crt.sh + OTX + HackerTarget)")
        result.subdomains = await self._safe(self.subs.collect(target), default=[])

        all_hosts = sorted({s.subdomain for s in result.subdomains} | {target})

        await _p("dns_resolve", 25, f"Resolving {len(all_hosts)} hosts")
        dns_results = await asyncio.gather(
            *[self._safe(self.dns_res.resolve_a(h), default=[]) for h in all_hosts]
        )
        for r in dns_results:
            if r:
                result.dns.extend(r)

        unique_hosts = sorted({r.subdomain for r in result.dns})
        unique_ips = sorted({r.ip for r in result.dns})

        await _p("http_probe", 35, f"Probing {len(unique_hosts)} hosts")
        http_results = await asyncio.gather(
            *[self._safe(self.http.probe(h), default=[]) for h in unique_hosts]
        )
        for r in http_results:
            if r:
                result.live_hosts.extend(r)

        live = [lh.host for lh in result.live_hosts][:15]
        live_urls = [lh.url for lh in result.live_hosts][:15]

        await _p("tls_tech_ss", 50, f"TLS + tech + screenshots on {len(live)} hosts")
        tls_t = [self._safe(self.tls.collect(h)) for h in live]
        tech_t = [self._safe(self.tech.fingerprint(h)) for h in live]
        ss_t = ([self._noop() for _ in live] if req.skip_screenshots
                else [self._safe(self.screenshots.capture(h)) for h in live])

        tls_r, tech_r, ss_r = await asyncio.gather(
            asyncio.gather(*tls_t), asyncio.gather(*tech_t), asyncio.gather(*ss_t),
        )
        result.tls_certs = [c for c in tls_r if c]
        result.tech_fingerprints = [t for t in tech_r if t]
        result.screenshots = [s for s in ss_r if s]

        await _p("ip_enrich", 62, f"IP enrichment + Shodan on {len(unique_ips)} IPs")
        ipi, ab, wh, shod = [], [], [], []
        for ip in unique_ips:
            ipi.append(self._safe(self.ipinfo.lookup(ip)))
            ab.append(self._safe(self.abuse.lookup(ip)))
            wh.append(self._safe(self.ip_whois.lookup(ip)))
            shod.append(self._safe(self.shodan.lookup(ip)))
        ipi_r, ab_r, wh_r, sh_r = await asyncio.gather(
            asyncio.gather(*ipi), asyncio.gather(*ab),
            asyncio.gather(*wh), asyncio.gather(*shod),
        )
        result.ips = self._merge_ips(ipi_r, ab_r)
        result.ip_whois = [w for w in wh_r if w]
        result.shodan = [s for s in sh_r if s]

        if not req.skip_ports:
            await _p("port_scan", 72, f"Port scanning {min(len(live), 10)} hosts")
            port_results = await asyncio.gather(
                *[self._safe(self.ports.scan_host(h), default=[]) for h in live[:10]]
            )
            for services in port_results:
                if services:
                    result.services.extend(services)

        if not req.skip_directories:
            await _p("directories", 80, f"Directory enum on {min(len(live_urls), 5)} hosts")
            dir_tasks = [self._enum_dirs(h, u) for h, u in zip(live[:5], live_urls[:5])]
            dir_results = await asyncio.gather(*dir_tasks)
            result.directories = [d for d in dir_results if d and d.entries]

        await _p("passive_dns", 88, "Passive DNS (OTX)")
        result.passive_dns = await self._safe(self.passive_dns.lookup(target), default=[])

        await _p("reputation", 92, "VirusTotal reputation")
        result.reputation = await self._safe(self.vt.lookup_domain(target))

        if not req.skip_dorking:
            await _p("dorking", 95, "Google dorking")
            result.dorking = await self._safe(
                self.dorker.run(target, custom_queries=req.dork_queries or None, use_defaults=True),
                default=[],
            )

    # ───────────────────────── WEBSITE ─────────────────────────
    async def _website_scan(self, req: ScanRequest, result: ScanResult, _p: ProgressCallback):
        host = req.target

        await _p("dns_resolve", 10, f"Resolving {host}")
        dns_records = await self._safe(self.dns_res.resolve_a(host), default=[])
        result.dns = dns_records

        await _p("domain", 20, "DNS records + DNSSEC check")
        apex = apex_of(host)
        dns_full = await self._safe(self.dns_rec.collect(apex))
        if dns_full:
            result.dns_records = dns_full
        # DNSSEC check via RDAP on the apex
        rdap = await self._safe(self.rdap.collect(apex))
        if rdap:
            result.domain = rdap

        await _p("http_probe", 35, f"Probing {host}")
        result.live_hosts = await self._safe(self.http.probe(host), default=[])

        await _p("tls_tech_ss", 55, f"TLS cert + tech fingerprint + screenshot")
        tls, tech, ss = await asyncio.gather(
            self._safe(self.tls.collect(host)),
            self._safe(self.tech.fingerprint(host)),
            (self._noop() if req.skip_screenshots else self._safe(self.screenshots.capture(host))),
        )
        if tls: result.tls_certs = [tls]
        if tech: result.tech_fingerprints = [tech]
        if ss: result.screenshots = [ss]

        unique_ips = sorted({r.ip for r in result.dns})

        await _p("ip_enrich", 68, f"Network info on {len(unique_ips)} IPs")
        ipi = await asyncio.gather(*[self._safe(self.ipinfo.lookup(ip)) for ip in unique_ips])
        wh = await asyncio.gather(*[self._safe(self.ip_whois.lookup(ip)) for ip in unique_ips])
        result.ips = [i for i in ipi if i]
        result.ip_whois = [w for w in wh if w]

        if not req.skip_ports:
            await _p("port_scan", 78, "Port scanning")
            services = await self._safe(self.ports.scan_host(host), default=[])
            if services:
                result.services = services

        if not req.skip_directories and result.live_hosts:
            await _p("directories", 88, "Directory enumeration")
            for lh in result.live_hosts[:1]:
                d = await self._enum_dirs(lh.host, lh.url)
                if d and d.entries:
                    result.directories.append(d)

    # ───────────────────────── IP ─────────────────────────
    async def _ip_scan(self, req: ScanRequest, result: ScanResult, _p: ProgressCallback):
        ip = req.target
        if not IP_RE.match(ip):
            raise ValueError(f"Invalid IP: {ip}")

        await _p("ip_enrich", 15, "IPInfo + AbuseIPDB")
        ipi, ab = await asyncio.gather(
            self._safe(self.ipinfo.lookup(ip)),
            self._safe(self.abuse.lookup(ip)),
        )
        result.ips = self._merge_ips([ipi], [ab])

        await _p("ip_whois", 35, "IP WHOIS / RDAP")
        wh = await self._safe(self.ip_whois.lookup(ip))
        if wh:
            result.ip_whois = [wh]

        await _p("shodan", 55, "Shodan — open ports + banners + vulns")
        sh = await self._safe(self.shodan.lookup(ip))
        if sh:
            result.shodan = [sh]

        await _p("port_scan", 72, "TCP port scan (supplementary)")
        if not req.skip_ports:
            services = await self._safe(self.ports.scan_host(ip), default=[])
            if services:
                result.services = services

        await _p("passive_dns", 88, "Passive DNS replication (OTX)")
        result.passive_dns = await self._safe(self._otx_ip_pdns(ip), default=[])

    # ───────────────────────── DORK ─────────────────────────
    async def _dork_scan(self, req: ScanRequest, result: ScanResult, _p: ProgressCallback):
        await _p("dorking", 20, "Google dorking")
        # When mode=dork, the "target" can be a placeholder; queries are what matter.
        queries = req.dork_queries or []
        result.dorking = await self._safe(
            self.dorker.run(req.target, custom_queries=queries, use_defaults=not queries),
            default=[],
        )

    # ───────────────────────── helpers ─────────────────────────
    async def _enum_dirs(self, host: str, base_url: str):
        from osint.models import DirectoryEnumResult
        entries = await self._safe(self.dirs.enumerate(base_url), default=[])
        return DirectoryEnumResult(host=host, base_url=base_url, entries=entries or [])

    async def _otx_ip_pdns(self, ip: str):
        """OTX passive DNS for an IP indicator."""
        import httpx
        from osint.config import settings
        from osint.models import PassiveDNSRecord
        headers = {"User-Agent": settings.user_agent}
        if settings.otx_key:
            headers["X-OTX-API-KEY"] = settings.otx_key
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
        try:
            async with httpx.AsyncClient(timeout=20, headers=headers) as c:
                r = await c.get(url)
                if r.status_code != 200:
                    return []
                d = r.json()
        except Exception:
            return []
        out = []
        seen = set()
        for e in d.get("passive_dns", []):
            key = (e.get("hostname"), e.get("address"))
            if key in seen:
                continue
            seen.add(key)
            out.append(PassiveDNSRecord(
                hostname=e.get("hostname", ""),
                ip=e.get("address") or None,
                record_type=e.get("record_type") or None,
                asn=e.get("asn"),
                first_seen=e.get("first"),
                last_seen=e.get("last"),
                source="otx",
            ))
        return out

    @staticmethod
    def _merge_ips(ipi_list, abuse_list) -> list[IPIntelRecord]:
        merged: dict[str, IPIntelRecord] = {}
        for item in ipi_list:
            if isinstance(item, IPIntelRecord):
                merged[item.ip] = item
        for item in abuse_list:
            if isinstance(item, IPIntelRecord):
                base = merged.get(item.ip, IPIntelRecord(ip=item.ip))
                if item.country: base.country = item.country
                if item.asn: base.asn = item.asn
                if item.org: base.org = item.org
                if item.reputation_score is not None:
                    base.reputation_score = item.reputation_score
                    base.flagged = item.flagged
                merged[item.ip] = base
        return list(merged.values())

    @staticmethod
    async def _safe(coro, default=None):
        try:
            return await coro
        except Exception:
            return default

    @staticmethod
    async def _noop():
        return None
