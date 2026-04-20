"""Main pipeline orchestrator."""
import asyncio
from typing import Callable, Awaitable
from osint.models import ScanRequest, ScanResult, IPIntelRecord
from osint.scoring import compute_risk

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

from osint.enrichment.ipinfo_adapter import IPInfoAdapter
from osint.enrichment.reputation import AbuseIPDBAdapter
from osint.enrichment.virustotal_adapter import VirusTotalAdapter
from osint.enrichment.ip_whois import IPWhoisCollector
from osint.enrichment.passive_dns_otx import PassiveDNSOTX


ProgressCallback = Callable[[str, int, str], Awaitable[None]]


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

        self.ipinfo = IPInfoAdapter()
        self.abuse = AbuseIPDBAdapter()
        self.vt = VirusTotalAdapter()
        self.ip_whois = IPWhoisCollector()
        self.passive_dns = PassiveDNSOTX()

    async def run(self, req: ScanRequest, progress: ProgressCallback | None = None) -> ScanResult:
        result = ScanResult(target=req.target)

        async def _p(phase: str, pct: int, msg: str):
            if progress:
                try:
                    await progress(phase, pct, msg)
                except Exception:
                    pass

        await _p("domain", 5, "Resolving domain + DNS records")
        phase1 = await asyncio.gather(
            self._safe(self.rdap.collect(req.target)),
            self._safe(self.dns_rec.collect(req.target)),
        )
        result.domain = phase1[0] or await self._safe(self.whois.collect(req.target))
        if phase1[1]:
            result.dns_records = phase1[1]

        await _p("subdomains", 15, "Enumerating subdomains")
        result.subdomains = await self._safe(self.subs.collect(req.target), default=[])

        all_hosts = sorted({s.subdomain for s in result.subdomains} | {req.target})

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

        await _p("tls_tech_ss", 50, f"TLS + tech + screenshots on {len(live)} hosts")
        tls_t = [self._safe(self.tls.collect(h)) for h in live]
        tech_t = [self._safe(self.tech.fingerprint(h)) for h in live]
        if req.skip_screenshots:
            ss_t = [self._noop() for _ in live]
        else:
            ss_t = [self._safe(self.screenshots.capture(h)) for h in live]

        tls_r, tech_r, ss_r = await asyncio.gather(
            asyncio.gather(*tls_t), asyncio.gather(*tech_t), asyncio.gather(*ss_t),
        )
        result.tls_certs = [c for c in tls_r if c]
        result.tech_fingerprints = [t for t in tech_r if t]
        result.screenshots = [s for s in ss_r if s]

        await _p("ip_enrich", 65, f"IP enrichment on {len(unique_ips)} IPs")
        ipi = [self._safe(self.ipinfo.lookup(ip)) for ip in unique_ips]
        ab = [self._safe(self.abuse.lookup(ip)) for ip in unique_ips]
        wh = [self._safe(self.ip_whois.lookup(ip)) for ip in unique_ips]
        ipi_r, ab_r, wh_r = await asyncio.gather(
            asyncio.gather(*ipi), asyncio.gather(*ab), asyncio.gather(*wh)
        )

        merged: dict[str, IPIntelRecord] = {}
        for item in ipi_r:
            if isinstance(item, IPIntelRecord):
                merged[item.ip] = item
        for item in ab_r:
            if isinstance(item, IPIntelRecord):
                base = merged.get(item.ip, IPIntelRecord(ip=item.ip))
                if item.country: base.country = item.country
                if item.asn: base.asn = item.asn
                if item.org: base.org = item.org
                if item.reputation_score is not None:
                    base.reputation_score = item.reputation_score
                    base.flagged = item.flagged
                merged[item.ip] = base
        result.ips = list(merged.values())
        result.ip_whois = [w for w in wh_r if w]

        await _p("port_scan", 72, f"Port scanning {len(live)} hosts")
        port_scan_targets = live[:10]  # cap to avoid excessive scans
        port_results = await asyncio.gather(
            *[self._safe(self.ports.scan_host(h), default=[]) for h in port_scan_targets]
        )
        for services in port_results:
            if services:
                result.services.extend(services)

        await _p("passive_dns", 78, "Passive DNS (OTX)")
        result.passive_dns = await self._safe(self.passive_dns.lookup(req.target), default=[])

        await _p("reputation", 85, "VirusTotal reputation")
        result.reputation = await self._safe(self.vt.lookup_domain(req.target))

        if not req.skip_dorking:
            await _p("dorking", 92, "Google dorking")
            result.dorking = await self._safe(
                self.dorker.run(req.target, custom_queries=req.dork_queries or None, use_defaults=True),
                default=[],
            )

        await _p("risk", 98, "Computing risk score")
        result.risk = compute_risk(result)

        await _p("done", 100, "Complete")
        return result

    @staticmethod
    async def _safe(coro, default=None):
        try:
            return await coro
        except Exception:
            return default

    @staticmethod
    async def _noop():
        return None
