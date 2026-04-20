"""Pydantic models for OSINT data."""
from pydantic import BaseModel, Field
from typing import Any
from datetime import datetime, timezone


class ScanRequest(BaseModel):
    target: str
    mode: str = "domain"  # domain | website | ip | dork
    dork_queries: list[str] = Field(default_factory=list)
    skip_screenshots: bool = False
    skip_dorking: bool = False
    skip_directories: bool = False
    skip_ports: bool = False


class DomainInfo(BaseModel):
    domain: str
    registrar: str | None = None
    registrant: str | None = None
    registration_date: str | None = None
    expiry_date: str | None = None
    statuses: list[str] = Field(default_factory=list)
    abuse_email: str | None = None
    dnssec: bool | None = None


class MXRecord(BaseModel):
    priority: int
    exchange: str


class DNSRecordSet(BaseModel):
    domain: str
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    mx: list[MXRecord] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)
    soa: dict[str, Any] | None = None
    spf: str | None = None
    dmarc: str | None = None


class TLSCertInfo(BaseModel):
    host: str
    subject: dict[str, str] = Field(default_factory=dict)
    issuer: dict[str, str] = Field(default_factory=dict)
    sans: list[str] = Field(default_factory=list)
    serial_number: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    version: int | None = None
    expired: bool = False
    self_signed: bool = False


class IPWhoisRecord(BaseModel):
    ip: str
    network_name: str | None = None
    network_cidr: str | None = None
    asn: str | None = None
    org: str | None = None
    country: str | None = None
    registrant: str | None = None


class PassiveDNSRecord(BaseModel):
    hostname: str
    ip: str | None = None
    record_type: str | None = None
    asn: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    source: str = "otx"


class TechFingerprint(BaseModel):
    host: str
    server: str | None = None
    powered_by: str | None = None
    meta_generator: str | None = None
    favicon_hash: str | None = None
    cdn: str | None = None
    frameworks: list[str] = Field(default_factory=list)
    js_libraries: list[str] = Field(default_factory=list)
    cookies_detected: dict[str, str] = Field(default_factory=dict)
    headers_of_interest: dict[str, str] = Field(default_factory=dict)
    cms: str | None = None


class ScreenshotRecord(BaseModel):
    host: str
    url: str
    path: str | None = None
    base64_data: str | None = None


class DorkEntry(BaseModel):
    title: str
    url: str
    snippet: str | None = None


class DorkResult(BaseModel):
    query: str
    results: list[DorkEntry] = Field(default_factory=list)


class SubdomainRecord(BaseModel):
    subdomain: str
    source: str | None = None


class DNSRecord(BaseModel):
    subdomain: str
    ip: str


class LiveHostRecord(BaseModel):
    host: str
    url: str
    status_code: int | None = None
    title: str | None = None
    server: str | None = None
    tech: list[str] = Field(default_factory=list)


class IPIntelRecord(BaseModel):
    ip: str
    country: str | None = None
    region: str | None = None
    city: str | None = None
    asn: str | None = None
    org: str | None = None
    reputation_score: int | None = None
    flagged: bool = False


class ReputationRecord(BaseModel):
    target: str
    malicious_score: int | None = None
    detected_engines: int | None = None


class ServiceRecord(BaseModel):
    host: str
    port: int
    service: str | None = None
    protocol: str = "tcp"
    banner: str | None = None
    authorized_scan: bool = False


class DirectoryEntry(BaseModel):
    path: str
    url: str
    status_code: int
    content_length: int = 0
    content_type: str | None = None
    title: str | None = None


class DirectoryEnumResult(BaseModel):
    host: str
    base_url: str
    entries: list[DirectoryEntry] = Field(default_factory=list)


class ShodanService(BaseModel):
    port: int
    transport: str = "tcp"
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    ssl_cert_issuer: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    cpe: list[str] = Field(default_factory=list)


class ShodanHostInfo(BaseModel):
    ip: str
    found: bool = False
    country_name: str | None = None
    city: str | None = None
    org: str | None = None
    isp: str | None = None
    asn: str | None = None
    os: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    last_update: str | None = None
    services: list[ShodanService] = Field(default_factory=list)


class CVEDetail(BaseModel):
    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    severity: str | None = None  # CRITICAL | HIGH | MEDIUM | LOW | NONE
    vector: str | None = None
    published: str | None = None
    last_modified: str | None = None
    references: list[str] = Field(default_factory=list)
    nvd_url: str | None = None


class ShodanSearchHit(BaseModel):
    ip: str
    port: int | None = None
    transport: str = "tcp"
    product: str | None = None
    version: str | None = None
    org: str | None = None
    isp: str | None = None
    asn: str | None = None
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    timestamp: str | None = None
    banner: str | None = None
    ssl_cert_issuer: str | None = None


class ShodanSearchResult(BaseModel):
    query: str
    total: int = 0
    hits: list[ShodanSearchHit] = Field(default_factory=list)
    error: str | None = None


class RiskScore(BaseModel):
    risk_score: int
    severity: str
    reasons: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    target: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    domain: DomainInfo | None = None
    dns_records: DNSRecordSet | None = None
    subdomains: list[SubdomainRecord] = Field(default_factory=list)
    dns: list[DNSRecord] = Field(default_factory=list)
    live_hosts: list[LiveHostRecord] = Field(default_factory=list)
    tls_certs: list[TLSCertInfo] = Field(default_factory=list)
    ips: list[IPIntelRecord] = Field(default_factory=list)
    ip_whois: list[IPWhoisRecord] = Field(default_factory=list)
    passive_dns: list[PassiveDNSRecord] = Field(default_factory=list)
    reputation: ReputationRecord | None = None
    tech_fingerprints: list[TechFingerprint] = Field(default_factory=list)
    screenshots: list[ScreenshotRecord] = Field(default_factory=list)
    dorking: list[DorkResult] = Field(default_factory=list)
    services: list[ServiceRecord] = Field(default_factory=list)
    directories: list[DirectoryEnumResult] = Field(default_factory=list)
    shodan: list[ShodanHostInfo] = Field(default_factory=list)
    cves: list[CVEDetail] = Field(default_factory=list)
    shodan_search: ShodanSearchResult | None = None
    risk: RiskScore | None = None
