"""Shodan adapter — IP open ports, banners, vulnerabilities via /shodan/host/{ip}."""
import httpx
from osint.config import settings
from osint.models import ShodanHostInfo, ShodanService


class ShodanAdapter:
    BASE = "https://api.shodan.io"

    async def lookup(self, ip: str) -> ShodanHostInfo | None:
        if not settings.shodan_key:
            return None
        url = f"{self.BASE}/shodan/host/{ip}"
        params = {"key": settings.shodan_key, "minify": "false"}
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(url, params=params)
                if resp.status_code == 404:
                    return ShodanHostInfo(ip=ip, found=False)
                if resp.status_code != 200:
                    return None
                d = resp.json()
        except Exception:
            return None

        services: list[ShodanService] = []
        for item in d.get("data", []):
            product = item.get("product") or ""
            version = item.get("version") or ""
            transport = item.get("transport", "tcp")
            banner = (item.get("data") or "").strip()[:500]
            port = item.get("port")
            services.append(ShodanService(
                port=port,
                transport=transport,
                product=product or None,
                version=version or None,
                banner=banner or None,
                ssl_cert_issuer=self._extract_ssl_issuer(item),
                hostnames=item.get("hostnames", []),
                cpe=item.get("cpe23", []) or item.get("cpe", []),
            ))

        return ShodanHostInfo(
            ip=ip,
            found=True,
            country_name=d.get("country_name"),
            city=d.get("city"),
            org=d.get("org"),
            isp=d.get("isp"),
            asn=d.get("asn"),
            os=d.get("os"),
            hostnames=d.get("hostnames", []),
            domains=d.get("domains", []),
            ports=d.get("ports", []),
            vulns=list(d.get("vulns", []) or []),
            tags=d.get("tags", []),
            last_update=d.get("last_update"),
            services=services,
        )

    @staticmethod
    def _extract_ssl_issuer(item: dict) -> str | None:
        ssl = item.get("ssl") or {}
        cert = ssl.get("cert") or {}
        issuer = cert.get("issuer") or {}
        return issuer.get("CN") or issuer.get("O")
