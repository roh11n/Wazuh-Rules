"""Shodan search adapter — search Shodan by query (e.g. 'apache country:US')."""
import httpx
from osint.config import settings
from osint.models import ShodanSearchHit, ShodanSearchResult


class ShodanSearcher:
    BASE = "https://api.shodan.io"

    async def search(self, query: str, limit: int = 50) -> ShodanSearchResult | None:
        if not settings.shodan_key:
            return None
        url = f"{self.BASE}/shodan/host/search"
        params = {"key": settings.shodan_key, "query": query, "limit": limit}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, params=params)
                if resp.status_code != 200:
                    return ShodanSearchResult(query=query, total=0, hits=[], error=f"HTTP {resp.status_code}: {resp.text[:200]}")
                data = resp.json()
        except Exception as e:
            return ShodanSearchResult(query=query, total=0, hits=[], error=str(e)[:200])

        hits: list[ShodanSearchHit] = []
        for item in data.get("matches", [])[:limit]:
            hits.append(ShodanSearchHit(
                ip=item.get("ip_str", ""),
                port=item.get("port"),
                transport=item.get("transport", "tcp"),
                product=item.get("product"),
                version=item.get("version"),
                org=item.get("org"),
                isp=item.get("isp"),
                asn=item.get("asn"),
                country_code=item.get("location", {}).get("country_code"),
                country_name=item.get("location", {}).get("country_name"),
                city=item.get("location", {}).get("city"),
                hostnames=item.get("hostnames", []),
                domains=item.get("domains", []),
                timestamp=item.get("timestamp"),
                banner=(item.get("data") or "").strip()[:400] or None,
                ssl_cert_issuer=self._ssl_issuer(item),
            ))

        return ShodanSearchResult(
            query=query,
            total=data.get("total", 0),
            hits=hits,
        )

    @staticmethod
    def _ssl_issuer(item: dict) -> str | None:
        ssl = item.get("ssl") or {}
        cert = ssl.get("cert") or {}
        issuer = cert.get("issuer") or {}
        return issuer.get("CN") or issuer.get("O")
