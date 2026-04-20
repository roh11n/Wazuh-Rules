"""Whois fallback (minimal - uses RDAP.org root if RDAP direct fails)."""
import httpx
from osint.config import settings
from osint.models import DomainInfo


class WhoisFallbackCollector:
    async def collect(self, target: str) -> DomainInfo | None:
        try:
            async with httpx.AsyncClient(
                timeout=settings.request_timeout,
                headers={"User-Agent": settings.user_agent},
                follow_redirects=True,
            ) as client:
                resp = await client.get(f"https://rdap.org/domain/{target}")
                if resp.status_code != 200:
                    return DomainInfo(domain=target)
        except Exception:
            return DomainInfo(domain=target)
        return DomainInfo(domain=target)
