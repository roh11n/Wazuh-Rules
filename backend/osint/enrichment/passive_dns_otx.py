"""Passive DNS via OTX."""
import httpx
from osint.config import settings
from osint.models import PassiveDNSRecord


class PassiveDNSOTX:
    BASE = "https://otx.alienvault.com/api/v1"

    async def lookup(self, domain: str) -> list[PassiveDNSRecord]:
        url = f"{self.BASE}/indicators/domain/{domain}/passive_dns"
        headers = {"User-Agent": settings.user_agent}
        if settings.otx_key:
            headers["X-OTX-API-KEY"] = settings.otx_key
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout, headers=headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return []
                data = resp.json()
        except Exception:
            return []

        out: list[PassiveDNSRecord] = []
        seen: set = set()
        for e in data.get("passive_dns", []):
            hn = e.get("hostname", "")
            addr = e.get("address", "")
            rtype = e.get("record_type", "")
            key = (hn, addr, rtype)
            if key in seen:
                continue
            seen.add(key)
            out.append(PassiveDNSRecord(
                hostname=hn,
                ip=addr or None,
                record_type=rtype or None,
                asn=e.get("asn"),
                first_seen=e.get("first"),
                last_seen=e.get("last"),
                source="otx",
            ))
        return out
