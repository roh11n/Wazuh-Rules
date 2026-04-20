"""IPInfo.io adapter."""
import httpx
from osint.config import settings
from osint.models import IPIntelRecord


class IPInfoAdapter:
    async def lookup(self, ip: str) -> IPIntelRecord | None:
        url = f"https://ipinfo.io/{ip}/json"
        headers = {"User-Agent": settings.user_agent}
        if settings.ipinfo_token:
            headers["Authorization"] = f"Bearer {settings.ipinfo_token}"
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout, headers=headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return IPIntelRecord(ip=ip)
                data = resp.json()
        except Exception:
            return IPIntelRecord(ip=ip)

        org_full = data.get("org", "")
        asn = None
        org = org_full
        if org_full.startswith("AS"):
            parts = org_full.split(" ", 1)
            asn = parts[0]
            org = parts[1] if len(parts) > 1 else None

        return IPIntelRecord(
            ip=ip,
            country=data.get("country"),
            region=data.get("region"),
            city=data.get("city"),
            asn=asn,
            org=org,
        )
