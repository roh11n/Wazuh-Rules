"""AbuseIPDB adapter."""
import httpx
from osint.config import settings
from osint.models import IPIntelRecord


class AbuseIPDBAdapter:
    async def lookup(self, ip: str) -> IPIntelRecord | None:
        if not settings.abuseipdb_key:
            return IPIntelRecord(ip=ip)
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": settings.abuseipdb_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout, headers=headers) as client:
                resp = await client.get(url, params=params)
                if resp.status_code != 200:
                    return IPIntelRecord(ip=ip)
                d = resp.json().get("data", {})
        except Exception:
            return IPIntelRecord(ip=ip)

        score = d.get("abuseConfidenceScore", 0) or 0
        return IPIntelRecord(
            ip=ip,
            country=d.get("countryCode"),
            asn=f"AS{d.get('asn')}" if d.get("asn") else None,
            org=d.get("isp"),
            reputation_score=score,
            flagged=score >= 50,
        )
