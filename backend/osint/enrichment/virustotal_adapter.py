"""VirusTotal adapter."""
import httpx
from osint.config import settings
from osint.models import ReputationRecord


class VirusTotalAdapter:
    async def lookup_domain(self, domain: str) -> ReputationRecord | None:
        if not settings.virustotal_key:
            return ReputationRecord(target=domain)
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": settings.virustotal_key}
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout, headers=headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return ReputationRecord(target=domain)
                d = resp.json().get("data", {}).get("attributes", {})
        except Exception:
            return ReputationRecord(target=domain)

        stats = d.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        return ReputationRecord(
            target=domain, malicious_score=malicious, detected_engines=total
        )
