"""NVD CVE enrichment with Mongo-backed cache.
Uses NVD REST 2.0 — no API key needed, but rate-limited.
"""
import asyncio
import httpx
from datetime import datetime, timezone
from osint.config import settings
from osint.models import CVEDetail

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDAdapter:
    """Looks up CVE details. Must be initialized with mongo db for caching."""

    def __init__(self, db=None):
        self._db = db
        self._sem = asyncio.Semaphore(3)  # NVD rate-limits hard

    async def enrich(self, cve_ids: list[str]) -> list[CVEDetail]:
        if not cve_ids:
            return []
        unique = sorted(set(cve_ids))
        tasks = [self._lookup_one(c) for c in unique]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r]

    async def _lookup_one(self, cve_id: str) -> CVEDetail | None:
        if self._db is not None:
            cached = await self._db.cve_cache.find_one({"_id": cve_id}, {"_id": 0})
            if cached:
                return CVEDetail(**cached)

        async with self._sem:
            try:
                async with httpx.AsyncClient(
                    timeout=15, headers={"User-Agent": settings.user_agent}
                ) as client:
                    resp = await client.get(BASE, params={"cveId": cve_id})
                    if resp.status_code != 200:
                        return None
                    data = resp.json()
            except Exception:
                return None

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            cve = vulns[0].get("cve", {})

            detail = self._parse(cve_id, cve)
            if self._db is not None and detail:
                try:
                    await self._db.cve_cache.update_one(
                        {"_id": cve_id},
                        {"$set": {**detail.model_dump(), "cached_at": datetime.now(timezone.utc).isoformat()}},
                        upsert=True,
                    )
                except Exception:
                    pass
            return detail

    @staticmethod
    def _parse(cve_id: str, cve: dict) -> CVEDetail | None:
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        metrics = cve.get("metrics", {})
        score = None
        severity = None
        vector = None
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(k, [])
            if arr:
                m = arr[0].get("cvssData", {})
                score = m.get("baseScore")
                severity = (m.get("baseSeverity")
                            or arr[0].get("baseSeverity")
                            or _severity_from_score(score))
                vector = m.get("vectorString")
                break
        if severity is None and score is not None:
            severity = _severity_from_score(score)

        refs = [r.get("url") for r in cve.get("references", []) if r.get("url")][:5]

        return CVEDetail(
            cve_id=cve_id,
            description=(desc or "")[:600],
            cvss_score=score,
            severity=severity,
            vector=vector,
            published=cve.get("published"),
            last_modified=cve.get("lastModified"),
            references=refs,
            nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        )


def _severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0: return "LOW"
    return "NONE"
