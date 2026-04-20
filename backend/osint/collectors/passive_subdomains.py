"""Passive subdomain enumeration from multiple sources (crt.sh, OTX, HackerTarget)."""
import asyncio
import httpx
from osint.config import settings
from osint.models import SubdomainRecord


class PassiveSubdomainCollector:
    async def collect(self, target: str) -> list[SubdomainRecord]:
        results = await asyncio.gather(
            self._crtsh(target),
            self._otx(target),
            self._hackertarget(target),
            return_exceptions=True,
        )

        merged: dict[str, SubdomainRecord] = {}
        for r in results:
            if isinstance(r, list):
                for rec in r:
                    if rec.subdomain not in merged:
                        merged[rec.subdomain] = rec

        return sorted(merged.values(), key=lambda r: r.subdomain)

    async def _crtsh(self, target: str) -> list[SubdomainRecord]:
        try:
            async with httpx.AsyncClient(
                timeout=30, headers={"User-Agent": settings.user_agent}
            ) as client:
                resp = await client.get(
                    "https://crt.sh/",
                    params={"q": f"%.{target}", "output": "json"},
                )
                if resp.status_code != 200:
                    return []
                data = resp.json()
        except Exception:
            return []

        out: dict[str, SubdomainRecord] = {}
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if not name or not name.endswith(target.lower()):
                    continue
                if name not in out:
                    out[name] = SubdomainRecord(subdomain=name, source="crt.sh")
        return list(out.values())

    async def _otx(self, target: str) -> list[SubdomainRecord]:
        try:
            headers = {"User-Agent": settings.user_agent}
            if settings.otx_key:
                headers["X-OTX-API-KEY"] = settings.otx_key
            async with httpx.AsyncClient(timeout=20, headers=headers) as client:
                resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
                )
                if resp.status_code != 200:
                    return []
                data = resp.json()
        except Exception:
            return []

        out: dict[str, SubdomainRecord] = {}
        for r in data.get("passive_dns", []):
            name = (r.get("hostname") or "").strip().lower()
            if not name or not name.endswith(target.lower()):
                continue
            if name not in out:
                out[name] = SubdomainRecord(subdomain=name, source="otx")
        return list(out.values())

    async def _hackertarget(self, target: str) -> list[SubdomainRecord]:
        try:
            async with httpx.AsyncClient(
                timeout=20, headers={"User-Agent": settings.user_agent}
            ) as client:
                resp = await client.get(
                    f"https://api.hackertarget.com/hostsearch/?q={target}"
                )
                if resp.status_code != 200:
                    return []
                text = resp.text
        except Exception:
            return []

        if "error" in text.lower() or "api count exceeded" in text.lower():
            return []

        out: dict[str, SubdomainRecord] = {}
        for line in text.splitlines():
            name = line.split(",")[0].strip().lower()
            if not name or not name.endswith(target.lower()):
                continue
            if name not in out:
                out[name] = SubdomainRecord(subdomain=name, source="hackertarget")
        return list(out.values())
