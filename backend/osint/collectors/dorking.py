"""Google dorking via best-effort scraping."""
import asyncio
import random
import httpx
from bs4 import BeautifulSoup
from osint.config import settings
from osint.models import DorkEntry, DorkResult


class GoogleDorker:
    SEARCH_URL = "https://www.google.com/search"

    def __init__(self, delay_range: tuple[float, float] = (2.0, 4.0)):
        self.delay_range = delay_range

    async def run(
        self,
        target: str,
        custom_queries: list[str] | None = None,
        use_defaults: bool = True,
        max_results_per_query: int = 10,
    ) -> list[DorkResult]:
        queries: list[str] = []
        if use_defaults:
            for tmpl in settings.default_dork_templates:
                queries.append(tmpl.replace("{target}", target))
        if custom_queries:
            for q in custom_queries:
                queries.append(q.replace("{target}", target))

        seen: set[str] = set()
        unique = []
        for q in queries:
            if q not in seen:
                seen.add(q)
                unique.append(q)

        results: list[DorkResult] = []
        for query in unique:
            entries = await self._scrape(query, max_results_per_query)
            results.append(DorkResult(query=query, results=entries))
            await asyncio.sleep(random.uniform(*self.delay_range))
        return results

    async def _scrape(self, query: str, num: int) -> list[DorkEntry]:
        params = {"q": query, "num": num, "hl": "en"}
        headers = {
            "User-Agent": settings.browser_ua,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.google.com/",
        }
        try:
            async with httpx.AsyncClient(
                timeout=15, headers=headers, follow_redirects=True
            ) as client:
                resp = await client.get(self.SEARCH_URL, params=params)
                if resp.status_code != 200:
                    return []
                return self._parse(resp.text)
        except Exception:
            return []

    @staticmethod
    def _parse(html: str) -> list[DorkEntry]:
        soup = BeautifulSoup(html, "html.parser")
        results: list[DorkEntry] = []
        for g in soup.find_all("div", class_="g"):
            anchor = g.find("a", href=True)
            h3 = g.find("h3")
            if not anchor or not h3:
                continue
            href = anchor.get("href", "")
            if not href.startswith("http"):
                continue
            title = h3.get_text(strip=True)
            snippet = ""
            for sel in ["div.VwiC3b", "span.st", "div[data-sncf]", "div.IsZvec"]:
                el = g.select_one(sel)
                if el:
                    snippet = el.get_text(strip=True)
                    break
            if not snippet:
                full = g.get_text(" ", strip=True)
                snippet = full.replace(title, "").strip()[:300]
            results.append(DorkEntry(title=title, url=href, snippet=snippet[:500]))
        return results
