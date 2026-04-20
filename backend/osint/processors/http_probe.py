"""HTTP probe for live hosts."""
import httpx
from bs4 import BeautifulSoup
from osint.config import settings
from osint.models import LiveHostRecord


class HTTPProbe:
    async def probe(self, host: str) -> list[LiveHostRecord]:
        records: list[LiveHostRecord] = []
        headers = {"User-Agent": settings.browser_ua}
        async with httpx.AsyncClient(
            timeout=10, headers=headers, follow_redirects=True, verify=False
        ) as client:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                try:
                    resp = await client.get(url)
                except Exception:
                    continue

                title = None
                try:
                    soup = BeautifulSoup(resp.text[:200_000], "html.parser")
                    t = soup.find("title")
                    if t:
                        title = t.get_text(strip=True)[:200]
                except Exception:
                    pass

                records.append(
                    LiveHostRecord(
                        host=host,
                        url=str(resp.url),
                        status_code=resp.status_code,
                        title=title,
                        server=resp.headers.get("server"),
                    )
                )
                break
        return records
