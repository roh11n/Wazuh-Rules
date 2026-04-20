"""Directory / path enumeration on live hosts — checks common sensitive paths."""
import asyncio
import httpx
from osint.config import settings
from osint.models import DirectoryEntry

COMMON_PATHS: list[str] = [
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/config", "/.git/HEAD",
    "/admin", "/admin/", "/administrator", "/login", "/signin",
    "/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-json/",
    "/phpmyadmin/", "/phpinfo.php", "/server-status", "/server-info",
    "/api", "/api/", "/api/v1", "/graphql", "/swagger", "/swagger-ui",
    "/docs", "/api-docs", "/.DS_Store", "/config.json", "/config.yml",
    "/backup", "/backup.zip", "/backup.sql", "/dump.sql",
    "/.htaccess", "/web.config", "/crossdomain.xml",
    "/readme.md", "/README.md", "/CHANGELOG.md",
    "/cpanel", "/webmail", "/ftp", "/phpinfo",
    "/.well-known/security.txt", "/.well-known/change-password",
]


class DirectoryEnumerator:
    def __init__(self, concurrency: int = 20, timeout: int = 5):
        self._sem = asyncio.Semaphore(concurrency)
        self.timeout = timeout

    async def enumerate(self, base_url: str) -> list[DirectoryEntry]:
        base_url = base_url.rstrip("/")
        async with httpx.AsyncClient(
            timeout=self.timeout,
            headers={"User-Agent": settings.browser_ua},
            follow_redirects=False,
            verify=False,
        ) as client:
            tasks = [self._probe(client, base_url, p) for p in COMMON_PATHS]
            results = await asyncio.gather(*tasks)
        return [r for r in results if r]

    async def _probe(self, client: httpx.AsyncClient, base_url: str, path: str) -> DirectoryEntry | None:
        async with self._sem:
            url = f"{base_url}{path}"
            try:
                resp = await client.get(url)
            except Exception:
                return None

            code = resp.status_code
            # Consider path "interesting" if 200/301/302/401/403
            if code not in (200, 201, 301, 302, 401, 403):
                return None

            # Skip obvious soft-404s (many sites return 200 on any path)
            if code == 200:
                body = resp.text[:2000].lower()
                if "not found" in body or "404" in body[:400]:
                    return None

            return DirectoryEntry(
                path=path,
                url=url,
                status_code=code,
                content_length=int(resp.headers.get("content-length", "0") or "0"),
                content_type=resp.headers.get("content-type", "").split(";")[0] or None,
                title=None,
            )
