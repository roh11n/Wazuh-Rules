"""Technology fingerprinting."""
import base64
import re
import httpx
from bs4 import BeautifulSoup

try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False

from osint.config import settings
from osint.models import TechFingerprint

COOKIE_SIGS = {
    "PHPSESSID": "PHP", "JSESSIONID": "Java", "ASP.NET_SessionId": "ASP.NET",
    "csrftoken": "Django", "django_language": "Django", "laravel_session": "Laravel",
    "connect.sid": "Express.js", "XSRF-TOKEN": "Angular / Laravel",
    "wordpress_logged_in": "WordPress", "wp-settings": "WordPress",
    "AWSALB": "AWS ALB", "_gh_sess": "GitHub",
}

HEADER_SIGS = {
    "cf-ray": "Cloudflare", "cf-cache-status": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront", "x-fastly-request-id": "Fastly",
    "x-akamai-transformed": "Akamai", "x-varnish": "Varnish",
    "x-drupal-cache": "Drupal", "x-shopify-stage": "Shopify",
    "x-wix-request-id": "Wix", "x-litespeed-cache": "LiteSpeed",
}

JS_PATTERNS = [
    (r"jquery[\.\-/]", "jQuery"), (r"react[\.\-/]|react\.production", "React"),
    (r"angular[\.\-/]|ng\-app", "Angular"), (r"vue[\.\-/]|Vue\.js", "Vue.js"),
    (r"bootstrap[\.\-/]", "Bootstrap"), (r"tailwindcss|tailwind", "Tailwind CSS"),
    (r"next[\.\-/]|_next/", "Next.js"), (r"nuxt", "Nuxt.js"),
    (r"lodash", "Lodash"), (r"moment[\.\-/]", "Moment.js"),
    (r"gsap", "GSAP"), (r"three\.js|three[\.\-/]", "Three.js"),
    (r"d3[\.\-/]|d3\.js", "D3.js"), (r"chart\.js", "Chart.js"),
    (r"axios", "Axios"), (r"svelte", "Svelte"),
]

HTML_CMS = [
    (r"wp-content|wp-includes", "WordPress"), (r"Drupal\.settings", "Drupal"),
    (r"/media/jui/|com_content", "Joomla"), (r"cdn\.shopify\.com", "Shopify"),
    (r"squarespace\.com", "Squarespace"), (r"static\.wixstatic\.com", "Wix"),
    (r"ghost\.org|ghost\.io", "Ghost"),
]


class TechFingerprintCollector:
    async def fingerprint(self, host: str) -> TechFingerprint:
        result = TechFingerprint(host=host)
        async with httpx.AsyncClient(
            timeout=settings.request_timeout,
            headers={"User-Agent": settings.browser_ua},
            follow_redirects=True,
            verify=False,
        ) as client:
            for scheme in ("https://", "http://"):
                url = f"{scheme}{host}"
                try:
                    resp = await client.get(url)
                except Exception:
                    continue

                result.server = resp.headers.get("server")
                result.powered_by = resp.headers.get("x-powered-by")

                for hdr, tech in HEADER_SIGS.items():
                    if hdr in resp.headers:
                        result.headers_of_interest[hdr] = resp.headers[hdr]
                        if not result.cdn and tech in ("Cloudflare", "AWS CloudFront", "Fastly", "Akamai"):
                            result.cdn = tech
                        elif tech not in result.frameworks:
                            result.frameworks.append(tech)

                for cookie_name in resp.cookies.keys():
                    for sig, tech in COOKIE_SIGS.items():
                        if sig.lower() in cookie_name.lower():
                            result.cookies_detected[cookie_name] = tech
                            if tech not in result.frameworks:
                                result.frameworks.append(tech)

                body = resp.text[:200_000]
                soup = BeautifulSoup(body, "html.parser")

                gen = soup.find("meta", attrs={"name": "generator"})
                if gen:
                    result.meta_generator = gen.get("content", "")

                for pat, lib in JS_PATTERNS:
                    if re.search(pat, body, re.IGNORECASE) and lib not in result.js_libraries:
                        result.js_libraries.append(lib)

                for pat, cms in HTML_CMS:
                    if re.search(pat, body, re.IGNORECASE):
                        result.cms = cms
                        break

                fav_url = self._find_favicon(soup, url)
                if fav_url:
                    fh = await self._hash_favicon(client, fav_url)
                    if fh:
                        result.favicon_hash = fh
                break
        return result

    @staticmethod
    def _find_favicon(soup, base_url):
        link = soup.find("link", rel=lambda v: v and "icon" in " ".join(v).lower())
        if link and link.get("href"):
            href = link["href"]
            if href.startswith("//"):
                return "https:" + href
            if href.startswith("/"):
                return base_url.rstrip("/") + href
            if href.startswith("http"):
                return href
            return base_url.rstrip("/") + "/" + href
        return base_url.rstrip("/") + "/favicon.ico"

    @staticmethod
    async def _hash_favicon(client, url):
        if not HAS_MMH3:
            return None
        try:
            resp = await client.get(url)
            if resp.status_code != 200 or len(resp.content) < 10:
                return None
            b64 = base64.encodebytes(resp.content)
            return str(mmh3.hash(b64))
        except Exception:
            return None
