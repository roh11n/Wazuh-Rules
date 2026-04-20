"""Screenshot capture via Playwright."""
import base64
from pathlib import Path
from osint.config import settings
from osint.models import ScreenshotRecord

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


class ScreenshotService:
    def __init__(self, out_dir: str | None = None):
        self.out_dir = Path(out_dir or settings.screenshot_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    async def capture(self, host: str) -> ScreenshotRecord | None:
        if not HAS_PLAYWRIGHT:
            return None

        url = f"https://{host}"
        filename = host.replace(".", "_").replace(":", "_") + ".png"
        filepath = self.out_dir / filename

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
                )
                ctx = await browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    ignore_https_errors=True,
                    user_agent=settings.browser_ua,
                )
                page = await ctx.new_page()
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=20_000)
                except Exception:
                    url = f"http://{host}"
                    try:
                        await page.goto(url, wait_until="domcontentloaded", timeout=20_000)
                    except Exception:
                        await browser.close()
                        return None

                await page.wait_for_timeout(1500)
                data = await page.screenshot(full_page=False)
                await browser.close()

            filepath.write_bytes(data)
            b64 = base64.b64encode(data).decode()
            return ScreenshotRecord(host=host, url=url, path=str(filepath), base64_data=b64)
        except Exception:
            return None
