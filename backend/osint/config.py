"""Settings loaded from env + runtime overrides from Mongo settings doc."""
import os

_runtime_overrides: dict = {}


def set_overrides(overrides: dict) -> None:
    global _runtime_overrides
    _runtime_overrides = {k: v for k, v in overrides.items() if v}


def _get(key: str, default: str | None = None) -> str | None:
    return _runtime_overrides.get(key) or os.environ.get(key, default)


class Settings:
    app_name = "osint-pipeline"
    request_timeout = int(os.environ.get("REQUEST_TIMEOUT", "15"))
    user_agent = os.environ.get("USER_AGENT", "authorized-asset-monitor/1.0")
    browser_ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    )
    screenshot_dir = "/app/backend/osint_data/screenshots"

    suspicious_tlds = {
        "zip", "mov", "click", "top", "xyz", "gq", "tk", "ml", "work",
    }

    default_dork_templates = [
        'site:{target}',
        'site:{target} filetype:pdf',
        'site:{target} filetype:doc OR filetype:docx',
        'site:{target} inurl:login',
        'site:{target} inurl:admin',
        'site:{target} intitle:"index of"',
        '"{target}" password OR credentials',
        'site:{target} ext:env OR ext:yml',
        'site:{target} ext:sql OR ext:bak OR ext:log',
    ]

    @property
    def ipinfo_token(self) -> str | None:
        return _get("IPINFO_TOKEN")

    @property
    def abuseipdb_key(self) -> str | None:
        return _get("ABUSEIPDB_KEY")

    @property
    def virustotal_key(self) -> str | None:
        return _get("VIRUSTOTAL_KEY")

    @property
    def otx_key(self) -> str | None:
        return _get("OTX_KEY")

    @property
    def discord_webhook(self) -> str | None:
        return _get("DISCORD_WEBHOOK")


settings = Settings()
