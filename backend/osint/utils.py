import tldextract


def tld_of(domain: str) -> str:
    try:
        ext = tldextract.extract(domain)
        return (ext.suffix or "").split(".")[-1].lower()
    except Exception:
        return ""


def apex_of(domain: str) -> str:
    ext = tldextract.extract(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return domain
