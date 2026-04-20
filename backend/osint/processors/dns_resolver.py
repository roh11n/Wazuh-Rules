"""Simple A record resolver for subdomains."""
import asyncio
import dns.resolver
from osint.models import DNSRecord


class DNSResolver:
    def __init__(self):
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = 5
        self._resolver.lifetime = 8

    async def resolve_a(self, host: str) -> list[DNSRecord]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sync, host)

    def _sync(self, host: str) -> list[DNSRecord]:
        try:
            ans = self._resolver.resolve(host, "A")
            return [DNSRecord(subdomain=host, ip=str(r)) for r in ans]
        except Exception:
            return []
