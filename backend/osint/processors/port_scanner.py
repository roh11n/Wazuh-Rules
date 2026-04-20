"""Async TCP connect port scanner + banner grab. No root required."""
import asyncio
from osint.models import ServiceRecord

COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https",
    445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}


class PortScanner:
    def __init__(self, timeout: float = 1.5, concurrency: int = 50):
        self.timeout = timeout
        self._sem = asyncio.Semaphore(concurrency)

    async def scan_host(self, host: str) -> list[ServiceRecord]:
        tasks = [self._probe(host, p, svc) for p, svc in COMMON_PORTS.items()]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r]

    async def _probe(self, host: str, port: int, svc: str) -> ServiceRecord | None:
        async with self._sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=self.timeout
                )
            except Exception:
                return None

            banner: str | None = None
            try:
                if port in (80, 8080, 443, 8443):
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(256), timeout=1.0)
                    if data:
                        banner = data.decode("utf-8", errors="replace").strip().split("\n")[0][:120]
                except Exception:
                    pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

            return ServiceRecord(
                host=host,
                port=port,
                service=svc,
                protocol="tcp",
                banner=banner,
                authorized_scan=True,
            )
