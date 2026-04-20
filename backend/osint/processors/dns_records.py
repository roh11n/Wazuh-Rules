"""Full DNS records resolver."""
import asyncio
import dns.resolver
from osint.models import DNSRecordSet, MXRecord


class DNSRecordCollector:
    def __init__(self, nameservers: list[str] | None = None):
        self._resolver = dns.resolver.Resolver()
        if nameservers:
            self._resolver.nameservers = nameservers
        self._resolver.timeout = 8
        self._resolver.lifetime = 12

    async def collect(self, domain: str) -> DNSRecordSet:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sync, domain)

    def _sync(self, domain: str) -> DNSRecordSet:
        rec = DNSRecordSet(domain=domain)
        rec.a = self._resolve(domain, "A")
        rec.aaaa = self._resolve(domain, "AAAA")

        try:
            for rdata in self._resolver.resolve(domain, "MX"):
                rec.mx.append(
                    MXRecord(priority=rdata.preference, exchange=str(rdata.exchange).rstrip("."))
                )
            rec.mx.sort(key=lambda m: m.priority)
        except Exception:
            pass

        rec.ns = self._resolve(domain, "NS")

        try:
            for rdata in self._resolver.resolve(domain, "TXT"):
                txt = rdata.to_text().strip('"')
                rec.txt.append(txt)
                if txt.lower().startswith("v=spf1"):
                    rec.spf = txt
        except Exception:
            pass

        try:
            for rdata in self._resolver.resolve(f"_dmarc.{domain}", "TXT"):
                txt = rdata.to_text().strip('"')
                if "v=dmarc1" in txt.lower():
                    rec.dmarc = txt
        except Exception:
            pass

        try:
            for rdata in self._resolver.resolve(domain, "SOA"):
                rec.soa = {
                    "mname": str(rdata.mname).rstrip("."),
                    "rname": str(rdata.rname).rstrip("."),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "retry": rdata.retry,
                    "expire": rdata.expire,
                    "minimum": rdata.minimum,
                }
                break
        except Exception:
            pass

        rec.cname = self._resolve(domain, "CNAME")
        return rec

    def _resolve(self, name: str, rdtype: str) -> list[str]:
        try:
            return [str(r).rstrip(".") for r in self._resolver.resolve(name, rdtype)]
        except Exception:
            return []
