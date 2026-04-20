"""IP WHOIS via RDAP."""
import httpx
from osint.config import settings
from osint.models import IPWhoisRecord


class IPWhoisCollector:
    async def lookup(self, ip: str) -> IPWhoisRecord:
        url = f"https://rdap.org/ip/{ip}"
        headers = {"User-Agent": settings.user_agent}
        try:
            async with httpx.AsyncClient(
                timeout=settings.request_timeout, headers=headers, follow_redirects=True
            ) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
        except Exception:
            return IPWhoisRecord(ip=ip)

        name = data.get("name")
        country = data.get("country")
        cidr = None
        cidrs = data.get("cidr0_cidrs", [])
        if cidrs:
            c = cidrs[0]
            cidr = f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
        elif data.get("startAddress") and data.get("endAddress"):
            cidr = f"{data['startAddress']} - {data['endAddress']}"

        asn = None
        org = None
        registrant = None
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            handle = ent.get("handle", "")
            if "registrant" in roles:
                registrant = handle
                vcard = ent.get("vcardArray", [None, []])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if isinstance(field, list) and len(field) >= 4:
                            if field[0] == "org":
                                org = field[3]
                            elif field[0] == "fn" and not org:
                                org = field[3]
            if not asn and handle.upper().startswith("AS"):
                asn = handle

        if not org:
            for ent in data.get("entities", []):
                vcard = ent.get("vcardArray", [None, []])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                            org = field[3]
                            break
                if org:
                    break

        return IPWhoisRecord(
            ip=ip, network_name=name, network_cidr=cidr,
            asn=asn, org=org, country=country, registrant=registrant,
        )
