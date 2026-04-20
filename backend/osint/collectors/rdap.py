"""RDAP collector."""
import httpx
from osint.config import settings
from osint.models import DomainInfo


class RDAPCollector:
    async def collect(self, target: str) -> DomainInfo:
        url = f"https://rdap.org/domain/{target}"
        headers = {"User-Agent": settings.user_agent}
        async with httpx.AsyncClient(
            timeout=settings.request_timeout, headers=headers, follow_redirects=True
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()

        registrar = None
        registrant = None
        abuse_email = None
        statuses = data.get("status", [])

        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            handle = ent.get("handle", "")
            vcard = ent.get("vcardArray", [None, []])
            vcard_fields = vcard[1] if len(vcard) > 1 else []

            if "registrar" in roles:
                for field in vcard_fields:
                    if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                        registrar = field[3]
                        break
                if not registrar:
                    registrar = handle

            if "registrant" in roles:
                for field in vcard_fields:
                    if isinstance(field, list) and len(field) >= 4:
                        if field[0] == "fn":
                            registrant = field[3]
                        elif field[0] == "org":
                            registrant = field[3]
                if not registrant:
                    registrant = handle

            if "abuse" in roles:
                for field in vcard_fields:
                    if isinstance(field, list) and len(field) >= 4 and field[0] == "email":
                        abuse_email = field[3]

            if not abuse_email:
                for field in vcard_fields:
                    if isinstance(field, list) and len(field) >= 4 and field[0] == "email":
                        abuse_email = field[3]

        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}

        dnssec = None
        secure_dns = data.get("secureDNS")
        if isinstance(secure_dns, dict):
            dnssec = bool(secure_dns.get("delegationSigned"))

        return DomainInfo(
            domain=target,
            registrar=registrar,
            registrant=registrant,
            registration_date=events.get("registration"),
            expiry_date=events.get("expiration"),
            statuses=statuses,
            abuse_email=abuse_email,
            dnssec=dnssec,
        )
