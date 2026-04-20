"""TLS certificate inspector."""
import asyncio
import ssl
import socket
from datetime import datetime
from osint.models import TLSCertInfo


class TLSCertCollector:
    async def collect(self, host: str, port: int = 443) -> TLSCertInfo | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._fetch, host, port)

    def _fetch(self, host: str, port: int) -> TLSCertInfo | None:
        cert = self._try_parsed(host, port)
        if cert and not cert.get("_binary"):
            return self._build(cert, host)
        return self._binary_fallback(host, port)

    def _try_parsed(self, host: str, port: int) -> dict | None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    return ss.getpeercert()
        except ssl.SSLCertVerificationError:
            return {"_binary": True}
        except Exception:
            return None

    def _binary_fallback(self, host: str, port: int) -> TLSCertInfo | None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    binary = ss.getpeercert(binary_form=True)
                    if binary:
                        return TLSCertInfo(host=host, self_signed=True)
            return None
        except Exception:
            return None

    def _build(self, cert: dict, host: str) -> TLSCertInfo:
        subject = self._flatten(cert.get("subject", ()))
        issuer = self._flatten(cert.get("issuer", ()))
        sans = [v for _, v in cert.get("subjectAltName", ())]

        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        expired = False
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expired = exp < datetime.utcnow()
            except Exception:
                pass

        return TLSCertInfo(
            host=host,
            subject=subject,
            issuer=issuer,
            sans=sans,
            serial_number=cert.get("serialNumber"),
            not_before=not_before,
            not_after=not_after,
            version=cert.get("version"),
            expired=expired,
            self_signed=(subject == issuer),
        )

    @staticmethod
    def _flatten(tuples) -> dict[str, str]:
        out: dict[str, str] = {}
        for group in tuples:
            for k, v in group:
                out[k] = v
        return out
