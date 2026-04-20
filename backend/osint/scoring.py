"""Risk scoring engine."""
from datetime import datetime, timezone
from osint.config import settings
from osint.models import ScanResult, RiskScore
from osint.utils import tld_of


def compute_risk(result: ScanResult) -> RiskScore:
    score = 0
    reasons: list[str] = []

    if result.domain and result.domain.registration_date:
        try:
            raw = result.domain.registration_date.replace("Z", "+00:00")
            dt = datetime.fromisoformat(raw)
            age_days = (datetime.now(timezone.utc) - dt).days
            if age_days < 30:
                score += 20
                reasons.append(f"Domain age under 30 days ({age_days}d)")
        except Exception:
            pass

    tld = tld_of(result.target)
    if tld in settings.suspicious_tlds:
        score += 10
        reasons.append(f"Suspicious TLD: .{tld}")

    if result.domain and result.domain.dnssec is False:
        score += 10
        reasons.append("No DNSSEC")

    if result.dns_records and not result.dns_records.spf:
        score += 5
        reasons.append("No SPF record")

    if result.dns_records and not result.dns_records.dmarc:
        score += 10
        reasons.append("No DMARC record")

    if result.dns_records and not result.dns_records.mx:
        score += 5
        reasons.append("No MX records found")

    flagged_ips = [ip for ip in result.ips if ip.flagged]
    if flagged_ips:
        score += 25
        reasons.append(f"{len(flagged_ips)} IP(s) flagged by reputation sources")

    sensitive_ports = {22, 23, 3389, 5900, 445, 1433, 3306, 5432, 6379, 27017, 9200}
    exposed = [s for s in result.services if s.port in sensitive_ports]
    if exposed:
        score += 15
        unique_exposed = sorted({s.port for s in exposed})
        reasons.append(f"Sensitive ports exposed: {', '.join(str(p) for p in unique_exposed)}")

    for cert in result.tls_certs:
        if cert.expired:
            score += 20
            reasons.append(f"Expired TLS certificate on {cert.host}")
            break
    for cert in result.tls_certs:
        if cert.self_signed:
            score += 15
            reasons.append(f"Self-signed certificate on {cert.host}")
            break

    if result.reputation and (result.reputation.malicious_score or 0) > 0:
        add = min(20, result.reputation.malicious_score * 5)
        score += add
        reasons.append(
            f"Domain reputation: {result.reputation.malicious_score} engine(s) flagged"
        )

    unique_passive_ips = {r.ip for r in result.passive_dns if r.ip}
    if len(unique_passive_ips) > 20:
        score += 5
        reasons.append(
            f"High passive DNS IP churn ({len(unique_passive_ips)} unique IPs)"
        )

    if result.domain:
        bad_statuses = {"clientHold", "serverHold", "pendingDelete"}
        found = bad_statuses & set(result.domain.statuses)
        if found:
            score += 15
            reasons.append(f"Suspicious domain status: {', '.join(found)}")

    severity = "LOW"
    if score >= 70:
        severity = "CRITICAL"
    elif score >= 50:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"

    return RiskScore(risk_score=min(score, 100), severity=severity, reasons=reasons)
