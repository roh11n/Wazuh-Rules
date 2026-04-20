"""HTML report generator."""
from jinja2 import Template
from osint.models import ScanResult

REPORT_TEMPLATE = Template(r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>OSINT Report - {{ target }}</title>
<style>
:root{--bg:#09090b;--surface:#18181b;--border:#27272a;--text:#fafafa;
--muted:#a1a1aa;--cyan:#06b6d4;--green:#22c55e;--yellow:#eab308;
--orange:#f97316;--red:#ef4444;}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'IBM Plex Sans',system-ui,sans-serif;background:var(--bg);
color:var(--text);line-height:1.6;padding:2rem;}
.mono{font-family:'JetBrains Mono',monospace;}
.container{max-width:1200px;margin:0 auto;}
h1{color:var(--cyan);font-size:1.8rem;border-bottom:1px solid var(--border);padding-bottom:.5rem;margin-bottom:1rem;}
h2{color:var(--cyan);font-size:1.2rem;margin:2rem 0 .8rem;border-left:3px solid var(--cyan);padding-left:.8rem;text-transform:uppercase;letter-spacing:.05em;}
h3{color:var(--muted);font-size:.95rem;margin:.8rem 0 .4rem;}
table{width:100%;border-collapse:collapse;margin:.6rem 0 1.2rem;background:var(--surface);border:1px solid var(--border);font-family:'JetBrains Mono',monospace;font-size:.82rem;}
th,td{padding:.5rem .7rem;text-align:left;border-bottom:1px solid var(--border);}
th{background:#0f0f11;color:var(--cyan);font-weight:600;text-transform:uppercase;letter-spacing:.05em;font-size:.75rem;}
.badge{display:inline-block;padding:.25rem .6rem;border:1px solid;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;font-family:'JetBrains Mono',monospace;}
.badge-low{border-color:var(--green);color:var(--green);}
.badge-medium{border-color:var(--yellow);color:var(--yellow);}
.badge-high{border-color:var(--orange);color:var(--orange);}
.badge-critical{border-color:var(--red);color:var(--red);}
.meta{color:var(--muted);font-size:.82rem;}
.reason{background:var(--surface);padding:.4rem .7rem;margin:.2rem 0;font-size:.83rem;border-left:2px solid var(--yellow);}
.screenshot{max-width:100%;border:1px solid var(--border);margin:.5rem 0;}
.card{background:var(--surface);padding:1rem;margin:.5rem 0;border:1px solid var(--border);}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:.8rem;}
.kv{display:flex;gap:.5rem;margin:.2rem 0;font-size:.85rem;}
.kv .k{color:var(--muted);min-width:140px;text-transform:uppercase;font-size:.7rem;letter-spacing:.05em;}
.kv .v{color:var(--text);word-break:break-all;font-family:'JetBrains Mono',monospace;font-size:.82rem;}
.dork-query{background:var(--surface);padding:.5rem .8rem;margin:.5rem 0;font-family:'JetBrains Mono',monospace;font-size:.82rem;color:var(--cyan);border:1px solid var(--border);}
</style></head><body><div class="container">
<h1>OSINT INTELLIGENCE REPORT</h1>
<p class="meta">Target: <strong class="mono">{{ target }}</strong> | Generated: {{ timestamp }}</p>

<h2>Risk Assessment</h2>
<div class="card">
<p>Risk Score: <span class="badge badge-{{ sev_class }}">{{ risk.risk_score }}/100 - {{ risk.severity }}</span></p>
{% if risk.reasons %}<h3>Findings</h3>
{% for r in risk.reasons %}<div class="reason">{{ r }}</div>{% endfor %}{% endif %}
</div>

{% if domain %}<h2>Domain Intelligence</h2><div class="card grid2">
<div>
<div class="kv"><span class="k">Registrar</span><span class="v">{{ domain.registrar or '-' }}</span></div>
<div class="kv"><span class="k">Registrant</span><span class="v">{{ domain.registrant or '-' }}</span></div>
<div class="kv"><span class="k">Registered</span><span class="v">{{ domain.registration_date or '-' }}</span></div>
<div class="kv"><span class="k">Expires</span><span class="v">{{ domain.expiry_date or '-' }}</span></div>
</div><div>
<div class="kv"><span class="k">DNSSEC</span><span class="v">{{ 'YES' if domain.dnssec else 'NO' }}</span></div>
<div class="kv"><span class="k">Abuse</span><span class="v">{{ domain.abuse_email or '-' }}</span></div>
<div class="kv"><span class="k">Statuses</span><span class="v">{{ domain.statuses|join(', ') or '-' }}</span></div>
</div></div>{% endif %}

{% if dns_records %}<h2>DNS Records</h2><div class="card">
<div class="kv"><span class="k">A</span><span class="v">{{ dns_records.a|join(', ') or '-' }}</span></div>
<div class="kv"><span class="k">AAAA</span><span class="v">{{ dns_records.aaaa|join(', ') or '-' }}</span></div>
<div class="kv"><span class="k">NS</span><span class="v">{{ dns_records.ns|join(', ') or '-' }}</span></div>
<div class="kv"><span class="k">SPF</span><span class="v">{{ dns_records.spf or '-' }}</span></div>
<div class="kv"><span class="k">DMARC</span><span class="v">{{ dns_records.dmarc or '-' }}</span></div>
{% if dns_records.mx %}<h3>MX</h3><table><tr><th>Priority</th><th>Exchange</th></tr>
{% for m in dns_records.mx %}<tr><td>{{ m.priority }}</td><td>{{ m.exchange }}</td></tr>{% endfor %}</table>{% endif %}
</div>{% endif %}

{% if subdomains %}<h2>Subdomains ({{ subdomains|length }})</h2>
<table><tr><th>Subdomain</th><th>Source</th></tr>
{% for s in subdomains %}<tr><td>{{ s.subdomain }}</td><td>{{ s.source or '-' }}</td></tr>{% endfor %}</table>{% endif %}

{% if live_hosts %}<h2>Live Hosts ({{ live_hosts|length }})</h2>
<table><tr><th>Host</th><th>Status</th><th>Title</th><th>Server</th></tr>
{% for h in live_hosts %}<tr><td>{{ h.host }}</td><td>{{ h.status_code }}</td><td>{{ h.title or '-' }}</td><td>{{ h.server or '-' }}</td></tr>{% endfor %}</table>{% endif %}

{% if tls_certs %}<h2>TLS Certificates</h2>
{% for c in tls_certs %}<div class="card"><h3>{{ c.host }}</h3><div class="grid2">
<div><div class="kv"><span class="k">Subject CN</span><span class="v">{{ c.subject.get('commonName','-') }}</span></div>
<div class="kv"><span class="k">Issuer</span><span class="v">{{ c.issuer.get('commonName','-') }}</span></div></div>
<div><div class="kv"><span class="k">Not After</span><span class="v">{{ c.not_after or '-' }}</span></div>
<div class="kv"><span class="k">Expired</span><span class="v">{{ 'YES' if c.expired else 'NO' }}</span></div></div>
</div></div>{% endfor %}{% endif %}

{% if ips %}<h2>IP Intelligence</h2>
<table><tr><th>IP</th><th>Country</th><th>City</th><th>Org/ASN</th><th>Reputation</th><th>Flagged</th></tr>
{% for ip in ips %}<tr><td>{{ ip.ip }}</td><td>{{ ip.country or '-' }}</td><td>{{ ip.city or '-' }}</td>
<td>{{ ip.org or ip.asn or '-' }}</td><td>{{ ip.reputation_score if ip.reputation_score is not none else '-' }}</td>
<td>{{ 'YES' if ip.flagged else 'NO' }}</td></tr>{% endfor %}</table>{% endif %}

{% if services %}<h2>Open Ports / Services ({{ services|length }})</h2>
<table><tr><th>Host</th><th>Port</th><th>Service</th><th>Banner</th></tr>
{% for s in services %}<tr><td>{{ s.host }}</td><td>{{ s.port }}</td><td>{{ s.service or '-' }}</td><td>{{ s.banner or '-' }}</td></tr>{% endfor %}
</table>{% endif %}

{% if shodan %}<h2>Shodan Intelligence</h2>
{% for h in shodan %}<div class="card"><h3>{{ h.ip }}</h3>
{% if not h.found %}<p class="meta">Not indexed by Shodan.</p>
{% else %}<div class="grid2">
<div>
<div class="kv"><span class="k">Country</span><span class="v">{{ h.country_name or '-' }}</span></div>
<div class="kv"><span class="k">City</span><span class="v">{{ h.city or '-' }}</span></div>
<div class="kv"><span class="k">Org</span><span class="v">{{ h.org or '-' }}</span></div>
<div class="kv"><span class="k">ISP</span><span class="v">{{ h.isp or '-' }}</span></div>
<div class="kv"><span class="k">ASN</span><span class="v">{{ h.asn or '-' }}</span></div>
</div><div>
<div class="kv"><span class="k">OS</span><span class="v">{{ h.os or '-' }}</span></div>
<div class="kv"><span class="k">Last Update</span><span class="v">{{ h.last_update or '-' }}</span></div>
<div class="kv"><span class="k">Open Ports</span><span class="v">{{ h.ports|join(', ') or '-' }}</span></div>
<div class="kv"><span class="k">Hostnames</span><span class="v">{{ h.hostnames|join(', ') or '-' }}</span></div>
</div></div>
{% if h.vulns %}<h3 style="color:var(--red);">Vulnerabilities ({{ h.vulns|length }})</h3>
<p style="font-family:monospace;font-size:.78rem;color:var(--red);">{{ h.vulns|join(', ') }}</p>{% endif %}
{% if h.services %}<h3>Services</h3>
<table><tr><th>Port</th><th>Product</th><th>Version</th><th>Banner</th></tr>
{% for s in h.services %}<tr><td>{{ s.port }}</td><td>{{ s.product or '-' }}</td><td>{{ s.version or '-' }}</td><td>{{ (s.banner or '-')[:100] }}</td></tr>{% endfor %}
</table>{% endif %}
{% endif %}</div>{% endfor %}{% endif %}

{% if cves %}<h2>Vulnerabilities (CVE / NVD)</h2>
{% for c in cves|sort(attribute='cvss_score', reverse=true) %}<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem;flex-wrap:wrap;gap:.5rem;">
<a href="{{ c.nvd_url }}" style="font-family:monospace;color:var(--cyan);font-weight:600;">{{ c.cve_id }}</a>
<div>
{% if c.cvss_score %}<span class="meta">CVSS {{ c.cvss_score }}</span>{% endif %}
{% if c.severity %}<span class="badge badge-{{ c.severity.lower() if c.severity != 'NONE' else 'low' }}">{{ c.severity }}</span>{% endif %}
</div></div>
{% if c.description %}<p style="font-size:.82rem;color:var(--muted);">{{ c.description }}</p>{% endif %}
{% if c.vector %}<div class="meta" style="font-family:monospace;margin-top:.4rem;">{{ c.vector }}</div>{% endif %}
</div>{% endfor %}{% endif %}

{% if shodan_search %}<h2>Shodan Search: {{ shodan_search.query }}</h2>
<p class="meta">{{ shodan_search.hits|length }} of {{ shodan_search.total }} results</p>
<table><tr><th>IP:Port</th><th>Product</th><th>Org</th><th>CC</th><th>Hostnames</th></tr>
{% for h in shodan_search.hits %}<tr><td>{{ h.ip }}{% if h.port %}:{{ h.port }}{% endif %}</td>
<td>{{ h.product or '-' }} {{ h.version or '' }}</td><td>{{ h.org or '-' }}</td>
<td>{{ h.country_code or '-' }}</td><td>{{ h.hostnames[:2]|join(', ') or '-' }}</td></tr>{% endfor %}
</table>{% endif %}

{% if directories %}<h2>Directory Enumeration</h2>
{% for d in directories %}<div class="card"><h3>{{ d.host }}</h3>
<table><tr><th>Path</th><th>Status</th><th>Type</th><th>Size</th></tr>
{% for e in d.entries %}<tr><td>{{ e.path }}</td><td>{{ e.status_code }}</td><td>{{ e.content_type or '-' }}</td><td>{{ e.content_length }}</td></tr>{% endfor %}
</table></div>{% endfor %}{% endif %}

{% if tech_fingerprints %}<h2>Technology Fingerprints</h2>
{% for t in tech_fingerprints %}<div class="card"><h3>{{ t.host }}</h3><div class="grid2">
<div><div class="kv"><span class="k">Server</span><span class="v">{{ t.server or '-' }}</span></div>
<div class="kv"><span class="k">CMS</span><span class="v">{{ t.cms or '-' }}</span></div>
<div class="kv"><span class="k">CDN</span><span class="v">{{ t.cdn or '-' }}</span></div></div>
<div><div class="kv"><span class="k">JS Libraries</span><span class="v">{{ t.js_libraries|join(', ') or '-' }}</span></div>
<div class="kv"><span class="k">Frameworks</span><span class="v">{{ t.frameworks|join(', ') or '-' }}</span></div>
<div class="kv"><span class="k">Favicon Hash</span><span class="v">{{ t.favicon_hash or '-' }}</span></div></div>
</div></div>{% endfor %}{% endif %}

{% if passive_dns %}<h2>Passive DNS ({{ passive_dns|length }})</h2>
<table><tr><th>Hostname</th><th>IP</th><th>Type</th><th>First</th><th>Last</th></tr>
{% for r in passive_dns[:100] %}<tr><td>{{ r.hostname }}</td><td>{{ r.ip or '-' }}</td><td>{{ r.record_type or '-' }}</td><td>{{ r.first_seen or '-' }}</td><td>{{ r.last_seen or '-' }}</td></tr>{% endfor %}
</table>{% endif %}

{% if screenshots %}<h2>Screenshots</h2>
{% for s in screenshots %}<div class="card"><h3>{{ s.host }}</h3>
{% if s.base64_data %}<img class="screenshot" src="data:image/png;base64,{{ s.base64_data }}">{% endif %}
</div>{% endfor %}{% endif %}

{% if dorking %}<h2>Google Dorking</h2>
{% for d in dorking %}<div class="dork-query">{{ d.query }}</div>
{% if d.results %}<table><tr><th>Title</th><th>URL</th></tr>
{% for e in d.results %}<tr><td>{{ e.title }}</td><td>{{ e.url }}</td></tr>{% endfor %}</table>
{% else %}<p class="meta">No results</p>{% endif %}{% endfor %}{% endif %}

<hr style="border-color:var(--border);margin:2rem 0 1rem;">
<p class="meta" style="text-align:center;">Generated by OSINT Automation Pipeline | {{ timestamp }}</p>
</div></body></html>""")


def render_html(result: ScanResult) -> str:
    sev_map = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}
    return REPORT_TEMPLATE.render(
        target=result.target,
        timestamp=result.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        risk=result.risk,
        sev_class=sev_map.get(result.risk.severity if result.risk else "LOW", "low"),
        domain=result.domain,
        dns_records=result.dns_records,
        subdomains=result.subdomains,
        live_hosts=result.live_hosts,
        tls_certs=result.tls_certs,
        ips=result.ips,
        services=result.services,
        shodan=result.shodan,
        shodan_search=result.shodan_search,
        cves=result.cves,
        directories=result.directories,
        passive_dns=result.passive_dns,
        tech_fingerprints=result.tech_fingerprints,
        screenshots=result.screenshots,
        dorking=result.dorking,
    )
