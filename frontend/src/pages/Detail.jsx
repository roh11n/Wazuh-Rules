import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, FileText, Download, Globe, Server, Lock, Shield, Network, Camera, Search as SearchIcon, Cpu, Radar } from "lucide-react";
import { getScan, reportUrl } from "../lib/api";
import ScanProgress from "../components/ScanProgress";
import SeverityBadge from "../components/SeverityBadge";

const Section = ({ icon: Icon, title, count, children, testId }) => (
  <section className="border border-border bg-card" data-testid={testId}>
    <header className="flex items-center justify-between border-b border-border px-4 py-2.5">
      <div className="flex items-center gap-2">
        <Icon className="h-3.5 w-3.5 text-cyan" strokeWidth={1.5} />
        <h2 className="font-mono text-xs uppercase tracking-widest">{title}</h2>
      </div>
      {count != null && (
        <span className="font-mono text-[10px] text-muted-foreground">{count} items</span>
      )}
    </header>
    <div className="p-4">{children}</div>
  </section>
);

const KV = ({ k, v, mono = true }) => (
  <div className="flex gap-3 py-1 text-sm">
    <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground min-w-[120px] pt-0.5">{k}</span>
    <span className={`${mono ? "font-mono" : ""} text-foreground break-all`}>{v ?? <span className="text-muted-foreground">—</span>}</span>
  </div>
);

const Table = ({ cols, rows, keyFn }) => (
  <div className="overflow-x-auto">
    <table className="w-full font-mono text-xs">
      <thead>
        <tr className="border-b border-border">
          {cols.map((c) => (
            <th key={c.k} className="text-left py-2 px-2 font-medium text-cyan uppercase tracking-widest text-[10px]">{c.label}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.length === 0 ? (
          <tr><td colSpan={cols.length} className="py-4 text-center text-muted-foreground">No data</td></tr>
        ) : rows.map((r, i) => (
          <tr key={keyFn ? keyFn(r, i) : i} className="border-b border-border/50 last:border-b-0">
            {cols.map((c) => (
              <td key={c.k} className="py-1.5 px-2 text-foreground">{c.render ? c.render(r) : (r[c.k] ?? "—")}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

export default function Detail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    let interval;
    const fetch = async () => {
      try {
        const d = await getScan(id);
        if (!alive) return;
        setScan(d);
        setLoading(false);
        if (d.status === "completed" || d.status === "failed") {
          clearInterval(interval);
        }
      } catch {
        toast.error("Failed to load scan");
        setLoading(false);
      }
    };
    fetch();
    interval = setInterval(fetch, 2000);
    return () => { alive = false; clearInterval(interval); };
  }, [id]);

  if (loading) return <div className="max-w-7xl mx-auto p-8 font-mono text-muted-foreground">Loading…</div>;
  if (!scan) return <div className="max-w-7xl mx-auto p-8 font-mono text-risk-critical">Not found</div>;

  const r = scan.result || {};
  const isDone = scan.status === "completed";

  return (
    <div className="max-w-7xl mx-auto px-6 py-8" data-testid="scan-detail">
      <div className="flex items-center justify-between mb-6">
        <Link to="/scans" className="inline-flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-muted-foreground hover:text-cyan" data-testid="back-link">
          <ArrowLeft className="h-3.5 w-3.5" /> history
        </Link>
        {isDone && (
          <a
            href={reportUrl(id)}
            target="_blank"
            rel="noreferrer"
            data-testid="download-report-btn"
            className="inline-flex items-center gap-2 border border-cyan text-cyan hover:bg-cyan/10 font-mono text-xs uppercase tracking-widest px-4 py-2"
          >
            <Download className="h-3.5 w-3.5" /> HTML Report
          </a>
        )}
      </div>

      <div className="mb-4 font-mono text-xs text-cyan uppercase tracking-widest">target</div>
      <h1 className="text-3xl sm:text-4xl font-mono font-semibold mb-2 break-all" data-testid="target-heading">{scan.target}</h1>
      <div className="text-xs text-muted-foreground font-mono mb-8">
        scan_id={scan.id.slice(0, 8)}… · {new Date(scan.created_at).toLocaleString()}
      </div>

      <div className="mb-8">
        <ScanProgress status={scan} />
      </div>

      {isDone && r.risk && (
        <div className="mb-8 border border-border bg-card p-6" data-testid="risk-summary">
          <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
            <div>
              <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground mb-1">risk_assessment</div>
              <div className="text-5xl font-mono font-semibold text-cyan" data-testid="risk-score">
                {r.risk.risk_score}<span className="text-muted-foreground text-2xl">/100</span>
              </div>
            </div>
            <SeverityBadge severity={r.risk.severity} testId="risk-severity" />
          </div>
          <div className="h-1 bg-secondary mb-4 overflow-hidden">
            <div className={`h-full ${
              r.risk.severity === "CRITICAL" ? "bg-risk-critical" :
              r.risk.severity === "HIGH" ? "bg-risk-high" :
              r.risk.severity === "MEDIUM" ? "bg-risk-medium" : "bg-risk-low"
            }`} style={{ width: `${r.risk.risk_score}%` }} />
          </div>
          {r.risk.reasons?.length > 0 && (
            <div className="space-y-1.5">
              {r.risk.reasons.map((rs, i) => (
                <div key={i} className="flex gap-2 font-mono text-xs border-l-2 border-yellow-500 pl-3 py-1 bg-yellow-500/5">
                  <span className="text-yellow-500">!</span><span>{rs}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {isDone && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {r.domain && (
            <Section icon={Globe} title="Domain Intelligence" testId="sec-domain">
              <KV k="registrar" v={r.domain.registrar} />
              <KV k="registrant" v={r.domain.registrant} />
              <KV k="registered" v={r.domain.registration_date} />
              <KV k="expires" v={r.domain.expiry_date} />
              <KV k="dnssec" v={r.domain.dnssec ? "ENABLED" : "DISABLED"} />
              <KV k="abuse_email" v={r.domain.abuse_email} />
              <KV k="statuses" v={r.domain.statuses?.join(", ")} />
            </Section>
          )}

          {r.dns_records && (
            <Section icon={Network} title="DNS Records" testId="sec-dns">
              <KV k="A" v={r.dns_records.a?.join(", ")} />
              <KV k="AAAA" v={r.dns_records.aaaa?.join(", ")} />
              <KV k="NS" v={r.dns_records.ns?.join(", ")} />
              <KV k="MX" v={r.dns_records.mx?.map(m => `${m.priority} ${m.exchange}`).join(", ")} />
              <KV k="SPF" v={r.dns_records.spf} />
              <KV k="DMARC" v={r.dns_records.dmarc} />
            </Section>
          )}

          <Section icon={Server} title="Subdomains" count={r.subdomains?.length} testId="sec-subs">
            <Table
              cols={[{k:"subdomain",label:"Subdomain"},{k:"source",label:"Source"}]}
              rows={(r.subdomains || []).slice(0, 100)}
            />
          </Section>

          <Section icon={Globe} title="Live Hosts" count={r.live_hosts?.length} testId="sec-live">
            <Table
              cols={[
                {k:"host",label:"Host"},
                {k:"status_code",label:"Status"},
                {k:"server",label:"Server"},
                {k:"title",label:"Title", render:(x)=><span className="block truncate max-w-[260px]">{x.title || "—"}</span>},
              ]}
              rows={r.live_hosts || []}
            />
          </Section>

          <Section icon={Lock} title="TLS Certificates" count={r.tls_certs?.length} testId="sec-tls">
            {(r.tls_certs || []).map((c, i) => (
              <div key={i} className="mb-3 pb-3 border-b border-border last:border-0 last:mb-0 last:pb-0">
                <div className="font-mono text-sm text-cyan mb-2">{c.host}</div>
                <KV k="issuer" v={c.issuer?.commonName || c.issuer?.organizationName} />
                <KV k="not_after" v={c.not_after} />
                <KV k="expired" v={c.expired ? "YES" : "NO"} />
                <KV k="self_signed" v={c.self_signed ? "YES" : "NO"} />
              </div>
            ))}
            {(!r.tls_certs || r.tls_certs.length === 0) && <p className="text-xs text-muted-foreground font-mono">No certificates retrieved.</p>}
          </Section>

          <Section icon={Network} title="IP Intelligence" count={r.ips?.length} testId="sec-ips">
            <Table
              cols={[
                {k:"ip",label:"IP"},
                {k:"country",label:"CC"},
                {k:"org",label:"Org",render:(x)=>x.org || x.asn || "—"},
                {k:"reputation_score",label:"Rep"},
                {k:"flagged",label:"Flag",render:(x)=>x.flagged ? <span className="text-risk-critical">⬤</span> : <span className="text-risk-low">○</span>},
              ]}
              rows={r.ips || []}
            />
          </Section>

          <Section icon={Cpu} title="Tech Fingerprints" count={r.tech_fingerprints?.length} testId="sec-tech">
            {(r.tech_fingerprints || []).map((t, i) => (
              <div key={i} className="mb-3 pb-3 border-b border-border last:border-0 last:mb-0 last:pb-0">
                <div className="font-mono text-sm text-cyan mb-2">{t.host}</div>
                <KV k="server" v={t.server} />
                <KV k="cms" v={t.cms} />
                <KV k="cdn" v={t.cdn} />
                <KV k="js_libs" v={t.js_libraries?.join(", ")} />
                <KV k="frameworks" v={t.frameworks?.join(", ")} />
                <KV k="favicon_hash" v={t.favicon_hash} />
              </div>
            ))}
            {(!r.tech_fingerprints || r.tech_fingerprints.length === 0) && <p className="text-xs text-muted-foreground font-mono">No fingerprints.</p>}
          </Section>

          <Section icon={Radar} title="Open Ports / Services" count={r.services?.length} testId="sec-ports">
            <Table
              cols={[
                {k:"host",label:"Host"},
                {k:"port",label:"Port"},
                {k:"service",label:"Service"},
                {k:"banner",label:"Banner", render:(x)=><span className="block truncate max-w-[360px] text-muted-foreground">{x.banner || "—"}</span>},
              ]}
              rows={r.services || []}
            />
          </Section>

          <Section icon={Shield} title="Passive DNS" count={r.passive_dns?.length} testId="sec-pdns">
            <Table
              cols={[
                {k:"hostname",label:"Hostname"},
                {k:"ip",label:"IP"},
                {k:"record_type",label:"Type"},
                {k:"last_seen",label:"Last Seen"},
              ]}
              rows={(r.passive_dns || []).slice(0, 50)}
            />
          </Section>

          <Section icon={Camera} title="Screenshots" count={r.screenshots?.length} testId="sec-ss">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {(r.screenshots || []).map((s, i) => (
                <div key={i} className="border border-border">
                  <div className="px-3 py-2 border-b border-border font-mono text-xs text-cyan truncate">{s.host}</div>
                  {s.base64_data && (
                    <img src={`data:image/png;base64,${s.base64_data}`} alt={s.host} className="w-full block" />
                  )}
                </div>
              ))}
            </div>
            {(!r.screenshots || r.screenshots.length === 0) && <p className="text-xs text-muted-foreground font-mono">No screenshots captured.</p>}
          </Section>

          <Section icon={SearchIcon} title="Google Dorking" count={r.dorking?.length} testId="sec-dork">
            {(r.dorking || []).map((d, i) => (
              <div key={i} className="mb-4 last:mb-0">
                <div className="font-mono text-xs text-cyan border-l-2 border-cyan pl-2 py-1 mb-2 break-all">{d.query}</div>
                {d.results?.length ? (
                  <ul className="space-y-1 pl-4">
                    {d.results.slice(0, 5).map((e, j) => (
                      <li key={j} className="text-xs">
                        <div className="text-foreground">{e.title}</div>
                        <a href={e.url} target="_blank" rel="noreferrer" className="font-mono text-cyan hover:underline break-all">{e.url}</a>
                      </li>
                    ))}
                  </ul>
                ) : <p className="text-xs text-muted-foreground font-mono pl-2">No results (possibly rate-limited)</p>}
              </div>
            ))}
            {(!r.dorking || r.dorking.length === 0) && <p className="text-xs text-muted-foreground font-mono">Dorking skipped or failed.</p>}
          </Section>
        </div>
      )}
    </div>
  );
}
