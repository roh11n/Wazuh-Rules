const PHASES = [
  { key: "domain",        label: "Domain" },
  { key: "subdomains",    label: "Subs" },
  { key: "dns_resolve",   label: "Resolve" },
  { key: "http_probe",    label: "HTTP" },
  { key: "tls_tech_ss",   label: "TLS+Tech" },
  { key: "ip_enrich",     label: "IP Intel" },
  { key: "ip_whois",      label: "IP WHOIS" },
  { key: "shodan",        label: "Shodan" },
  { key: "shodan_search", label: "Search" },
  { key: "port_scan",     label: "Ports" },
  { key: "directories",   label: "Dirs" },
  { key: "passive_dns",   label: "pDNS" },
  { key: "reputation",    label: "VT" },
  { key: "dorking",       label: "Dorking" },
  { key: "nvd",           label: "CVE" },
  { key: "risk",          label: "Risk" },
];

const ORDER = PHASES.map(p => p.key);

export default function ScanProgress({ status }) {
  const idx = ORDER.indexOf(status?.phase);
  const done = status?.status === "completed";
  const failed = status?.status === "failed";

  return (
    <div className="border border-border bg-card p-6" data-testid="scan-progress">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`h-2 w-2 ${done ? "bg-risk-low" : failed ? "bg-risk-critical" : "bg-cyan animate-pulse-cyan"}`} />
          <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            {failed ? "FAILED" : done ? "COMPLETE" : "SCANNING"}
          </span>
        </div>
        <span className="font-mono text-xs text-cyan" data-testid="progress-pct">{status?.progress ?? 0}%</span>
      </div>

      <div className="relative h-1 bg-secondary mb-6 overflow-hidden">
        <div
          className="absolute inset-y-0 left-0 bg-cyan transition-all duration-500"
          style={{ width: `${status?.progress ?? 0}%` }}
        />
        {!done && !failed && <div className="absolute inset-0 scan-line" />}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 lg:grid-cols-7 gap-2">
        {PHASES.map((p, i) => {
          const active = ORDER.indexOf(status?.phase) === i && !done;
          const complete = i < idx || done;
          return (
            <div
              key={p.key}
              data-testid={`phase-${p.key}`}
              className={`border px-3 py-2 font-mono text-[10px] uppercase tracking-widest flex items-center gap-2 ${
                active ? "border-cyan text-cyan bg-cyan/5" :
                complete ? "border-risk-low/30 text-risk-low/80" :
                "border-border text-muted-foreground"
              }`}
            >
              <span>{String(i + 1).padStart(2, "0")}</span>
              <span>{p.label}</span>
              {active && <span className="ml-auto animate-blink">▊</span>}
              {complete && <span className="ml-auto">✓</span>}
            </div>
          );
        })}
      </div>

      {status?.message && (
        <div className="mt-4 font-mono text-xs text-muted-foreground border-l-2 border-cyan/40 pl-3" data-testid="progress-message">
          <span className="text-cyan">&gt;</span> {status.message}
        </div>
      )}
      {status?.error && (
        <div className="mt-4 font-mono text-xs text-risk-critical border-l-2 border-risk-critical pl-3" data-testid="progress-error">
          ERROR: {status.error}
        </div>
      )}
    </div>
  );
}
