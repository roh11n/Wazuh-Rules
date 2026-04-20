import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { Target, Play, AlertCircle, Globe, Server, Network, Search as SearchIcon, Database } from "lucide-react";
import { createScan } from "../lib/api";
import { Switch } from "../components/ui/switch";

const MODES = [
  { id: "domain", label: "Domain", icon: Globe, placeholder: "example.com", desc: "Full recon: RDAP, DNS, subs, certs, tech, IPs, ports, dirs, dorking." },
  { id: "website", label: "Website", icon: Server, placeholder: "www.example.com", desc: "Single host: tech stack, cert, ports, dirs, network info." },
  { id: "ip", label: "IP", icon: Network, placeholder: "8.8.8.8", desc: "IP ownership, reputation, Shodan ports + CVEs, passive DNS, WHOIS." },
  { id: "dork", label: "Dork", icon: SearchIcon, placeholder: "example.com", desc: "Google dorking only. Target can be a domain or keyword." },
  { id: "shodan_search", label: "Shodan", icon: Database, placeholder: 'apache country:"US"', desc: "Search Shodan by service, product, cert, org, country, etc." },
];

export default function Landing() {
  const [mode, setMode] = useState("domain");
  const [target, setTarget] = useState("");
  const [dorks, setDorks] = useState("");
  const [skipSs, setSkipSs] = useState(false);
  const [skipDork, setSkipDork] = useState(false);
  const [skipDirs, setSkipDirs] = useState(false);
  const [skipPorts, setSkipPorts] = useState(false);
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();

  const current = MODES.find(m => m.id === mode);

  const validate = (t) => {
    if (!t) return "Enter a target";
    if (mode === "ip" && !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(t)) return "Enter a valid IPv4 (e.g. 8.8.8.8)";
    if (mode === "shodan_search") return null;
    if ((mode === "domain" || mode === "website") && !t.includes(".")) return "Enter a valid domain";
    return null;
  };

  const onSubmit = async (e) => {
    e?.preventDefault();
    const t = target.trim();
    const err = validate(t);
    if (err) { toast.error(err); return; }

    setBusy(true);
    try {
      const dq = dorks.split("\n").map(s => s.trim()).filter(Boolean);
      const r = await createScan({
        target: t,
        mode,
        dork_queries: dq,
        skip_screenshots: skipSs,
        skip_dorking: skipDork,
        skip_directories: skipDirs,
        skip_ports: skipPorts,
      });
      toast.success(`${mode.toUpperCase()} scan queued for ${r.target}`);
      nav(`/scans/${r.id}`);
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Failed to start scan");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-56px)] relative overflow-hidden">
      <div className="absolute inset-0 grid-bg opacity-30 pointer-events-none" />
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-background/60 to-background pointer-events-none" />

      <div className="relative max-w-4xl mx-auto px-6 py-16">
        <div className="mb-2 font-mono text-xs text-cyan uppercase tracking-widest flex items-center gap-2">
          <span className="h-1 w-1 bg-cyan animate-pulse" /> osint::recon.initialize()
        </div>
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-semibold tracking-tight mb-4">
          Intelligence,
          <br />
          <span className="text-cyan">one target at a time.</span>
        </h1>
        <p className="text-muted-foreground text-base max-w-2xl mb-10">
          Pick a scan type below. Each mode runs a focused pipeline — Domain for full-surface recon,
          Website for single-host analysis, IP for infrastructure attribution (with Shodan),
          or Dork for targeted Google intel.
        </p>

        {/* Mode tabs */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-6" data-testid="mode-tabs">
          {MODES.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              onClick={() => setMode(id)}
              data-testid={`tab-${id}`}
              className={`flex items-center gap-2 px-4 py-3 font-mono text-xs uppercase tracking-widest border transition-colors ${
                mode === id
                  ? "border-cyan text-cyan bg-cyan/5"
                  : "border-border text-muted-foreground hover:text-foreground hover:border-border"
              }`}
            >
              <Icon className="h-3.5 w-3.5" strokeWidth={1.5} />
              {label}
            </button>
          ))}
        </div>

        <form onSubmit={onSubmit} className="space-y-4" data-testid="scan-form">
          <div className="border border-border bg-card">
            <div className="border-b border-border px-4 py-2 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Target className="h-3.5 w-3.5 text-cyan" strokeWidth={1.5} />
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  {mode === "ip" ? "target_ip" :
                   mode === "dork" ? "target_or_keyword" :
                   mode === "shodan_search" ? "shodan_query" :
                   "target_" + mode}
                </span>
              </div>
              <span className="font-mono text-[10px] text-cyan/70">{current.desc}</span>
            </div>
            <div className="flex">
              <div className="px-4 py-4 font-mono text-cyan text-sm border-r border-border">&gt;</div>
              <input
                data-testid="scan-input"
                autoFocus
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={current.placeholder}
                className="flex-1 bg-transparent font-mono text-lg px-4 py-4 outline-none text-foreground placeholder:text-muted-foreground/50"
              />
            </div>
          </div>

          {(mode === "domain" || mode === "dork") && (
            <div className="border border-border bg-card">
              <div className="border-b border-border px-4 py-2">
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  custom_dorks (optional, one per line — {'{target}'} is substituted)
                </span>
              </div>
              <textarea
                data-testid="dork-input"
                value={dorks}
                onChange={(e) => setDorks(e.target.value)}
                rows={3}
                placeholder={'site:{target} ext:bak\n"{target}" leaked'}
                className="w-full bg-transparent font-mono text-sm px-4 py-3 outline-none resize-none placeholder:text-muted-foreground/50"
              />
            </div>
          )}

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {mode !== "dork" && mode !== "ip" && mode !== "shodan_search" && (
              <label className="border border-border bg-card px-3 py-2 flex items-center justify-between gap-2 cursor-pointer" data-testid="toggle-skip-ss">
                <span className="font-mono text-[10px] uppercase tracking-widest">Skip SS</span>
                <Switch checked={skipSs} onCheckedChange={setSkipSs} />
              </label>
            )}
            {mode === "domain" && (
              <label className="border border-border bg-card px-3 py-2 flex items-center justify-between gap-2 cursor-pointer" data-testid="toggle-skip-dork">
                <span className="font-mono text-[10px] uppercase tracking-widest">Skip Dork</span>
                <Switch checked={skipDork} onCheckedChange={setSkipDork} />
              </label>
            )}
            {mode !== "dork" && mode !== "shodan_search" && (
              <label className="border border-border bg-card px-3 py-2 flex items-center justify-between gap-2 cursor-pointer" data-testid="toggle-skip-ports">
                <span className="font-mono text-[10px] uppercase tracking-widest">Skip Ports</span>
                <Switch checked={skipPorts} onCheckedChange={setSkipPorts} />
              </label>
            )}
            {(mode === "domain" || mode === "website") && (
              <label className="border border-border bg-card px-3 py-2 flex items-center justify-between gap-2 cursor-pointer" data-testid="toggle-skip-dirs">
                <span className="font-mono text-[10px] uppercase tracking-widest">Skip Dirs</span>
                <Switch checked={skipDirs} onCheckedChange={setSkipDirs} />
              </label>
            )}
          </div>

          {mode === "shodan_search" && (
            <div className="border border-cyan/20 bg-cyan/5 px-4 py-3 text-xs font-mono text-cyan/80">
              <div className="mb-2 text-[10px] uppercase tracking-widest text-cyan">Shodan query examples</div>
              <div className="space-y-1 text-muted-foreground">
                <div>• <span className="text-foreground">apache country:"US"</span> — Apache servers in US</div>
                <div>• <span className="text-foreground">port:22 product:"OpenSSH"</span> — SSH servers</div>
                <div>• <span className="text-foreground">ssl.cert.issuer.CN:"Let's Encrypt"</span> — LE certs</div>
                <div>• <span className="text-foreground">org:"Google"</span> — Hosts at a given org</div>
                <div>• <span className="text-foreground">vuln:CVE-2021-44228</span> — Log4Shell</div>
              </div>
            </div>
          )}

          <div className="flex items-start gap-3 text-xs text-muted-foreground font-mono border border-yellow-500/20 bg-yellow-500/5 px-4 py-3">
            <AlertCircle className="h-4 w-4 text-yellow-500 flex-shrink-0 mt-0.5" strokeWidth={1.5} />
            <p>Only scan targets you own or are authorized to assess. Unauthorized scanning may violate laws & ToS.</p>
          </div>

          <button
            type="submit"
            disabled={busy}
            data-testid="start-scan-button"
            className="inline-flex items-center gap-3 bg-cyan text-background hover:bg-cyan-hover disabled:opacity-50 disabled:cursor-not-allowed font-mono uppercase tracking-widest text-xs px-8 py-4 transition-colors duration-150"
          >
            <Play className="h-4 w-4" strokeWidth={2} />
            {busy ? "Queueing…" : `Initiate ${current.label} Scan`}
          </button>
        </form>
      </div>
    </div>
  );
}
