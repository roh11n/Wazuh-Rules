import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { Target, Play, AlertCircle } from "lucide-react";
import { createScan } from "../lib/api";
import { Switch } from "../components/ui/switch";

export default function Landing() {
  const [target, setTarget] = useState("");
  const [dorks, setDorks] = useState("");
  const [skipSs, setSkipSs] = useState(false);
  const [skipDork, setSkipDork] = useState(false);
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();

  const onSubmit = async (e) => {
    e?.preventDefault();
    const t = target.trim();
    if (!t || !t.includes(".")) {
      toast.error("Enter a valid domain (e.g. example.com)");
      return;
    }
    setBusy(true);
    try {
      const dq = dorks.split("\n").map(s => s.trim()).filter(Boolean);
      const r = await createScan({
        target: t,
        dork_queries: dq,
        skip_screenshots: skipSs,
        skip_dorking: skipDork,
      });
      toast.success(`Scan queued for ${r.target}`);
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

      <div className="relative max-w-4xl mx-auto px-6 py-20">
        <div className="mb-2 font-mono text-xs text-cyan uppercase tracking-widest flex items-center gap-2">
          <span className="h-1 w-1 bg-cyan animate-pulse" /> osint::recon.initialize()
        </div>
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-semibold tracking-tight mb-4">
          Domain Intelligence,
          <br />
          <span className="text-cyan">in one command.</span>
        </h1>
        <p className="text-muted-foreground text-base max-w-2xl mb-12">
          Automated OSINT reconnaissance across 10 phases — RDAP, DNS, subdomains, TLS certs,
          IP reputation, passive DNS, tech fingerprinting, screenshots & Google dorking.
          All correlated into a single risk score.
        </p>

        <form onSubmit={onSubmit} className="space-y-6" data-testid="scan-form">
          <div className="border border-border bg-card">
            <div className="border-b border-border px-4 py-2 flex items-center gap-2">
              <Target className="h-3.5 w-3.5 text-cyan" strokeWidth={1.5} />
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">target_domain</span>
            </div>
            <div className="flex">
              <div className="px-4 py-4 font-mono text-cyan text-sm border-r border-border">&gt;</div>
              <input
                data-testid="scan-input"
                autoFocus
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com"
                className="flex-1 bg-transparent font-mono text-lg px-4 py-4 outline-none text-foreground placeholder:text-muted-foreground/50"
              />
            </div>
          </div>

          <div className="border border-border bg-card">
            <div className="border-b border-border px-4 py-2 flex items-center gap-2">
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">custom_dorks (optional, one per line)</span>
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

          <div className="flex flex-col sm:flex-row gap-4">
            <label className="border border-border bg-card px-4 py-3 flex items-center justify-between gap-4 flex-1 cursor-pointer" data-testid="toggle-skip-ss">
              <div>
                <div className="font-mono text-xs uppercase tracking-widest">Skip Screenshots</div>
                <div className="text-xs text-muted-foreground mt-0.5">Faster scans, no chromium</div>
              </div>
              <Switch checked={skipSs} onCheckedChange={setSkipSs} />
            </label>
            <label className="border border-border bg-card px-4 py-3 flex items-center justify-between gap-4 flex-1 cursor-pointer" data-testid="toggle-skip-dork">
              <div>
                <div className="font-mono text-xs uppercase tracking-widest">Skip Dorking</div>
                <div className="text-xs text-muted-foreground mt-0.5">Google may rate-limit</div>
              </div>
              <Switch checked={skipDork} onCheckedChange={setSkipDork} />
            </label>
          </div>

          <div className="flex items-start gap-3 text-xs text-muted-foreground font-mono border border-yellow-500/20 bg-yellow-500/5 px-4 py-3">
            <AlertCircle className="h-4 w-4 text-yellow-500 flex-shrink-0 mt-0.5" strokeWidth={1.5} />
            <p>Only scan domains you own or are authorized to assess. Unauthorized scanning may violate laws & ToS.</p>
          </div>

          <button
            type="submit"
            disabled={busy}
            data-testid="start-scan-button"
            className="w-full sm:w-auto inline-flex items-center gap-3 bg-cyan text-background hover:bg-cyan-hover disabled:opacity-50 disabled:cursor-not-allowed font-mono uppercase tracking-widest text-xs px-8 py-4 transition-colors duration-150"
          >
            <Play className="h-4 w-4" strokeWidth={2} />
            {busy ? "Queueing…" : "Initiate Scan"}
          </button>
        </form>
      </div>
    </div>
  );
}
