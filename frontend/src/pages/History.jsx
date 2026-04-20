import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { Trash2, ExternalLink, Terminal } from "lucide-react";
import { listScans, deleteScan } from "../lib/api";
import SeverityBadge from "../components/SeverityBadge";

function statusPill(s) {
  const map = {
    queued: "text-muted-foreground border-border",
    running: "text-cyan border-cyan/50 animate-pulse-cyan",
    completed: "text-risk-low border-risk-low/50",
    failed: "text-risk-critical border-risk-critical/50",
  };
  return (
    <span className={`inline-block px-2 py-0.5 border font-mono text-[10px] uppercase tracking-widest ${map[s] || ""}`}>
      {s}
    </span>
  );
}

export default function History() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      const data = await listScans();
      setScans(data);
    } catch {
      toast.error("Failed to load scans");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  const onDelete = async (id, e) => {
    e.preventDefault(); e.stopPropagation();
    if (!window.confirm("Delete this scan?")) return;
    await deleteScan(id);
    toast.success("Scan deleted");
    load();
  };

  return (
    <div className="max-w-7xl mx-auto px-6 py-10">
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="font-mono text-xs text-cyan uppercase tracking-widest flex items-center gap-2 mb-2">
            <Terminal className="h-3 w-3" /> osint::history
          </div>
          <h1 className="text-3xl font-semibold">Scan History</h1>
        </div>
        <Link to="/" className="font-mono text-xs uppercase tracking-widest border border-cyan text-cyan px-4 py-2 hover:bg-cyan/10" data-testid="new-scan-btn">
          + new scan
        </Link>
      </div>

      <div className="border border-border bg-card" data-testid="scans-table">
        <div className="grid grid-cols-12 px-4 py-2 border-b border-border font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          <div className="col-span-4">Target</div>
          <div className="col-span-2">Status</div>
          <div className="col-span-2">Severity</div>
          <div className="col-span-2">Created</div>
          <div className="col-span-2 text-right">Actions</div>
        </div>

        {loading ? (
          <div className="p-6 font-mono text-sm text-muted-foreground">Loading…</div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center">
            <p className="font-mono text-sm text-muted-foreground">No scans yet.</p>
            <Link to="/" className="inline-block mt-4 text-cyan font-mono text-xs uppercase tracking-widest underline">
              Start your first scan →
            </Link>
          </div>
        ) : (
          scans.map((s) => (
            <Link
              key={s.id}
              to={`/scans/${s.id}`}
              data-testid={`scan-row-${s.id}`}
              className="grid grid-cols-12 px-4 py-3 border-b border-border last:border-b-0 items-center hover:bg-secondary/30 transition-colors"
            >
              <div className="col-span-4 font-mono text-sm text-foreground truncate">{s.target}</div>
              <div className="col-span-2">{statusPill(s.status)}</div>
              <div className="col-span-2">
                {s.severity ? <SeverityBadge severity={s.severity} score={s.risk_score} /> : <span className="text-muted-foreground font-mono text-xs">—</span>}
              </div>
              <div className="col-span-2 font-mono text-xs text-muted-foreground">
                {new Date(s.created_at).toLocaleString()}
              </div>
              <div className="col-span-2 flex items-center justify-end gap-2">
                <ExternalLink className="h-3.5 w-3.5 text-muted-foreground" />
                <button
                  onClick={(e) => onDelete(s.id, e)}
                  className="p-1.5 hover:text-risk-critical text-muted-foreground"
                  data-testid={`delete-${s.id}`}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </Link>
          ))
        )}
      </div>
    </div>
  );
}
