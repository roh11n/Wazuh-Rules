const MAP = {
  LOW: "border-risk-low text-risk-low",
  MEDIUM: "border-risk-medium text-risk-medium",
  HIGH: "border-risk-high text-risk-high",
  CRITICAL: "border-risk-critical text-risk-critical animate-pulse-cyan",
};

export default function SeverityBadge({ severity, score, testId }) {
  const cls = MAP[severity] || "border-muted-foreground text-muted-foreground";
  return (
    <span
      data-testid={testId || "severity-badge"}
      className={`inline-flex items-center gap-2 px-2 py-0.5 border ${cls} font-mono text-xs uppercase tracking-widest rounded-sm`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current inline-block" />
      {severity || "—"}
      {score != null && <span className="opacity-80">{score}/100</span>}
    </span>
  );
}
