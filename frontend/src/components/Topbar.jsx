import { Link, useLocation } from "react-router-dom";
import { Shield, Radar, Settings as SettingsIcon, Terminal } from "lucide-react";

export default function Topbar() {
  const loc = useLocation();
  const tabs = [
    { to: "/", label: "Scan", icon: Radar, id: "nav-scan" },
    { to: "/scans", label: "History", icon: Terminal, id: "nav-history" },
    { to: "/settings", label: "Settings", icon: SettingsIcon, id: "nav-settings" },
  ];
  return (
    <header className="border-b border-border bg-background/80 backdrop-blur sticky top-0 z-50" data-testid="topbar">
      <div className="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2" data-testid="logo-link">
          <Shield className="h-5 w-5 text-cyan" strokeWidth={1.5} />
          <span className="font-mono text-sm tracking-widest uppercase">
            <span className="text-cyan">osint</span>
            <span className="text-muted-foreground">::</span>
            <span>pipeline</span>
          </span>
        </Link>
        <nav className="flex items-center gap-1">
          {tabs.map(({ to, label, icon: Icon, id }) => {
            const active = loc.pathname === to || (to === "/scans" && loc.pathname.startsWith("/scans"));
            return (
              <Link
                key={to}
                to={to}
                data-testid={id}
                className={`flex items-center gap-2 px-4 py-2 font-mono text-xs uppercase tracking-wider transition-colors duration-150 border border-transparent ${
                  active ? "text-cyan border-cyan/30 bg-cyan/5" : "text-muted-foreground hover:text-foreground hover:border-border"
                }`}
              >
                <Icon className="h-3.5 w-3.5" strokeWidth={1.5} />
                {label}
              </Link>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
