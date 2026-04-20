import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Save, Key } from "lucide-react";
import { getSettings, updateSettings } from "../lib/api";

const FIELDS = [
  { k: "ipinfo_token", label: "IPInfo Token", url: "https://ipinfo.io/account/token" },
  { k: "abuseipdb_key", label: "AbuseIPDB Key", url: "https://www.abuseipdb.com/account/api" },
  { k: "virustotal_key", label: "VirusTotal Key", url: "https://www.virustotal.com/gui/my-apikey" },
  { k: "otx_key", label: "OTX Key", url: "https://otx.alienvault.com/api" },
  { k: "discord_webhook", label: "Discord Webhook", url: "https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks" },
];

export default function Settings() {
  const [masked, setMasked] = useState({});
  const [values, setValues] = useState({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getSettings().then(setMasked).catch(() => {});
  }, []);

  const onSave = async () => {
    const payload = Object.fromEntries(Object.entries(values).filter(([, v]) => v));
    if (!Object.keys(payload).length) {
      toast.message("Nothing to update");
      return;
    }
    setSaving(true);
    try {
      await updateSettings(payload);
      toast.success("API keys saved");
      setValues({});
      setMasked(await getSettings());
    } catch {
      toast.error("Failed to save");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-6 py-10" data-testid="settings-page">
      <div className="font-mono text-xs text-cyan uppercase tracking-widest flex items-center gap-2 mb-2">
        <Key className="h-3 w-3" /> osint::credentials
      </div>
      <h1 className="text-3xl font-semibold mb-2">API Keys</h1>
      <p className="text-sm text-muted-foreground mb-8">
        Optional. Modules without keys run in limited mode. Keys are stored in MongoDB.
      </p>

      <div className="space-y-4">
        {FIELDS.map(({ k, label, url }) => (
          <div key={k} className="border border-border bg-card">
            <div className="flex items-center justify-between px-4 py-2 border-b border-border">
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</span>
              <div className="flex items-center gap-3">
                {masked[`${k}_set`] && (
                  <span className="font-mono text-[10px] text-risk-low uppercase tracking-widest">● set</span>
                )}
                <a href={url} target="_blank" rel="noreferrer" className="font-mono text-[10px] text-cyan hover:underline">
                  get_key →
                </a>
              </div>
            </div>
            <input
              type="password"
              data-testid={`input-${k}`}
              value={values[k] || ""}
              onChange={(e) => setValues({ ...values, [k]: e.target.value })}
              placeholder={masked[k] || "not set"}
              className="w-full bg-transparent font-mono text-sm px-4 py-3 outline-none placeholder:text-muted-foreground/50"
            />
          </div>
        ))}
      </div>

      <button
        onClick={onSave}
        disabled={saving}
        data-testid="save-settings-btn"
        className="mt-8 inline-flex items-center gap-2 bg-cyan text-background hover:bg-cyan-hover disabled:opacity-50 font-mono uppercase tracking-widest text-xs px-6 py-3"
      >
        <Save className="h-3.5 w-3.5" /> {saving ? "Saving…" : "Save Keys"}
      </button>
    </div>
  );
}
