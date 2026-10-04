import { useEffect, useState } from "react";
import { ipc } from "@/ipc/client";
import type { Settings } from "@/ipc/types";
import { useAppStore } from "@/stores/app-store";
import { Button } from "@/components/ui/button";
import { APP_NAME } from "@/lib/constants";

export function SettingsScreen() {
  const settings = useAppStore((s) => s.settings);
  const setSettings = useAppStore((s) => s.setSettings);
  const [draft, setDraft] = useState<Settings | null>(settings);
  const [msg, setMsg] = useState<string | null>(null);
  const [version, setVersion] = useState("0.1.0");

  useEffect(() => {
    setDraft(settings);
  }, [settings]);

  useEffect(() => {
    void ipc.appVersion().then(setVersion).catch(() => setVersion("0.1.0"));
  }, []);

  if (!draft) {
    return <p className="text-muted-foreground">Loading settings…</p>;
  }

  async function save() {
    if (!draft) return;
    await ipc.setSettings(draft);
    setSettings(draft);
    setMsg("Settings saved");
  }

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6">
      <section className="space-y-1">
        <h1 className="font-display text-3xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">
          Display, performance, and default analysis options
        </p>
      </section>

      <section className="grid gap-4 rounded-lg border border-border/70 bg-card/30 p-4">
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">
          Display timezone
          <input
            className="h-9 rounded-md border border-border bg-background/70 px-2 text-sm text-foreground"
            value={draft.display_timezone}
            onChange={(e) =>
              setDraft({ ...draft, display_timezone: e.target.value })
            }
          />
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={draft.use_utc}
            onChange={(e) => setDraft({ ...draft, use_utc: e.target.checked })}
          />
          Prefer UTC in UI
        </label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">
          Worker threads
          <input
            type="number"
            min={1}
            className="h-9 rounded-md border border-border bg-background/70 px-2 text-sm text-foreground"
            value={draft.threads}
            onChange={(e) =>
              setDraft({ ...draft, threads: Number(e.target.value) || 1 })
            }
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">
          Default rule profile
          <select
            className="h-9 rounded-md border border-border bg-background/70 px-2 text-sm text-foreground"
            value={draft.rule_profile}
            onChange={(e) => setDraft({ ...draft, rule_profile: e.target.value })}
          >
            <option value="default">Default</option>
            <option value="all">All</option>
            <option value="high">High + Critical</option>
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={draft.fts_default}
            onChange={(e) => setDraft({ ...draft, fts_default: e.target.checked })}
          />
          FTS on by default
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={draft.hash_default}
            onChange={(e) => setDraft({ ...draft, hash_default: e.target.checked })}
          />
          Hash files by default
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={draft.builtins_default}
            onChange={(e) =>
              setDraft({ ...draft, builtins_default: e.target.checked })
            }
          />
          Built-ins on by default
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={draft.run_detection_default}
            onChange={(e) =>
              setDraft({ ...draft, run_detection_default: e.target.checked })
            }
          />
          Run detection by default
        </label>

        <div className="grid gap-3 sm:grid-cols-3">
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            B009 kerberoast ≥
            <input
              type="number"
              className="h-9 rounded-md border border-border bg-background/70 px-2 text-sm text-foreground"
              value={draft.thresh_kerberoast}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  thresh_kerberoast: Number(e.target.value) || 0,
                })
              }
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            B010 bruteforce ≥
            <input
              type="number"
              className="h-9 rounded-md border border-border bg-background/70 px-2 text-sm text-foreground"
              value={draft.thresh_bruteforce}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  thresh_bruteforce: Number(e.target.value) || 0,
                })
              }
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            B011 spray ≥
            <input
              type="number"
              className="h-9 rounded-md border border-border bg-background/70 px-2 text-sm text-foreground"
              value={draft.thresh_spray}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  thresh_spray: Number(e.target.value) || 0,
                })
              }
            />
          </label>
        </div>

        <div className="flex gap-2">
          <Button onClick={() => void save()}>Save</Button>
        </div>
        {msg && <p className="text-sm text-muted-foreground">{msg}</p>}
      </section>

      <section className="rounded-lg border border-border/70 bg-card/20 p-4 text-sm text-muted-foreground">
        <h2 className="mb-2 text-foreground">
          {APP_NAME} {version}
        </h2>
        <p>
          Offline EVTX threat hunting. Sigma packs use Detection Rule License (DRL)
          1.1 — author attribution required on every match.
        </p>
        <p className="mt-2">
          ATT&amp;CK® is a trademark of The MITRE Corporation. Built-in rules are MIT.
        </p>
        <p className="mt-2 text-xs">
          Desktop packages: see docs/packaging.md · MIT OR Apache-2.0
        </p>
      </section>
    </div>
  );
}
