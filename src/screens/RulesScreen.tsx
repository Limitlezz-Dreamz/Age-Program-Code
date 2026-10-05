import { useCallback, useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { ipc } from "@/ipc/client";
import type { RuleDetailDto, RulePackDto, RuleRowDto, SuppressionDto } from "@/ipc/types";
import { useAppStore } from "@/stores/app-store";
import { Button } from "@/components/ui/button";

export function RulesScreen() {
  const caseInfo = useAppStore((s) => s.caseInfo);
  const setScreen = useAppStore((s) => s.setScreen);
  const settings = useAppStore((s) => s.settings);

  const [packs, setPacks] = useState<RulePackDto[]>([]);
  const [rules, setRules] = useState<RuleRowDto[]>([]);
  const [total, setTotal] = useState(0);
  const [text, setText] = useState("");
  const [detail, setDetail] = useState<RuleDetailDto | null>(null);
  const [suppressions, setSuppressions] = useState<SuppressionDto[]>([]);
  const [profile, setProfile] = useState(settings?.rule_profile ?? "default");
  const [builtins, setBuiltins] = useState(settings?.builtins_default ?? true);
  const [drl, setDrl] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [suppField, setSuppField] = useState("summary");
  const [suppValue, setSuppValue] = useState("");
  const [enabledFilter, setEnabledFilter] = useState<"all" | "enabled" | "disabled">(
    "all",
  );

  const refresh = useCallback(async () => {
    setError(null);
    try {
      setPacks(await ipc.listRulePacks());
      setDrl(await ipc.drlNotice());
      if (caseInfo) {
        const page = await ipc.listRules({
          offset: 0,
          limit: 500,
          text: text || null,
          enabled_only:
            enabledFilter === "all" ? null : enabledFilter === "enabled",
        });
        setRules(page.rows);
        setTotal(page.total);
        setSuppressions(await ipc.listSuppressions());
      }
    } catch (e) {
      setError(String(e));
    }
  }, [caseInfo, text, enabledFilter]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function handleImport() {
    const selected = await open({
      directory: true,
      multiple: false,
      title: "Import Sigma pack directory",
    });
    if (!selected || Array.isArray(selected)) return;
    setBusy(true);
    try {
      const pack = await ipc.importRulePack(selected, "local");
      setMsg(`Imported ${pack.id}@${pack.version} (${pack.rule_count} rules)`);
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleDownload(kind: string) {
    setBusy(true);
    setMsg(`Downloading ${kind}…`);
    try {
      const pack = await ipc.downloadRulePack(kind);
      setMsg(`Downloaded ${pack.id}@${pack.version} (${pack.rule_count} rules)`);
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function toggleEnabled(r: RuleRowDto) {
    if (!caseInfo) return;
    try {
      await ipc.setRuleEnabled(r.rule_uid, !r.enabled);
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  }

  async function handleRerun() {
    if (!caseInfo) return;
    setBusy(true);
    setMsg("Re-running detection…");
    try {
      const report = await ipc.rerunDetection(profile, builtins, null);
      setMsg(
        `Hunt done: ${report.detections} detections · ${report.events_scanned} events · ${report.elapsed_ms}ms`,
      );
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function addSupp() {
    if (!caseInfo || !suppValue.trim()) return;
    try {
      await ipc.addSuppression({
        rule_uid: detail?.rule.rule_uid ?? null,
        field: suppField,
        value: suppValue.trim(),
        note: null,
      });
      setSuppValue("");
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-display text-3xl font-semibold tracking-tight">Rules</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Packs, enable/disable, suppressions, re-run · {total.toLocaleString()} rules in case
          </p>
        </div>
        <Button variant="ghost" className="h-8 text-xs" onClick={() => void refresh()}>
          Refresh
        </Button>
      </header>

      {error && (
        <p className="rounded-md border border-red-900/50 bg-red-950/30 px-3 py-2 text-sm text-red-200">
          {error}
        </p>
      )}
      {msg && <p className="text-sm text-muted-foreground">{msg}</p>}

      <section className="space-y-3 rounded-md border border-border/70 p-3">
        <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Packs
        </h2>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" disabled={busy} onClick={() => void handleImport()}>
            Import folder…
          </Button>
          <Button variant="outline" disabled={busy} onClick={() => void handleDownload("core")}>
            Download Sigma core
          </Button>
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => void handleDownload("emerging")}
          >
            Download emerging
          </Button>
        </div>
        {packs.length === 0 ? (
          <p className="text-sm text-muted-foreground">No packs installed yet.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {packs.map((p) => (
              <li
                key={`${p.id}-${p.version}`}
                className="flex flex-wrap justify-between gap-2 border-b border-border/40 py-1.5"
              >
                <span>
                  <span className="font-medium">{p.id}</span>@{p.version} · {p.rule_count} rules
                </span>
                <span className="truncate text-xs text-muted-foreground">{p.path}</span>
              </li>
            ))}
          </ul>
        )}
        <p className="whitespace-pre-wrap rounded-md border border-border/50 bg-muted/20 p-2 text-xs text-muted-foreground">
          {drl || "DRL notice loads from backend."}
        </p>
      </section>

      <section className="space-y-3 rounded-md border border-border/70 p-3">
        <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Re-run detection
        </h2>
        {!caseInfo ? (
          <p className="text-sm text-muted-foreground">
            Open a case to re-run.{" "}
            <button type="button" className="underline" onClick={() => setScreen("case")}>
              Case
            </button>
          </p>
        ) : (
          <div className="flex flex-wrap items-end gap-2">
            <label className="flex flex-col gap-1 text-xs text-muted-foreground">
              Profile
              <select
                className="h-8 rounded-md border border-border bg-background/60 px-2 text-sm text-foreground"
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
              >
                <option value="default">Default</option>
                <option value="all">All</option>
                <option value="high">High + Critical</option>
              </select>
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={builtins}
                onChange={(e) => setBuiltins(e.target.checked)}
              />
              Built-ins
            </label>
            <Button disabled={busy} onClick={() => void handleRerun()}>
              Re-run detection
            </Button>
          </div>
        )}
      </section>

      <div className="flex min-h-[20rem] gap-3">
        <section className="min-w-0 flex-1 space-y-2">
          <div className="flex flex-wrap gap-2">
            <input
              className="h-8 min-w-[12rem] flex-1 rounded-md border border-border bg-background/60 px-2 text-sm"
              placeholder="Filter rules…"
              value={text}
              onChange={(e) => setText(e.target.value)}
            />
            <select
              className="h-8 rounded-md border border-border bg-background/60 px-2 text-sm text-foreground"
              value={enabledFilter}
              onChange={(e) =>
                setEnabledFilter(e.target.value as "all" | "enabled" | "disabled")
              }
              aria-label="Enabled filter"
            >
              <option value="all">All rules</option>
              <option value="enabled">Enabled only</option>
              <option value="disabled">Disabled only</option>
            </select>
          </div>
          <div className="max-h-[28rem] overflow-auto rounded-md border border-border/70">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 bg-muted/40 text-xs uppercase tracking-wide text-muted-foreground">
                <tr>
                  <th className="px-2 py-1.5">On</th>
                  <th className="px-2 py-1.5">Title</th>
                  <th className="px-2 py-1.5">Level</th>
                  <th className="px-2 py-1.5">Author</th>
                  <th className="px-2 py-1.5">Hits</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr
                    key={r.rule_uid}
                    className="cursor-pointer border-t border-border/40 hover:bg-muted/30"
                    onClick={() => void ipc.getRule(r.rule_uid).then(setDetail).catch((e) => setError(String(e)))}
                  >
                    <td className="px-2 py-1.5" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={r.enabled}
                        onChange={() => void toggleEnabled(r)}
                        aria-label={`Enable ${r.title}`}
                      />
                    </td>
                    <td className="px-2 py-1.5">
                      {r.title}
                      {r.unmapped && (
                        <span className="ml-1 text-[10px] text-amber-300">unmapped</span>
                      )}
                    </td>
                    <td className="px-2 py-1.5 capitalize">{r.level ?? "—"}</td>
                    <td className="px-2 py-1.5 text-muted-foreground">{r.author ?? "—"}</td>
                    <td className="px-2 py-1.5 font-mono">{r.hit_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <aside className="w-[22rem] shrink-0 space-y-3 rounded-md border border-border/70 p-3">
          <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Detail
          </h2>
          {!detail ? (
            <p className="text-sm text-muted-foreground">Select a rule</p>
          ) : (
            <>
              <p className="font-medium">{detail.rule.title}</p>
              <p className="font-mono text-[11px] text-muted-foreground">{detail.rule.rule_uid}</p>
              <p className="text-xs">Author: {detail.rule.author ?? "(none)"}</p>
              <pre className="max-h-64 overflow-auto rounded border border-border/50 bg-muted/20 p-2 font-mono text-[11px] whitespace-pre-wrap">
                {detail.yaml || "(no yaml stored)"}
              </pre>
            </>
          )}

          <h2 className="pt-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Suppressions
          </h2>
          <div className="flex flex-wrap gap-1">
            <select
              className="h-8 rounded-md border border-border bg-background/60 px-2 text-xs"
              value={suppField}
              onChange={(e) => setSuppField(e.target.value)}
            >
              <option value="summary">summary</option>
              <option value="computer">computer</option>
              <option value="user">user</option>
            </select>
            <input
              className="h-8 min-w-0 flex-1 rounded-md border border-border bg-background/60 px-2 text-xs"
              placeholder="value"
              value={suppValue}
              onChange={(e) => setSuppValue(e.target.value)}
            />
            <Button variant="outline" className="h-8 text-xs" onClick={() => void addSupp()}>
              Add
            </Button>
          </div>
          <ul className="max-h-40 space-y-1 overflow-auto text-xs">
            {suppressions.map((s) => (
              <li
                key={s.id}
                className="flex items-start justify-between gap-2 border-b border-border/40 py-1"
              >
                <span>
                  {s.rule_uid ? `${s.rule_uid} · ` : ""}
                  {s.field}={s.value}
                </span>
                <button
                  type="button"
                  className="text-muted-foreground hover:text-foreground"
                  onClick={() =>
                    void ipc.deleteSuppression(s.id).then(refresh).catch((e) => setError(String(e)))
                  }
                >
                  ×
                </button>
              </li>
            ))}
          </ul>
        </aside>
      </div>
    </div>
  );
}
