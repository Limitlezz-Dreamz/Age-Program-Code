import { useCallback, useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { ipc } from "@/ipc/client";
import { useAppStore } from "@/stores/app-store";
import { Button } from "@/components/ui/button";
import { APP_NAME } from "@/lib/constants";

function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

export function CaseScreen() {
  const caseInfo = useAppStore((s) => s.caseInfo);
  const setCase = useAppStore((s) => s.setCase);
  const recent = useAppStore((s) => s.recent);
  const setRecent = useAppStore((s) => s.setRecent);
  const files = useAppStore((s) => s.files);
  const setFiles = useAppStore((s) => s.setFiles);
  const stats = useAppStore((s) => s.stats);
  const setStats = useAppStore((s) => s.setStats);
  const analysis = useAppStore((s) => s.analysis);
  const beginAnalysis = useAppStore((s) => s.beginAnalysis);
  const applyProgress = useAppStore((s) => s.applyProgress);
  const defaultAnalysisOptions = useAppStore((s) => s.defaultAnalysisOptions);
  const dropActive = useAppStore((s) => s.dropActive);
  const settings = useAppStore((s) => s.settings);

  const [name, setName] = useState("investigation");
  const [profile, setProfile] = useState(settings?.rule_profile ?? "default");
  const [builtins, setBuiltins] = useState(settings?.builtins_default ?? true);
  const [fts, setFts] = useState(settings?.fts_default ?? true);
  const [hash, setHash] = useState(settings?.hash_default ?? true);
  const [detect, setDetect] = useState(settings?.run_detection_default ?? true);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!caseInfo) return;
    try {
      setFiles(await ipc.listFiles());
      setStats(await ipc.caseStats());
    } catch (e) {
      setMsg(String(e));
    }
  }, [caseInfo, setFiles, setStats]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (settings) {
      setProfile(settings.rule_profile);
      setBuiltins(settings.builtins_default);
      setFts(settings.fts_default);
      setHash(settings.hash_default);
      setDetect(settings.run_detection_default);
    }
  }, [settings]);

  async function handleCreate() {
    setBusy(true);
    setMsg(null);
    try {
      const dir = await ipc.defaultCasesDir();
      const info = await ipc.createCase(dir, name.trim() || "case");
      setCase(info);
      setRecent(await ipc.recentCases());
      setFiles([]);
      setStats(null);
      setMsg(`Created ${info.path}`);
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleOpen() {
    setBusy(true);
    setMsg(null);
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: "Open Logwarden case (.lwcase folder)",
      });
      if (!selected || Array.isArray(selected)) {
        setBusy(false);
        return;
      }
      const info = await ipc.openCase(selected);
      setCase(info);
      setRecent(await ipc.recentCases());
      await refresh();
      setMsg(`Opened ${info.path}`);
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function openRecent(path: string) {
    setBusy(true);
    try {
      const info = await ipc.openCase(path);
      setCase(info);
      setRecent(await ipc.recentCases());
      setFiles(await ipc.listFiles());
      setStats(await ipc.caseStats());
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function addPaths(paths: string[]) {
    if (!caseInfo || paths.length === 0) return;
    setBusy(true);
    setMsg(null);
    try {
      const result = await ipc.addInputs(paths);
      setMsg(
        `Queued ${result.files.length} EVTX files (${formatBytes(result.bytes)})`,
      );
      await refresh();
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleAddFiles() {
    const selected = await open({
      multiple: true,
      filters: [{ name: "EVTX", extensions: ["evtx"] }],
      title: "Add EVTX files",
    });
    if (!selected) return;
    const paths = Array.isArray(selected) ? selected : [selected];
    await addPaths(paths);
  }

  async function handleAddFolder() {
    const selected = await open({
      directory: true,
      multiple: false,
      title: "Add folder of EVTX files",
    });
    if (!selected || Array.isArray(selected)) return;
    await addPaths([selected]);
  }

  async function handleStart() {
    if (!caseInfo) return;
    setMsg(null);
    const opts = {
      ...defaultAnalysisOptions(),
      profile,
      builtins,
      build_fts: fts,
      hash_files: hash,
      run_detection: detect,
    };
    try {
      const runId = await ipc.startAnalysis(opts, (msg) => {
        applyProgress(msg);
        if (msg.kind === "finished" || msg.kind === "cancelled" || msg.kind === "failed") {
          void refresh();
        }
      });
      beginAnalysis(runId);
    } catch (e) {
      setMsg(String(e));
    }
  }

  async function handleCancel() {
    await ipc.cancelAnalysis();
  }

  if (!caseInfo) {
    return (
      <div className="mx-auto flex max-w-3xl flex-col gap-8">
        <section className="space-y-3">
          <h1 className="font-display text-4xl font-semibold tracking-tight">
            {APP_NAME}
          </h1>
          <p className="max-w-xl text-muted-foreground">
            Create or open a case, then drop EVTX evidence to parse and hunt offline.
          </p>
        </section>

        <section className="space-y-3 rounded-lg border border-border/70 bg-card/40 p-4">
          <h2 className="text-sm font-medium uppercase tracking-wide text-muted-foreground">
            New case
          </h2>
          <div className="flex flex-wrap gap-2">
            <input
              className="h-10 min-w-[14rem] flex-1 rounded-md border border-border bg-background/70 px-3 text-sm"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Case name"
              aria-label="Case name"
            />
            <Button disabled={busy} onClick={() => void handleCreate()}>
              Create case
            </Button>
            <Button variant="outline" disabled={busy} onClick={() => void handleOpen()}>
              Open case…
            </Button>
          </div>
        </section>

        {recent.length > 0 && (
          <section className="space-y-2">
            <h2 className="text-sm font-medium uppercase tracking-wide text-muted-foreground">
              Recent
            </h2>
            <ul className="divide-y divide-border/60 rounded-lg border border-border/70">
              {recent.map((r) => (
                <li key={r.path}>
                  <button
                    type="button"
                    className="flex w-full flex-col gap-0.5 px-3 py-2.5 text-left hover:bg-muted/40"
                    onClick={() => void openRecent(r.path)}
                  >
                    <span className="text-sm font-medium">{r.name}</span>
                    <span className="truncate text-xs text-muted-foreground">
                      {r.path}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        )}
        {msg && <p className="text-sm text-muted-foreground">{msg}</p>}
      </div>
    );
  }

  const pct =
    analysis.filesTotal > 0
      ? Math.min(100, Math.round((analysis.filesDone / analysis.filesTotal) * 100))
      : analysis.running
        ? 5
        : analysis.phase === "done"
          ? 100
          : 0;

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6">
      <section className="space-y-1">
        <h1 className="font-display text-3xl font-semibold tracking-tight">
          {caseInfo.name}
        </h1>
        <p className="text-sm text-muted-foreground">{caseInfo.path}</p>
        {stats && (
          <p className="text-sm text-muted-foreground">
            {stats.files} files · {stats.events.toLocaleString()} events ·{" "}
            {stats.detections.toLocaleString()} detections
          </p>
        )}
      </section>

      <section
        className={`rounded-lg border border-dashed p-4 transition-colors ${
          dropActive
            ? "border-primary bg-primary/10"
            : "border-border/80 bg-card/30"
        }`}
        data-testid="drop-zone"
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-medium">Evidence</h2>
            <p className="text-xs text-muted-foreground">
              Add files/folders or drag EVTX onto the window
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              disabled={busy || analysis.running}
              onClick={() => void handleAddFiles()}
            >
              Add files…
            </Button>
            <Button
              variant="outline"
              disabled={busy || analysis.running}
              onClick={() => void handleAddFolder()}
            >
              Add folder…
            </Button>
          </div>
        </div>
      </section>

      <section className="space-y-3 rounded-lg border border-border/70 bg-card/30 p-4">
        <h2 className="text-sm font-medium">Analysis options</h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            Rule profile
            <select
              className="h-9 rounded-md border border-border bg-background/70 px-2 text-sm text-foreground"
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              disabled={analysis.running}
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
              disabled={analysis.running}
            />
            Built-in rules
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={detect}
              onChange={(e) => setDetect(e.target.checked)}
              disabled={analysis.running}
            />
            Run detection
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={fts}
              onChange={(e) => setFts(e.target.checked)}
              disabled={analysis.running}
            />
            Build FTS index
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={hash}
              onChange={(e) => setHash(e.target.checked)}
              disabled={analysis.running}
            />
            SHA-256 hashing
          </label>
        </div>
        <div className="flex flex-wrap gap-2">
          {!analysis.running ? (
            <Button disabled={busy} onClick={() => void handleStart()}>
              Start analysis
            </Button>
          ) : (
            <Button variant="outline" onClick={() => void handleCancel()}>
              Cancel
            </Button>
          )}
        </div>
        {(analysis.running || analysis.phase === "done" || analysis.phase === "failed") && (
          <div className="space-y-2">
            <div className="h-2 overflow-hidden rounded-full bg-muted">
              <div
                className="h-full bg-primary transition-all duration-300"
                style={{ width: `${pct}%` }}
              />
            </div>
            <p className="text-xs text-muted-foreground" data-testid="analysis-progress">
              phase={analysis.phase} · files {analysis.filesDone}/{analysis.filesTotal} ·{" "}
              {analysis.events.toLocaleString()} events ·{" "}
              {Math.round(analysis.eventsPerSec)}/s · {analysis.detections} detections
              {analysis.lastError ? ` · ${analysis.lastError}` : ""}
            </p>
          </div>
        )}
      </section>

      <section className="space-y-2">
        <h2 className="text-sm font-medium">Files</h2>
        <div className="overflow-x-auto rounded-lg border border-border/70">
          <table className="w-full min-w-[40rem] text-left text-sm">
            <thead className="bg-muted/40 text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 font-medium">Path</th>
                <th className="px-3 py-2 font-medium">Size</th>
                <th className="px-3 py-2 font-medium">Records</th>
                <th className="px-3 py-2 font-medium">Error</th>
              </tr>
            </thead>
            <tbody>
              {files.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-3 py-6 text-center text-muted-foreground">
                    No files yet
                  </td>
                </tr>
              ) : (
                files.map((f) => (
                  <tr key={f.path} className="border-t border-border/50">
                    <td className="px-3 py-2 capitalize">{f.status}</td>
                    <td className="max-w-md truncate px-3 py-2 font-mono text-xs">
                      {f.path}
                    </td>
                    <td className="px-3 py-2">{f.size ? formatBytes(f.size) : "—"}</td>
                    <td className="px-3 py-2">
                      {f.records_ok}
                      {f.records_err ? ` / err ${f.records_err}` : ""}
                    </td>
                    <td className="max-w-xs truncate px-3 py-2 text-xs text-red-300/90">
                      {f.error ?? ""}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
      {msg && <p className="text-sm text-muted-foreground">{msg}</p>}
    </div>
  );
}
