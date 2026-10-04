import { useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { ipc } from "@/ipc/client";
import { useAppStore } from "@/stores/app-store";
import { Button } from "@/components/ui/button";

const FORMATS = [
  { id: "csv", label: "CSV", ext: "csv" },
  { id: "json", label: "JSON", ext: "json" },
  { id: "jsonl", label: "JSONL", ext: "jsonl" },
  { id: "html", label: "HTML report", ext: "html" },
] as const;

export function ExportScreen() {
  const caseInfo = useAppStore((s) => s.caseInfo);
  const setScreen = useAppStore((s) => s.setScreen);
  const [format, setFormat] = useState<(typeof FORMATS)[number]["id"]>("csv");
  const [limit, setLimit] = useState(100_000);
  const [busy, setBusy] = useState(false);
  const [resultPath, setResultPath] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleExport() {
    if (!caseInfo) return;
    setBusy(true);
    setError(null);
    setMsg(null);
    try {
      const fmt = FORMATS.find((f) => f.id === format)!;
      const path = await save({
        title: "Export detections",
        defaultPath: `${caseInfo.name}-detections.${fmt.ext}`,
        filters: [{ name: fmt.label, extensions: [fmt.ext] }],
      });
      if (!path) {
        setBusy(false);
        return;
      }
      const res = await ipc.exportDetections({
        path,
        format,
        limit,
      });
      setResultPath(res.path);
      setMsg(`Exported ${res.rows.toLocaleString()} rows → ${res.path}`);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!caseInfo) {
    return (
      <div className="mx-auto max-w-lg py-12">
        <h1 className="font-display text-3xl font-semibold tracking-tight">Export</h1>
        <p className="mt-2 text-muted-foreground">Open a case to export detections.</p>
        <Button className="mt-4" variant="outline" onClick={() => setScreen("case")}>
          Go to Case
        </Button>
      </div>
    );
  }

  return (
    <div className="mx-auto flex max-w-xl flex-col gap-6">
      <header>
        <h1 className="font-display text-3xl font-semibold tracking-tight">Export</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          CSV / JSON / JSONL / HTML · includes rule author and source · offline HTML with DRL + MITRE notices
        </p>
      </header>

      <section className="space-y-3 rounded-md border border-border/70 p-4">
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">
          Format
          <select
            className="h-9 rounded-md border border-border bg-background/60 px-2 text-sm text-foreground"
            value={format}
            onChange={(e) => setFormat(e.target.value as typeof format)}
          >
            {FORMATS.map((f) => (
              <option key={f.id} value={f.id}>
                {f.label}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">
          Max rows
          <input
            type="number"
            className="h-9 rounded-md border border-border bg-background/60 px-2 text-sm text-foreground"
            value={limit}
            min={1}
            onChange={(e) => setLimit(Number(e.target.value) || 1)}
          />
        </label>
        <Button disabled={busy} onClick={() => void handleExport()}>
          {busy ? "Exporting…" : "Export detections…"}
        </Button>
      </section>

      {error && (
        <p className="rounded-md border border-red-900/50 bg-red-950/30 px-3 py-2 text-sm text-red-200">
          {error}
        </p>
      )}
      {msg && <p className="text-sm text-muted-foreground">{msg}</p>}
      {resultPath && (
        <Button
          variant="outline"
          className="w-fit"
          onClick={() => void revealItemInDir(resultPath)}
        >
          Reveal in folder
        </Button>
      )}
    </div>
  );
}
