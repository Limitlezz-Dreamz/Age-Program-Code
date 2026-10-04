import { useCallback, useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ipc } from "@/ipc/client";
import type { EventRowDto, FieldFilterDto, SavedSearchDto } from "@/ipc/types";
import { useAppStore } from "@/stores/app-store";
import { formatTsMicros } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { EventDetailScreen } from "@/screens/EventDetailScreen";

const OPS = ["equals", "contains", "starts", "ends", "in", "exists", "regex"] as const;

export function ExplorerScreen() {
  const caseInfo = useAppStore((s) => s.caseInfo);
  const filter = useAppStore((s) => s.filter);
  const setScreen = useAppStore((s) => s.setScreen);
  const settings = useAppStore((s) => s.settings);
  const useUtc = settings?.use_utc !== false;

  const [fts, setFts] = useState(filter.text ?? "");
  const [fieldFilters, setFieldFilters] = useState<FieldFilterDto[]>([]);
  const [draft, setDraft] = useState<FieldFilterDto>({
    field: "CommandLine",
    op: "contains",
    value: "",
  });
  const [rows, setRows] = useState<EventRowDto[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [eventId, setEventId] = useState<number | null>(null);
  const [saved, setSaved] = useState<SavedSearchDto[]>([]);
  const [saveName, setSaveName] = useState("");
  const parentRef = useRef<HTMLDivElement>(null);

  const refreshSaved = useCallback(async () => {
    if (!caseInfo) return;
    try {
      setSaved(await ipc.listSavedSearches());
    } catch {
      /* ignore until case ready */
    }
  }, [caseInfo]);

  const search = useCallback(
    async (offset = 0, append = false) => {
      if (!caseInfo) return;
      setLoading(true);
      setError(null);
      try {
        const page = await ipc.queryEvents(
          {
            offset,
            limit: 200,
            sort_col: "ts",
            sort_dir: "asc",
            event_ids: [],
            computers: [],
            channels: [],
            users: [],
            src_ips: [],
            text: fts || null,
            field_filters: fieldFilters,
            time_from: null,
            time_to: null,
          },
          filter,
        );
        setRows((prev) => (append ? [...prev, ...page.rows] : page.rows));
        setTotal(page.total);
      } catch (e) {
        setError(String(e));
      } finally {
        setLoading(false);
      }
    },
    [caseInfo, fts, fieldFilters, filter],
  );

  useEffect(() => {
    void search(0, false);
    void refreshSaved();
  }, [search, refreshSaved]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 40,
    overscan: 12,
  });

  const virtualItems = virtualizer.getVirtualItems();
  useEffect(() => {
    const last = virtualItems[virtualItems.length - 1];
    if (last && last.index >= rows.length - 20 && rows.length < total && !loading) {
      void search(rows.length, true);
    }
  }, [virtualItems, rows.length, total, loading, search]);

  async function handleSave() {
    if (!saveName.trim()) return;
    try {
      await ipc.saveSearch(
        saveName.trim(),
        JSON.stringify({ fts, fieldFilters }),
      );
      setSaveName("");
      await refreshSaved();
    } catch (e) {
      setError(String(e));
    }
  }

  async function loadSaved(s: SavedSearchDto) {
    try {
      const parsed = JSON.parse(s.query_json) as {
        fts?: string;
        fieldFilters?: FieldFilterDto[];
      };
      setFts(parsed.fts ?? "");
      setFieldFilters(parsed.fieldFilters ?? []);
    } catch (e) {
      setError(String(e));
    }
  }

  if (!caseInfo) {
    return (
      <div className="mx-auto max-w-lg py-12">
        <h1 className="font-display text-3xl font-semibold tracking-tight">Explorer</h1>
        <p className="mt-2 text-muted-foreground">Open a case to search events.</p>
        <Button className="mt-4" variant="outline" onClick={() => setScreen("case")}>
          Go to Case
        </Button>
      </div>
    );
  }

  return (
    <div className="flex h-[calc(100vh-9rem)] min-h-[24rem] flex-col gap-3">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-display text-3xl font-semibold tracking-tight">Explorer</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {total.toLocaleString()} events · FTS + structured filters
          </p>
        </div>
        <Button variant="ghost" className="h-8 text-xs" onClick={() => void search(0, false)}>
          Search
        </Button>
      </header>

      <section className="flex flex-col gap-2 rounded-md border border-border/70 bg-[hsl(222_22%_11%)]/60 p-3">
        <input
          className="h-9 w-full rounded-md border border-border bg-background/60 px-3 text-sm"
          placeholder="FTS text (e.g. mimikatz)"
          value={fts}
          onChange={(e) => setFts(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void search(0, false);
          }}
          aria-label="FTS search"
        />
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
            Field
            <input
              className="h-8 w-36 rounded-md border border-border bg-background/60 px-2 text-sm text-foreground"
              value={draft.field}
              onChange={(e) => setDraft((d) => ({ ...d, field: e.target.value }))}
            />
          </label>
          <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
            Op
            <select
              className="h-8 rounded-md border border-border bg-background/60 px-2 text-sm text-foreground"
              value={draft.op}
              onChange={(e) => setDraft((d) => ({ ...d, op: e.target.value }))}
            >
              {OPS.map((op) => (
                <option key={op} value={op}>
                  {op}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
            Value
            <input
              className="h-8 w-48 rounded-md border border-border bg-background/60 px-2 text-sm text-foreground"
              value={draft.value}
              onChange={(e) => setDraft((d) => ({ ...d, value: e.target.value }))}
              disabled={draft.op === "exists"}
            />
          </label>
          <Button
            variant="outline"
            className="h-8 text-xs"
            onClick={() => {
              if (!draft.field.trim()) return;
              setFieldFilters((prev) => [...prev, { ...draft }]);
              setDraft((d) => ({ ...d, value: "" }));
            }}
          >
            Add filter
          </Button>
        </div>
        {fieldFilters.length > 0 && (
          <ul className="flex flex-wrap gap-2 text-xs">
            {fieldFilters.map((f, i) => (
              <li
                key={`${f.field}-${i}`}
                className="flex items-center gap-1 rounded border border-border/60 px-2 py-1"
              >
                <span className="font-mono">
                  {f.field} {f.op} {f.op === "exists" ? "" : f.value}
                </span>
                <button
                  type="button"
                  className="text-muted-foreground hover:text-foreground"
                  onClick={() =>
                    setFieldFilters((prev) => prev.filter((_, j) => j !== i))
                  }
                >
                  ×
                </button>
              </li>
            ))}
          </ul>
        )}
        <div className="flex flex-wrap items-center gap-2 border-t border-border/40 pt-2">
          <input
            className="h-8 w-40 rounded-md border border-border bg-background/60 px-2 text-xs"
            placeholder="Save as…"
            value={saveName}
            onChange={(e) => setSaveName(e.target.value)}
          />
          <Button variant="outline" className="h-8 text-xs" onClick={() => void handleSave()}>
            Save search
          </Button>
          {saved.map((s) => (
            <button
              key={s.id}
              type="button"
              className="rounded border border-border/50 px-2 py-1 text-xs hover:bg-muted/40"
              onClick={() => void loadSaved(s)}
              title="Load saved search"
            >
              {s.name}
              <span
                className="ml-2 text-muted-foreground"
                onClick={(e) => {
                  e.stopPropagation();
                  void ipc.deleteSavedSearch(s.id).then(refreshSaved);
                }}
              >
                ×
              </span>
            </button>
          ))}
        </div>
      </section>

      {error && (
        <p className="rounded-md border border-red-900/50 bg-red-950/30 px-3 py-2 text-sm text-red-200">
          {error}
        </p>
      )}

      <div className="flex min-h-0 flex-1 gap-3">
        <div
          ref={parentRef}
          className="min-w-0 flex-1 overflow-auto rounded-md border border-border/70"
          data-testid="explorer-list"
        >
          <div
            className="sticky top-0 z-10 grid grid-cols-[8rem_6rem_5rem_7rem_6rem_6rem_minmax(8rem,1fr)] gap-2 border-b border-border/60 bg-[hsl(222_22%_11%)] px-2 py-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground"
          >
            <span>Time</span>
            <span>Host</span>
            <span>EID</span>
            <span>Channel</span>
            <span>User</span>
            <span>Src IP</span>
            <span>Summary</span>
          </div>
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((vi) => {
              const r = rows[vi.index];
              if (!r) return null;
              return (
                <button
                  key={r.id}
                  type="button"
                  className="absolute left-0 top-0 grid w-full grid-cols-[8rem_6rem_5rem_7rem_6rem_6rem_minmax(8rem,1fr)] gap-2 border-b border-border/30 px-2 py-2 text-left text-xs hover:bg-muted/30"
                  style={{ transform: `translateY(${vi.start}px)` }}
                  onClick={() => setEventId(r.id)}
                >
                  <span className="truncate font-mono text-muted-foreground">
                    {formatTsMicros(r.ts, useUtc)}
                  </span>
                  <span className="truncate">{r.computer}</span>
                  <span className="font-mono">{r.event_id}</span>
                  <span className="truncate text-muted-foreground">{r.channel}</span>
                  <span className="truncate">{r.user_name ?? "—"}</span>
                  <span className="truncate font-mono">{r.src_ip ?? "—"}</span>
                  <span className="truncate text-muted-foreground" title={r.summary ?? ""}>
                    {r.summary ?? ""}
                  </span>
                </button>
              );
            })}
          </div>
          {loading && (
            <p className="px-3 py-2 text-xs text-muted-foreground">Loading…</p>
          )}
        </div>
        {eventId != null && (
          <aside className="w-[26rem] shrink-0 overflow-hidden rounded-md border border-border/70 bg-[hsl(222_22%_10%)]/90 p-3">
            <EventDetailScreen eventId={eventId} onClose={() => setEventId(null)} />
          </aside>
        )}
      </div>
    </div>
  );
}
