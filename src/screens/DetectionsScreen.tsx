import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type MouseEvent,
} from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ipc } from "@/ipc/client";
import type {
  DetectionDetailDto,
  DetectionQueryDto,
  DetectionRowDto,
  GlobalFilter,
} from "@/ipc/types";
import { useAppStore } from "@/stores/app-store";
import { formatTsMicros } from "@/lib/format";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Button } from "@/components/ui/button";
import { EventDetailScreen } from "@/screens/EventDetailScreen";
import { cn } from "@/lib/utils";

type GroupBy = "none" | "rule" | "computer" | "user" | "tactic";
type MenuState = {
  x: number;
  y: number;
  field: string;
  value: string;
} | null;

const PAGE = 200;

export function DetectionsScreen() {
  const caseInfo = useAppStore((s) => s.caseInfo);
  const filter = useAppStore((s) => s.filter);
  const setFilter = useAppStore((s) => s.setFilter);
  const setScreen = useAppStore((s) => s.setScreen);
  const settings = useAppStore((s) => s.settings);
  const useUtc = settings?.use_utc !== false;

  const [rows, setRows] = useState<DetectionRowDto[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sortCol, setSortCol] = useState("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [focusIdx, setFocusIdx] = useState(0);
  const [detail, setDetail] = useState<DetectionDetailDto | null>(null);
  const [eventId, setEventId] = useState<number | null>(null);
  const [groupBy, setGroupBy] = useState<GroupBy>("none");
  const [showAuthor, setShowAuthor] = useState(true);
  const [menu, setMenu] = useState<MenuState>(null);
  const parentRef = useRef<HTMLDivElement>(null);

  const buildQuery = useCallback(
    (offset: number): DetectionQueryDto => ({
      offset,
      limit: PAGE,
      sort_col: sortCol,
      sort_dir: sortDir,
      severities: [],
      computers: [],
      users: [],
      triage: [],
      text: null,
      rule_uid: null,
      time_from: null,
      time_to: null,
      mitre_tactic: null,
    }),
    [sortCol, sortDir],
  );

  const reload = useCallback(async () => {
    if (!caseInfo) {
      setRows([]);
      setTotal(0);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const page = await ipc.queryDetections(buildQuery(0), filter);
      setRows(page.rows);
      setTotal(page.total);
      setFocusIdx(0);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [caseInfo, buildQuery, filter]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const loadMore = useCallback(async () => {
    if (!caseInfo || loading || rows.length >= total) return;
    setLoading(true);
    try {
      const page = await ipc.queryDetections(buildQuery(rows.length), filter);
      setRows((prev) => [...prev, ...page.rows]);
      setTotal(page.total);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [caseInfo, loading, rows.length, total, buildQuery, filter]);

  const openDetail = useCallback(async (id: number) => {
    try {
      setDetail(await ipc.getDetection(id));
      setEventId(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  const toggleSelect = (id: number, additive: boolean) => {
    setSelected((prev) => {
      const next = additive ? new Set(prev) : new Set<number>();
      if (next.has(id) && additive) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const applyTriage = async (state: string) => {
    const ids = selected.size
      ? Array.from(selected)
      : detail
        ? [detail.detection.id]
        : [];
    if (!ids.length) return;
    try {
      await ipc.setTriage({ detection_ids: ids, state, note: null });
      await reload();
      if (detail && ids.includes(detail.detection.id)) {
        setDetail(await ipc.getDetection(detail.detection.id));
      }
    } catch (e) {
      setError(String(e));
    }
  };

  const displayRows = useMemo(() => {
    if (groupBy === "none") return rows.map((r) => ({ type: "row" as const, row: r }));
    const map = new Map<string, DetectionRowDto[]>();
    for (const r of rows) {
      let key = "(none)";
      if (groupBy === "rule") key = r.rule_title;
      else if (groupBy === "computer") key = r.computer || "(none)";
      else if (groupBy === "user") key = r.user || "(none)";
      else if (groupBy === "tactic") {
        key = r.mitre.map((m) => m.tactic).filter(Boolean).join(", ") || "(none)";
      }
      const list = map.get(key) ?? [];
      list.push(r);
      map.set(key, list);
    }
    const out: Array<
      | { type: "group"; key: string; count: number }
      | { type: "row"; row: DetectionRowDto }
    > = [];
    for (const [key, list] of map) {
      out.push({ type: "group", key, count: list.length });
      for (const r of list) out.push({ type: "row", row: r });
    }
    return out;
  }, [rows, groupBy]);

  const virtualizer = useVirtualizer({
    count: displayRows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 40,
    overscan: 12,
  });

  useEffect(() => {
    const items = virtualizer.getVirtualItems();
    const last = items[items.length - 1];
    if (last && last.index >= displayRows.length - 20) {
      void loadMore();
    }
  }, [virtualizer.getVirtualItems(), displayRows.length, loadMore, virtualizer]);

  const onKeyDown = (e: KeyboardEvent) => {
    if (!rows.length) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setFocusIdx((i) => Math.min(rows.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setFocusIdx((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const row = rows[focusIdx];
      if (row) void openDetail(row.id);
    } else if (e.key === "Escape") {
      setDetail(null);
      setEventId(null);
      setMenu(null);
    }
  };

  const openMenu = (e: MouseEvent, field: string, value: string) => {
    e.preventDefault();
    setMenu({ x: e.clientX, y: e.clientY, field, value });
  };

  const applyMenu = (mode: "in" | "out") => {
    if (!menu) return;
    const patch: Partial<GlobalFilter> = {};
    if (menu.field === "computer") {
      patch.computers = mode === "in" ? [menu.value] : filter.computers.filter((c) => c !== menu.value);
      if (mode === "out" && !filter.computers.length) {
        /* filter-out without prior filter: set text negation via empty — skip */
      }
    } else if (menu.field === "user") {
      patch.users = mode === "in" ? [menu.value] : [];
    } else if (menu.field === "severity") {
      patch.severities = mode === "in" ? [menu.value] : [];
    } else if (menu.field === "triage") {
      patch.triage = mode === "in" ? [menu.value] : [];
    } else if (menu.field === "rule") {
      patch.text = mode === "in" ? menu.value : null;
    } else {
      patch.text = mode === "in" ? menu.value : null;
    }
    setFilter(patch);
    setMenu(null);
  };

  if (!caseInfo) {
    return (
      <div className="mx-auto max-w-lg py-12">
        <h1 className="font-display text-3xl font-semibold tracking-tight">Detections</h1>
        <p className="mt-2 text-muted-foreground">Open a case and run analysis first.</p>
        <Button className="mt-4" variant="outline" onClick={() => setScreen("case")}>
          Go to Case
        </Button>
      </div>
    );
  }

  return (
    <div className="flex h-[calc(100vh-9rem)] min-h-[24rem] flex-col gap-3" onKeyDown={onKeyDown} tabIndex={0}>
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-display text-3xl font-semibold tracking-tight">Detections</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {total.toLocaleString()} total
            {loading ? " · loading…" : ""}
            {selected.size ? ` · ${selected.size} selected` : ""}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
            Group
            <select
              className="h-8 rounded-md border border-border bg-background/60 px-2"
              value={groupBy}
              onChange={(e) => setGroupBy(e.target.value as GroupBy)}
            >
              <option value="none">None</option>
              <option value="rule">Rule</option>
              <option value="computer">Computer</option>
              <option value="user">User</option>
              <option value="tactic">Tactic</option>
            </select>
          </label>
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={showAuthor}
              onChange={(e) => setShowAuthor(e.target.checked)}
            />
            Author
          </label>
          <Button variant="outline" className="h-8 text-xs" onClick={() => void applyTriage("reviewed")}>
            Reviewed
          </Button>
          <Button variant="outline" className="h-8 text-xs" onClick={() => void applyTriage("false_positive")}>
            FP
          </Button>
          <Button variant="outline" className="h-8 text-xs" onClick={() => void applyTriage("escalated")}>
            Escalate
          </Button>
          <Button variant="ghost" className="h-8 text-xs" onClick={() => void reload()}>
            Refresh
          </Button>
        </div>
      </header>

      {error && (
        <p className="rounded-md border border-red-900/50 bg-red-950/30 px-3 py-2 text-sm text-red-200">
          {error}
        </p>
      )}

      <div className="flex min-h-0 flex-1 gap-3">
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden rounded-md border border-border/70">
          <div className="grid grid-cols-[1.6rem_7.5rem_4.5rem_minmax(8rem,1.4fr)_7rem_6rem_minmax(8rem,1.6fr)_4rem_5rem] gap-2 border-b border-border/60 bg-[hsl(222_22%_11%)] px-2 py-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
            <span />
            <SortBtn col="ts" label="Time" sortCol={sortCol} sortDir={sortDir} setSortCol={setSortCol} setSortDir={setSortDir} />
            <SortBtn col="severity" label="Sev" sortCol={sortCol} sortDir={sortDir} setSortCol={setSortCol} setSortDir={setSortDir} />
            <SortBtn col="rule" label="Rule" sortCol={sortCol} sortDir={sortDir} setSortCol={setSortCol} setSortDir={setSortDir} />
            <SortBtn col="computer" label="Host" sortCol={sortCol} sortDir={sortDir} setSortCol={setSortCol} setSortDir={setSortDir} />
            <SortBtn col="user" label="User" sortCol={sortCol} sortDir={sortDir} setSortCol={setSortCol} setSortDir={setSortDir} />
            <span>Summary</span>
            <SortBtn col="count" label="Cnt" sortCol={sortCol} sortDir={sortDir} setSortCol={setSortCol} setSortDir={setSortDir} />
            <SortBtn col="triage" label="Triage" sortCol={sortCol} sortDir={sortDir} setSortCol={setSortCol} setSortDir={setSortDir} />
          </div>
          <div ref={parentRef} className="min-h-0 flex-1 overflow-auto" data-testid="detections-list">
            <div
              style={{ height: virtualizer.getTotalSize(), position: "relative" }}
            >
              {virtualizer.getVirtualItems().map((vi) => {
                const item = displayRows[vi.index];
                if (!item) return null;
                if (item.type === "group") {
                  return (
                    <div
                      key={`g-${item.key}-${vi.index}`}
                      className="absolute left-0 top-0 w-full border-b border-border/40 bg-muted/30 px-3 py-2 text-xs font-medium"
                      style={{ transform: `translateY(${vi.start}px)` }}
                    >
                      {item.key}{" "}
                      <span className="text-muted-foreground">({item.count})</span>
                    </div>
                  );
                }
                const r = item.row;
                const rowIdx = rows.findIndex((x) => x.id === r.id);
                const focused = rowIdx === focusIdx;
                const isSel = selected.has(r.id);
                return (
                  <div
                    key={r.id}
                    role="row"
                    aria-selected={focused}
                    className={cn(
                      "absolute left-0 top-0 grid w-full cursor-pointer grid-cols-[1.6rem_7.5rem_4.5rem_minmax(8rem,1.4fr)_7rem_6rem_minmax(8rem,1.6fr)_4rem_5rem] gap-2 border-b border-border/30 px-2 py-2 text-xs",
                      focused || isSel ? "bg-primary/10" : "hover:bg-muted/30",
                    )}
                    style={{ transform: `translateY(${vi.start}px)` }}
                    onClick={(e) => {
                      setFocusIdx(rowIdx);
                      toggleSelect(r.id, e.metaKey || e.ctrlKey || e.shiftKey);
                      void openDetail(r.id);
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={isSel}
                      onChange={() => toggleSelect(r.id, true)}
                      onClick={(e) => e.stopPropagation()}
                      aria-label={`Select detection ${r.id}`}
                    />
                    <span
                      className="truncate font-mono text-muted-foreground"
                      onContextMenu={(e) =>
                        openMenu(e, "time", formatTsMicros(r.ts, useUtc))
                      }
                    >
                      {formatTsMicros(r.ts, useUtc)}
                    </span>
                    <span onContextMenu={(e) => openMenu(e, "severity", r.severity)}>
                      <SeverityBadge severity={r.severity} />
                    </span>
                    <span
                      className="truncate"
                      title={showAuthor && r.rule_author ? `${r.rule_title} — ${r.rule_author}` : r.rule_title}
                      onContextMenu={(e) => openMenu(e, "rule", r.rule_title)}
                    >
                      {r.rule_title}
                      {showAuthor && r.rule_author ? (
                        <span className="ml-1 text-[10px] text-muted-foreground">
                          · {r.rule_author}
                        </span>
                      ) : null}
                    </span>
                    <span
                      className="truncate"
                      onContextMenu={(e) => openMenu(e, "computer", r.computer)}
                    >
                      {r.computer}
                    </span>
                    <span
                      className="truncate"
                      onContextMenu={(e) => openMenu(e, "user", r.user ?? "")}
                    >
                      {r.user ?? "—"}
                    </span>
                    <span className="truncate text-muted-foreground" title={r.summary}>
                      {r.summary}
                      {r.mitre.length > 0 && (
                        <span className="ml-1 text-[10px] text-primary/80">
                          {r.mitre
                            .map((m) => m.technique || m.tactic)
                            .filter(Boolean)
                            .slice(0, 2)
                            .join(" ")}
                        </span>
                      )}
                    </span>
                    <span className="font-mono tabular-nums">{r.event_count}</span>
                    <span
                      className="truncate capitalize text-muted-foreground"
                      onContextMenu={(e) => openMenu(e, "triage", r.triage)}
                    >
                      {r.triage.replace("_", " ")}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {(detail || eventId != null) && (
          <aside className="flex w-[26rem] shrink-0 flex-col overflow-hidden rounded-md border border-border/70 bg-[hsl(222_22%_10%)]/90 p-3">
            {eventId != null ? (
              <EventDetailScreen
                eventId={eventId}
                onClose={() => setEventId(null)}
                onOpenDetection={(id) => void openDetail(id)}
              />
            ) : detail ? (
              <DetectionDrawer
                detail={detail}
                useUtc={useUtc}
                onClose={() => setDetail(null)}
                onOpenEvent={(id) => setEventId(id)}
                onTriage={(state) => void applyTriage(state)}
              />
            ) : null}
          </aside>
        )}
      </div>

      {menu && (
        <div
          className="fixed z-50 min-w-[10rem] rounded-md border border-border bg-[hsl(222_24%_12%)] py-1 text-xs shadow-lg"
          style={{ left: menu.x, top: menu.y }}
          role="menu"
        >
          <button
            type="button"
            className="block w-full px-3 py-1.5 text-left hover:bg-muted/60"
            onClick={() => applyMenu("in")}
          >
            Filter in “{menu.value.slice(0, 40)}”
          </button>
          <button
            type="button"
            className="block w-full px-3 py-1.5 text-left hover:bg-muted/60"
            onClick={() => applyMenu("out")}
          >
            Clear / filter out
          </button>
          <button
            type="button"
            className="block w-full px-3 py-1.5 text-left hover:bg-muted/60"
            onClick={() => setMenu(null)}
          >
            Cancel
          </button>
        </div>
      )}
    </div>
  );
}

function SortBtn({
  col,
  label,
  sortCol,
  sortDir,
  setSortCol,
  setSortDir,
}: {
  col: string;
  label: string;
  sortCol: string;
  sortDir: string;
  setSortCol: (c: string) => void;
  setSortDir: (d: "asc" | "desc") => void;
}) {
  const active = sortCol === col;
  return (
    <button
      type="button"
      className={cn("text-left", active && "text-foreground")}
      onClick={() => {
        if (active) setSortDir(sortDir === "asc" ? "desc" : "asc");
        else {
          setSortCol(col);
          setSortDir(col === "ts" ? "asc" : "desc");
        }
      }}
    >
      {label}
      {active ? (sortDir === "asc" ? " ↑" : " ↓") : ""}
    </button>
  );
}

function DetectionDrawer({
  detail,
  useUtc,
  onClose,
  onOpenEvent,
  onTriage,
}: {
  detail: DetectionDetailDto;
  useUtc: boolean;
  onClose: () => void;
  onOpenEvent: (id: number) => void;
  onTriage: (state: string) => void;
}) {
  const d = detail.detection;
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-auto">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <SeverityBadge severity={d.severity} />
          <h2 className="mt-2 font-display text-lg font-semibold leading-snug">
            {d.rule_title}
          </h2>
          <p className="mt-1 font-mono text-[11px] text-muted-foreground">{d.rule_uid}</p>
        </div>
        <Button variant="ghost" className="h-8 px-2 text-xs" onClick={onClose}>
          Close
        </Button>
      </div>

      <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
        <div>
          <dt className="text-muted-foreground">Author</dt>
          <dd>{d.rule_author ?? "(none)"}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Status</dt>
          <dd>{d.status ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Source</dt>
          <dd className="capitalize">{d.rule_source.kind}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Triage</dt>
          <dd className="capitalize">{d.triage.replace("_", " ")}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Time</dt>
          <dd className="font-mono">{formatTsMicros(d.ts, useUtc)}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Host / user</dt>
          <dd>
            {d.computer}
            {d.user ? ` / ${d.user}` : ""}
          </dd>
        </div>
      </dl>

      <p className="text-sm whitespace-pre-wrap break-words">{d.summary}</p>

      {d.fp_hint && (
        <p className="rounded-md border border-border/60 bg-muted/30 px-2 py-1.5 text-xs text-muted-foreground">
          FP note: {d.fp_hint}
        </p>
      )}

      {d.mitre.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {d.mitre.map((m, i) => (
            <span
              key={i}
              className="rounded border border-border/60 px-1.5 py-0.5 text-[11px] text-muted-foreground"
            >
              {[m.tactic, m.technique, m.name].filter(Boolean).join(" · ")}
            </span>
          ))}
        </div>
      )}

      {detail.group_json && (
        <pre className="overflow-auto rounded-md border border-border/50 bg-muted/20 p-2 font-mono text-[11px]">
          {detail.group_json}
        </pre>
      )}

      <div className="flex flex-wrap gap-1">
        <Button variant="outline" className="h-7 text-xs" onClick={() => onTriage("reviewed")}>
          Reviewed
        </Button>
        <Button variant="outline" className="h-7 text-xs" onClick={() => onTriage("false_positive")}>
          False positive
        </Button>
        <Button variant="outline" className="h-7 text-xs" onClick={() => onTriage("escalated")}>
          Escalate
        </Button>
        <Button variant="ghost" className="h-7 text-xs" onClick={() => onTriage("new")}>
          Reset
        </Button>
      </div>

      <div>
        <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Linked events ({detail.linked_events.length})
        </h3>
        <ul className="space-y-1">
          {detail.linked_events.map((e) => (
            <li key={e.id}>
              <button
                type="button"
                className="w-full rounded-md px-2 py-1.5 text-left text-xs hover:bg-muted/50"
                onClick={() => onOpenEvent(e.id)}
              >
                <span className="font-mono text-muted-foreground">
                  {formatTsMicros(e.ts, useUtc)}
                </span>{" "}
                <span className="font-medium">EID {e.event_id}</span>{" "}
                <span className="text-muted-foreground">{e.channel}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
