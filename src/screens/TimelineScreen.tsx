import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ipc } from "@/ipc/client";
import type { HistogramBucketDto, TimelineItemDto } from "@/ipc/types";
import { useAppStore } from "@/stores/app-store";
import { formatTsMicros } from "@/lib/format";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const SEV_COLORS: Record<string, string> = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#38bdf8",
  informational: "#94a3b8",
};

export function TimelineScreen() {
  const caseInfo = useAppStore((s) => s.caseInfo);
  const filter = useAppStore((s) => s.filter);
  const setFilter = useAppStore((s) => s.setFilter);
  const setScreen = useAppStore((s) => s.setScreen);
  const settings = useAppStore((s) => s.settings);
  const useUtc = settings?.use_utc !== false;

  const [buckets, setBuckets] = useState<HistogramBucketDto[]>([]);
  const [rows, setRows] = useState<TimelineItemDto[]>([]);
  const [total, setTotal] = useState(0);
  const [includeEvents, setIncludeEvents] = useState(false);
  const [seriesMode, setSeriesMode] = useState<"severity" | "channel">("severity");
  const [jump, setJump] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [brush, setBrush] = useState<{ a: number; b: number } | null>(null);
  const dragging = useRef(false);
  const parentRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    if (!caseInfo) return;
    setError(null);
    try {
      const [hist, list] = await Promise.all([
        ipc.timelineHistogram(
          {
            computers: [],
            channels: [],
            series: seriesMode,
            time_from: null,
            time_to: null,
            bucket_micros: null,
          },
          filter,
        ),
        ipc.timelineList(
          {
            offset: 0,
            limit: 500,
            computers: [],
            include_events: includeEvents,
            time_from: null,
            time_to: null,
            text: null,
          },
          filter,
        ),
      ]);
      setBuckets(hist);
      setRows(list.rows);
      setTotal(list.total);
    } catch (e) {
      setError(String(e));
    }
  }, [caseInfo, filter, includeEvents, seriesMode]);

  useEffect(() => {
    void load();
  }, [load]);

  const { chartBuckets, minTs, maxTs, maxCount } = useMemo(() => {
    if (!buckets.length) {
      return { chartBuckets: [] as { ts: number; total: number; parts: Record<string, number> }[], minTs: 0, maxTs: 1, maxCount: 1 };
    }
    const map = new Map<number, { ts: number; total: number; parts: Record<string, number> }>();
    for (const b of buckets) {
      const cur = map.get(b.ts) ?? { ts: b.ts, total: 0, parts: {} };
      cur.parts[b.series] = (cur.parts[b.series] ?? 0) + b.count;
      cur.total += b.count;
      map.set(b.ts, cur);
    }
    const chartBuckets = Array.from(map.values()).sort((a, b) => a.ts - b.ts);
    return {
      chartBuckets,
      minTs: chartBuckets[0].ts,
      maxTs: chartBuckets[chartBuckets.length - 1].ts,
      maxCount: Math.max(1, ...chartBuckets.map((c) => c.total)),
    };
  }, [buckets]);

  const applyBrush = () => {
    if (!brush) return;
    const from = Math.min(brush.a, brush.b);
    const to = Math.max(brush.a, brush.b);
    setFilter({ time_from: from, time_to: to });
    setBrush(null);
  };

  const jumpTo = () => {
    const t = Date.parse(jump);
    if (Number.isNaN(t)) {
      setError("Jump time must be a parseable date (ISO)");
      return;
    }
    const micros = t * 1000;
    setFilter({ time_from: micros - 2_500_000, time_to: micros + 2_500_000 });
  };

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 36,
    overscan: 16,
  });

  const laneColor = (computer: string) => {
    let h = 0;
    for (let i = 0; i < computer.length; i++) h = (h * 31 + computer.charCodeAt(i)) % 360;
    return `hsl(${h} 35% 45%)`;
  };

  if (!caseInfo) {
    return (
      <div className="mx-auto max-w-lg py-12">
        <h1 className="font-display text-3xl font-semibold tracking-tight">Timeline</h1>
        <p className="mt-2 text-muted-foreground">Open a case to browse the timeline.</p>
        <Button className="mt-4" variant="outline" onClick={() => setScreen("case")}>
          Go to Case
        </Button>
      </div>
    );
  }

  return (
    <div className="flex h-[calc(100vh-9rem)] min-h-[24rem] flex-col gap-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-display text-3xl font-semibold tracking-tight">Timeline</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {total.toLocaleString()} items · brush the histogram to set the global time filter
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            className="h-8 rounded-md border border-border bg-background/60 px-2 text-xs"
            value={seriesMode}
            onChange={(e) => setSeriesMode(e.target.value as "severity" | "channel")}
          >
            <option value="severity">Stack by severity</option>
            <option value="channel">Stack by channel</option>
          </select>
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={includeEvents}
              onChange={(e) => setIncludeEvents(e.target.checked)}
            />
            Include events
          </label>
          <input
            className="h-8 w-48 rounded-md border border-border bg-background/60 px-2 text-xs"
            placeholder="Jump to ISO time"
            value={jump}
            onChange={(e) => setJump(e.target.value)}
          />
          <Button variant="outline" className="h-8 text-xs" onClick={jumpTo}>
            Jump
          </Button>
          <Button variant="ghost" className="h-8 text-xs" onClick={() => void load()}>
            Refresh
          </Button>
        </div>
      </header>

      {error && (
        <p className="rounded-md border border-red-900/50 bg-red-950/30 px-3 py-2 text-sm text-red-200">
          {error}
        </p>
      )}

      <section
        className="relative h-36 select-none rounded-md border border-border/70 bg-[hsl(222_22%_11%)]/80 px-2 pt-3 pb-6"
        aria-label="Timeline histogram"
        onMouseLeave={() => {
          if (dragging.current) {
            dragging.current = false;
            applyBrush();
          }
        }}
      >
        {chartBuckets.length === 0 ? (
          <p className="flex h-full items-center justify-center text-xs text-muted-foreground">
            No histogram data
          </p>
        ) : (
          <div className="flex h-full items-end gap-px">
            {chartBuckets.map((b) => {
              const span = Math.max(1, maxTs - minTs);
              const xRatio = (b.ts - minTs) / span;
              const inBrush =
                brush &&
                b.ts >= Math.min(brush.a, brush.b) &&
                b.ts <= Math.max(brush.a, brush.b);
              return (
                <div
                  key={b.ts}
                  className={cn(
                    "relative flex min-w-[3px] flex-1 flex-col-reverse",
                    inBrush && "outline outline-1 outline-primary/60",
                  )}
                  style={{ height: "100%" }}
                  title={`${formatTsMicros(b.ts, useUtc)} · ${b.total}`}
                  onMouseDown={() => {
                    dragging.current = true;
                    setBrush({ a: b.ts, b: b.ts });
                  }}
                  onMouseEnter={() => {
                    if (dragging.current) setBrush((prev) => (prev ? { ...prev, b: b.ts } : prev));
                  }}
                  onMouseUp={() => {
                    if (dragging.current) {
                      dragging.current = false;
                      applyBrush();
                    }
                  }}
                >
                  {Object.entries(b.parts).map(([series, count]) => (
                    <div
                      key={series}
                      style={{
                        height: `${(count / maxCount) * 100}%`,
                        background:
                          SEV_COLORS[series] ??
                          `hsl(${Math.floor(xRatio * 200 + 140)} 40% 50%)`,
                      }}
                    />
                  ))}
                </div>
              );
            })}
          </div>
        )}
        <div className="absolute bottom-1 left-2 right-2 flex justify-between text-[10px] text-muted-foreground">
          <span>{formatTsMicros(filter.time_from ?? minTs, useUtc)}</span>
          <span>
            {brush
              ? "Release to apply time filter"
              : filter.time_from != null
                ? "Filtered · Clear filter to reset"
                : "Drag to brush"}
          </span>
          <span>{formatTsMicros(filter.time_to ?? maxTs, useUtc)}</span>
        </div>
      </section>

      <div
        ref={parentRef}
        className="min-h-0 flex-1 overflow-auto rounded-md border border-border/70"
        data-testid="timeline-list"
      >
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {virtualizer.getVirtualItems().map((vi) => {
            const r = rows[vi.index];
            if (!r) return null;
            return (
              <div
                key={`${r.kind}-${r.id}`}
                className="absolute left-0 top-0 flex w-full items-center gap-3 border-b border-border/30 px-3 py-2 text-xs"
                style={{
                  transform: `translateY(${vi.start}px)`,
                  borderLeft: `3px solid ${laneColor(r.computer)}`,
                }}
              >
                <span className="w-40 shrink-0 font-mono text-muted-foreground">
                  {formatTsMicros(r.ts, useUtc)}
                </span>
                <span className="w-16 shrink-0 uppercase text-muted-foreground">{r.kind}</span>
                {r.severity ? <SeverityBadge severity={r.severity} /> : <span className="w-14" />}
                <span className="w-28 shrink-0 truncate">{r.computer}</span>
                <span className="min-w-0 flex-1 truncate">{r.label}</span>
                {r.channel && (
                  <span className="shrink-0 text-muted-foreground">{r.channel}</span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
