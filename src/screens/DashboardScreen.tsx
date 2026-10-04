import { useCallback, useEffect, useState } from "react";
import { ipc } from "@/ipc/client";
import type { DashboardSummaryDto } from "@/ipc/types";
import { useAppStore } from "@/stores/app-store";
import { formatTsMicros, severityLabel } from "@/lib/format";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Button } from "@/components/ui/button";

const SEV_ORDER = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
] as const;

export function DashboardScreen() {
  const caseInfo = useAppStore((s) => s.caseInfo);
  const filter = useAppStore((s) => s.filter);
  const setFilter = useAppStore((s) => s.setFilter);
  const setScreen = useAppStore((s) => s.setScreen);
  const settings = useAppStore((s) => s.settings);
  const useUtc = settings?.use_utc !== false;

  const [summary, setSummary] = useState<DashboardSummaryDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    if (!caseInfo) {
      setSummary(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      setSummary(await ipc.dashboardSummary(filter));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [caseInfo, filter]);

  useEffect(() => {
    void load();
  }, [load]);

  if (!caseInfo) {
    return (
      <div className="mx-auto max-w-lg py-12">
        <h1 className="font-display text-3xl font-semibold tracking-tight">Dashboard</h1>
        <p className="mt-2 text-muted-foreground">Open a case to see detection summary.</p>
        <Button className="mt-4" variant="outline" onClick={() => setScreen("case")}>
          Go to Case
        </Button>
      </div>
    );
  }

  const sev = summary?.severity;
  const counts: Record<(typeof SEV_ORDER)[number], number> = {
    critical: sev?.critical ?? 0,
    high: sev?.high ?? 0,
    medium: sev?.medium ?? 0,
    low: sev?.low ?? 0,
    informational: sev?.informational ?? 0,
  };
  const maxBucket = Math.max(
    1,
    ...(summary?.detections_over_time.map((b) => b.count) ?? [1]),
  );

  function filterSeverity(level: string) {
    setFilter({ severities: [level] });
    setScreen("detections");
  }

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-8">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-display text-3xl font-semibold tracking-tight">Dashboard</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {summary
              ? `${summary.total_detections.toLocaleString()} detections · ${summary.events.toLocaleString()} events`
              : loading
                ? "Loading…"
                : "No summary yet"}
          </p>
        </div>
        <Button variant="outline" className="h-8 text-xs" onClick={() => void load()}>
          Refresh
        </Button>
      </header>

      {error && (
        <p className="rounded-md border border-red-900/50 bg-red-950/30 px-3 py-2 text-sm text-red-200">
          {error}
        </p>
      )}

      <section aria-label="Severity counts">
        <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Severity
        </h2>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          {SEV_ORDER.map((level) => (
            <button
              key={level}
              type="button"
              onClick={() => filterSeverity(level)}
              className="rounded-md border border-border/70 bg-[hsl(222_22%_12%)]/80 px-3 py-3 text-left transition-colors hover:border-primary/40 hover:bg-primary/5"
            >
              <SeverityBadge severity={level} />
              <p className="mt-2 font-mono text-2xl font-semibold tabular-nums">
                {counts[level].toLocaleString()}
              </p>
              <p className="text-[11px] text-muted-foreground">
                {severityLabel(level)} · filter
              </p>
            </button>
          ))}
        </div>
      </section>

      <section aria-label="Detections over time">
        <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Detections over time
        </h2>
        <div className="flex h-20 items-end gap-px rounded-md border border-border/60 bg-[hsl(222_22%_11%)]/70 px-2 py-2">
          {(summary?.detections_over_time.length ?? 0) === 0 ? (
            <p className="m-auto text-xs text-muted-foreground">No detection timeline yet</p>
          ) : (
            summary!.detections_over_time.map((b) => (
              <div
                key={b.ts}
                title={`${formatTsMicros(b.ts, useUtc)} · ${b.count}`}
                className="min-w-[2px] flex-1 rounded-sm bg-primary/70"
                style={{ height: `${Math.max(8, (b.count / maxBucket) * 100)}%` }}
              />
            ))
          )}
        </div>
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <TopList title="Top rules" rows={summary?.top_rules ?? []} />
        <TopList title="Top hosts" rows={summary?.top_hosts ?? []} />
        <TopList title="Top users" rows={summary?.top_users ?? []} />
        <TopList title="MITRE tactics" rows={summary?.top_tactics ?? []} />
      </div>

      <section aria-label="Evidence">
        <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Evidence
        </h2>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
          <Stat label="Files" value={summary?.files} />
          <Stat label="With errors" value={summary?.files_with_errors} />
          <Stat label="Events" value={summary?.events} />
          <Stat
            label="Range"
            value={
              summary?.first_ts != null
                ? `${formatTsMicros(summary.first_ts, true)} → ${formatTsMicros(summary.last_ts, true)}`
                : "—"
            }
          />
        </dl>
        {(summary?.channels.length ?? 0) > 0 && (
          <p className="mt-3 text-xs text-muted-foreground">
            Channels:{" "}
            {summary!.channels
              .slice(0, 12)
              .map((c) => `${c.name} (${c.count})`)
              .join(" · ")}
          </p>
        )}
      </section>

      {(summary?.coverage.length ?? 0) > 0 && (
        <section aria-label="Coverage warnings">
          <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Coverage warnings
          </h2>
          <ul className="space-y-2">
            {summary!.coverage.map((w) => (
              <li
                key={w.code}
                className="rounded-md border border-amber-900/40 bg-amber-950/20 px-3 py-2 text-sm text-amber-100"
              >
                {w.message}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string | number | undefined | null }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="font-mono tabular-nums">
        {typeof value === "number" ? value.toLocaleString() : (value ?? "—")}
      </dd>
    </div>
  );
}

function TopList({
  title,
  rows,
}: {
  title: string;
  rows: { name: string; count: number }[];
}) {
  return (
    <section>
      <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {title}
      </h2>
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">None</p>
      ) : (
        <ol className="space-y-1.5 text-sm">
          {rows.map((r) => (
            <li
              key={r.name}
              className="flex items-baseline justify-between gap-3 border-b border-border/40 pb-1"
            >
              <span className="min-w-0 truncate">{r.name}</span>
              <span className="shrink-0 font-mono text-xs tabular-nums text-muted-foreground">
                {r.count.toLocaleString()}
              </span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
