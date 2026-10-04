import { useCallback, useEffect, useState } from "react";
import { ipc } from "@/ipc/client";
import type { LogonSummaryRowDto, PivotRowDto } from "@/ipc/types";
import { useAppStore } from "@/stores/app-store";
import { formatTsMicros } from "@/lib/format";
import { Button } from "@/components/ui/button";

type Tab = "hosts" | "users" | "ips" | "logons";

const LOGON_LEGEND = [
  [2, "Interactive"],
  [3, "Network"],
  [4, "Batch"],
  [5, "Service"],
  [7, "Unlock"],
  [8, "NetworkCleartext"],
  [9, "NewCredentials"],
  [10, "RemoteInteractive"],
  [11, "CachedInteractive"],
] as const;

export function PivotsScreen() {
  const caseInfo = useAppStore((s) => s.caseInfo);
  const filter = useAppStore((s) => s.filter);
  const setFilter = useAppStore((s) => s.setFilter);
  const setScreen = useAppStore((s) => s.setScreen);
  const settings = useAppStore((s) => s.settings);
  const useUtc = settings?.use_utc !== false;

  const [tab, setTab] = useState<Tab>("hosts");
  const [rows, setRows] = useState<PivotRowDto[]>([]);
  const [logons, setLogons] = useState<LogonSummaryRowDto[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");

  const load = useCallback(async () => {
    if (!caseInfo) return;
    setError(null);
    try {
      if (tab === "logons") {
        const page = await ipc.logonSummary(
          {
            dimension: "logon",
            offset: 0,
            limit: 500,
            text: q || null,
            time_from: null,
            time_to: null,
          },
          filter,
        );
        setLogons(page.rows);
        setRows([]);
        setTotal(page.total);
      } else {
        const dim = tab === "hosts" ? "computer" : tab === "users" ? "user" : "src_ip";
        const page = await ipc.queryPivots(
          {
            dimension: dim,
            offset: 0,
            limit: 500,
            text: q || null,
            time_from: null,
            time_to: null,
          },
          filter,
        );
        setRows(page.rows);
        setLogons([]);
        setTotal(page.total);
      }
    } catch (e) {
      setError(String(e));
    }
  }, [caseInfo, tab, q, filter]);

  useEffect(() => {
    void load();
  }, [load]);

  function applyEntity(key: string) {
    if (tab === "hosts") setFilter({ computers: [key] });
    else if (tab === "users") setFilter({ users: [key] });
    else if (tab === "ips") setFilter({ text: key });
    setScreen("detections");
  }

  if (!caseInfo) {
    return (
      <div className="mx-auto max-w-lg py-12">
        <h1 className="font-display text-3xl font-semibold tracking-tight">Pivots</h1>
        <p className="mt-2 text-muted-foreground">Open a case to pivot on hosts, users, and logons.</p>
        <Button className="mt-4" variant="outline" onClick={() => setScreen("case")}>
          Go to Case
        </Button>
      </div>
    );
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: "hosts", label: "Hosts" },
    { id: "users", label: "Users" },
    { id: "ips", label: "Source IPs" },
    { id: "logons", label: "Logons" },
  ];

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-display text-3xl font-semibold tracking-tight">Pivots</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {total.toLocaleString()} rows · click to filter the case
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <input
            className="h-8 w-40 rounded-md border border-border bg-background/60 px-2 text-xs"
            placeholder="Filter…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <Button variant="ghost" className="h-8 text-xs" onClick={() => void load()}>
            Refresh
          </Button>
        </div>
      </header>

      <div className="flex flex-wrap gap-1 border-b border-border/50 pb-2">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={
              tab === t.id
                ? "rounded-md bg-primary/15 px-3 py-1.5 text-sm"
                : "rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted/50"
            }
          >
            {t.label}
          </button>
        ))}
      </div>

      {error && (
        <p className="rounded-md border border-red-900/50 bg-red-950/30 px-3 py-2 text-sm text-red-200">
          {error}
        </p>
      )}

      {tab === "logons" ? (
        <>
          <p className="text-xs text-muted-foreground">
            Logon types:{" "}
            {LOGON_LEGEND.map(([n, name]) => `${n} ${name}`).join(" · ")}
          </p>
          <div className="overflow-x-auto rounded-md border border-border/70">
            <table className="w-full min-w-[48rem] text-left text-sm">
              <thead className="bg-muted/40 text-xs uppercase tracking-wide text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">User</th>
                  <th className="px-3 py-2">Src IP</th>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Host</th>
                  <th className="px-3 py-2">Success</th>
                  <th className="px-3 py-2">Fail</th>
                  <th className="px-3 py-2">First</th>
                  <th className="px-3 py-2">Last</th>
                </tr>
              </thead>
              <tbody>
                {logons.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-3 py-8 text-center text-muted-foreground">
                      No logon summary yet (run analysis with built-ins / A002)
                    </td>
                  </tr>
                ) : (
                  logons.map((r, i) => (
                    <tr
                      key={`${r.user_name}-${r.src_ip}-${r.logon_type}-${r.computer}-${i}`}
                      className="cursor-pointer border-t border-border/40 hover:bg-muted/30"
                      onClick={() => {
                        setFilter({
                          users: r.user_name ? [r.user_name] : [],
                          computers: r.computer ? [r.computer] : [],
                          text: r.src_ip || null,
                        });
                        setScreen("detections");
                      }}
                    >
                      <td className="px-3 py-2">{r.user_name || "—"}</td>
                      <td className="px-3 py-2 font-mono text-xs">{r.src_ip || "—"}</td>
                      <td className="px-3 py-2">
                        {r.logon_type} {r.logon_type_name}
                      </td>
                      <td className="px-3 py-2">{r.computer}</td>
                      <td className="px-3 py-2 font-mono">{r.success_count}</td>
                      <td className="px-3 py-2 font-mono">{r.fail_count}</td>
                      <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                        {formatTsMicros(r.first_ts, useUtc)}
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                        {formatTsMicros(r.last_ts, useUtc)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <div className="overflow-x-auto rounded-md border border-border/70">
          <table className="w-full min-w-[40rem] text-left text-sm">
            <thead className="bg-muted/40 text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-3 py-2">{tab === "hosts" ? "Host" : tab === "users" ? "User" : "IP"}</th>
                <th className="px-3 py-2">Events</th>
                <th className="px-3 py-2">Detections</th>
                <th className="px-3 py-2">Crit</th>
                <th className="px-3 py-2">High</th>
                <th className="px-3 py-2">Med</th>
                <th className="px-3 py-2">First</th>
                <th className="px-3 py-2">Last</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-3 py-8 text-center text-muted-foreground">
                    No pivot rows
                  </td>
                </tr>
              ) : (
                rows.map((r) => (
                  <tr
                    key={r.key}
                    className="cursor-pointer border-t border-border/40 hover:bg-muted/30"
                    onClick={() => applyEntity(r.key)}
                  >
                    <td className="px-3 py-2 font-medium">{r.key}</td>
                    <td className="px-3 py-2 font-mono">{r.event_count.toLocaleString()}</td>
                    <td className="px-3 py-2 font-mono">{r.detection_count.toLocaleString()}</td>
                    <td className="px-3 py-2 font-mono">{r.critical}</td>
                    <td className="px-3 py-2 font-mono">{r.high}</td>
                    <td className="px-3 py-2 font-mono">{r.medium}</td>
                    <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                      {formatTsMicros(r.first_ts, useUtc)}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                      {formatTsMicros(r.last_ts, useUtc)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
