import type { ReactNode } from "react";
import { APP_NAME } from "@/lib/constants";
import { useAppStore } from "@/stores/app-store";
import type { NavId } from "@/ipc/types";
import { GlobalFilterBar } from "@/components/layout/GlobalFilterBar";
import { cn } from "@/lib/utils";

const NAV: { id: NavId; label: string; soon?: boolean }[] = [
  { id: "case", label: "Case" },
  { id: "dashboard", label: "Dashboard" },
  { id: "detections", label: "Detections" },
  { id: "timeline", label: "Timeline" },
  { id: "explorer", label: "Explorer" },
  { id: "pivots", label: "Pivots" },
  { id: "rules", label: "Rules", soon: true },
  { id: "export", label: "Export", soon: true },
  { id: "settings", label: "Settings" },
];

export function AppShell({ children }: { children: ReactNode }) {
  const screen = useAppStore((s) => s.screen);
  const setScreen = useAppStore((s) => s.setScreen);
  const caseInfo = useAppStore((s) => s.caseInfo);
  const analysis = useAppStore((s) => s.analysis);
  const settings = useAppStore((s) => s.settings);

  const statusLabel = analysis.running
    ? `${analysis.phase} · ${analysis.events.toLocaleString()} ev · ${Math.round(analysis.eventsPerSec)}/s`
    : analysis.phase === "done"
      ? `idle · ${analysis.detections} detections`
      : analysis.phase === "failed"
        ? "failed"
        : "idle";

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-56 shrink-0 flex-col border-r border-border/80 bg-[hsl(222_24%_9%)]/90 backdrop-blur">
        <div className="border-b border-border/60 px-4 py-5">
          <p className="font-display text-xl font-semibold tracking-tight text-foreground">
            {APP_NAME}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">Offline EVTX hunting</p>
        </div>
        <nav className="flex flex-1 flex-col gap-0.5 p-2" aria-label="Main">
          {NAV.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setScreen(item.id)}
              className={cn(
                "rounded-md px-3 py-2 text-left text-sm transition-colors",
                screen === item.id
                  ? "bg-primary/15 text-foreground"
                  : "text-muted-foreground hover:bg-muted/60 hover:text-foreground",
              )}
            >
              <span className="flex items-center justify-between gap-2">
                {item.label}
                {item.soon && (
                  <span className="text-[10px] uppercase tracking-wide text-muted-foreground/70">
                    soon
                  </span>
                )}
              </span>
            </button>
          ))}
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-center gap-3 border-b border-border/70 bg-[hsl(222_24%_10%)]/80 px-4 py-3 backdrop-blur">
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium text-foreground">
              {caseInfo?.name ?? "No case open"}
            </p>
            <p className="truncate text-xs text-muted-foreground">
              {caseInfo?.path ?? "Create or open a case to begin"}
            </p>
          </div>
          <div
            className={cn(
              "rounded-md border px-2.5 py-1 text-xs",
              analysis.running
                ? "border-primary/40 bg-primary/10 text-foreground"
                : "border-border bg-muted/40 text-muted-foreground",
            )}
            data-testid="run-status"
          >
            {statusLabel}
          </div>
          <div className="rounded-md border border-border bg-muted/30 px-2.5 py-1 text-xs text-muted-foreground">
            {settings?.use_utc === false ? "Local" : "UTC"}
          </div>
        </header>
        <GlobalFilterBar />
        <main className="min-h-0 flex-1 overflow-auto p-4 md:p-6">{children}</main>
      </div>
    </div>
  );
}
