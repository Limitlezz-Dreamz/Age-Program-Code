import { useEffect } from "react";
import { AppShell } from "@/components/layout/AppShell";
import { useDragDrop } from "@/hooks/useDragDrop";
import { ipc } from "@/ipc/client";
import { CaseScreen } from "@/screens/CaseScreen";
import { PlaceholderScreen } from "@/screens/PlaceholderScreen";
import { SettingsScreen } from "@/screens/SettingsScreen";
import { useAppStore } from "@/stores/app-store";

function ScreenRouter() {
  const screen = useAppStore((s) => s.screen);
  switch (screen) {
    case "case":
      return <CaseScreen />;
    case "settings":
      return <SettingsScreen />;
    case "dashboard":
      return (
        <PlaceholderScreen
          title="Dashboard"
          blurb="Severity cards, top rules/hosts, and coverage warnings arrive in M4."
        />
      );
    case "detections":
      return (
        <PlaceholderScreen
          title="Detections"
          blurb="Paged detections list and detail drawer arrive in M4."
        />
      );
    case "timeline":
      return (
        <PlaceholderScreen
          title="Timeline"
          blurb="Histogram + merged event/detection lane view arrives in M5."
        />
      );
    case "explorer":
      return (
        <PlaceholderScreen
          title="Explorer"
          blurb="Structured search across all events arrives in M5."
        />
      );
    case "pivots":
      return (
        <PlaceholderScreen
          title="Pivots"
          blurb="Hosts, users, IPs, and logon summary arrive in M5."
        />
      );
    case "rules":
      return (
        <PlaceholderScreen
          title="Rules"
          blurb="Pack manager, profiles, and re-run detection arrive in M6."
        />
      );
    case "export":
      return (
        <PlaceholderScreen
          title="Export"
          blurb="CSV/JSON/HTML export arrives in M6."
        />
      );
    default:
      return <CaseScreen />;
  }
}

function App() {
  const setReady = useAppStore((s) => s.setReady);
  const markBootstrapped = useAppStore((s) => s.markBootstrapped);
  const setSettings = useAppStore((s) => s.setSettings);
  const setRecent = useAppStore((s) => s.setRecent);
  const setCase = useAppStore((s) => s.setCase);
  const ready = useAppStore((s) => s.ready);

  useDragDrop();

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        await ipc.appName();
        if (cancelled) return;
        const [settings, recent, current] = await Promise.all([
          ipc.getSettings(),
          ipc.recentCases(),
          ipc.currentCase(),
        ]);
        if (cancelled) return;
        setSettings(settings);
        setRecent(recent);
        setCase(current);
        setReady(true);
      } catch {
        if (!cancelled) {
          // Vitest / browser-only: still show shell with defaults
          setSettings({
            display_timezone: "UTC",
            use_utc: true,
            threads: 4,
            fts_default: true,
            hash_default: true,
            rule_profile: "default",
            builtins_default: true,
            run_detection_default: true,
            log_level: "info",
            thresh_kerberoast: 10,
            thresh_bruteforce: 10,
            thresh_spray: 5,
          });
          markBootstrapped();
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [setReady, markBootstrapped, setSettings, setRecent, setCase]);

  if (!ready) {
    return (
      <div className="flex min-h-screen items-center justify-center text-muted-foreground">
        Loading…
      </div>
    );
  }

  return (
    <AppShell>
      <ScreenRouter />
    </AppShell>
  );
}

export default App;
