import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { APP_NAME } from "@/lib/constants";
import { Button } from "@/components/ui/button";

function App() {
  const [backendName, setBackendName] = useState(APP_NAME);
  const [status, setStatus] = useState("Scaffold ready");

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const name = await invoke<string>("app_name");
        if (!cancelled) {
          setBackendName(name);
          setStatus("Rust backend connected");
        }
      } catch {
        if (!cancelled) {
          setStatus("Frontend-only mode (Tauri IPC unavailable)");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col justify-center gap-8 px-8 py-16">
      <div className="space-y-3">
        <p className="text-sm font-medium uppercase tracking-[0.2em] text-muted-foreground">
          Milestone M0
        </p>
        <h1 className="font-display text-5xl font-semibold tracking-tight text-foreground">
          {backendName}
        </h1>
        <p className="max-w-xl text-lg text-muted-foreground">
          Cross-platform EVTX threat hunting. Parse, detect, and triage Windows
          event logs offline — Chainsaw-style workflow with a GUI.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Button onClick={() => setStatus("Scaffolding complete — M1 next")}>
          Continue
        </Button>
        <Button variant="outline" onClick={() => setStatus("Awaiting case ingest…")}>
          Open case (soon)
        </Button>
      </div>

      <p className="text-sm text-muted-foreground" data-testid="status">
        {status}
      </p>
    </main>
  );
}

export default App;
