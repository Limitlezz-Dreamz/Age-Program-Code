import { useEffect } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { ipc } from "@/ipc/client";
import { useAppStore } from "@/stores/app-store";

/** Wire Tauri drag-drop events into case evidence intake. */
export function useDragDrop() {
  const caseInfo = useAppStore((s) => s.caseInfo);
  const setDropActive = useAppStore((s) => s.setDropActive);
  const setFiles = useAppStore((s) => s.setFiles);
  const analysisRunning = useAppStore((s) => s.analysis.running);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;

    void (async () => {
      try {
        unlisten = await getCurrentWebview().onDragDropEvent(async (event) => {
          if (cancelled) return;
          const { type } = event.payload;
          if (type === "enter" || type === "over") {
            setDropActive(true);
          } else if (type === "leave") {
            setDropActive(false);
          } else if (type === "drop") {
            setDropActive(false);
            if (!caseInfo || analysisRunning) return;
            const paths = event.payload.paths ?? [];
            if (paths.length === 0) return;
            try {
              await ipc.addInputs(paths);
              setFiles(await ipc.listFiles());
            } catch (e) {
              console.error(e);
            }
          }
        });
      } catch {
        // Frontend-only / vitest — drag-drop unavailable
      }
    })();

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [caseInfo, analysisRunning, setDropActive, setFiles]);
}
