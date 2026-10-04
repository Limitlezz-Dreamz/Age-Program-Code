import { useCallback, useEffect, useMemo, useState } from "react";
import { ipc } from "@/ipc/client";
import type { EventDetailDto } from "@/ipc/types";
import { useAppStore } from "@/stores/app-store";
import { fieldText, formatTsMicros } from "@/lib/format";
import { Button } from "@/components/ui/button";

type Tab = "fields" | "raw" | "xml" | "detections" | "decoded";

export function EventDetailScreen({
  eventId,
  onClose,
  onOpenDetection,
}: {
  eventId: number;
  onClose?: () => void;
  onOpenDetection?: (id: number) => void;
}) {
  const setFilter = useAppStore((s) => s.setFilter);
  const setScreen = useAppStore((s) => s.setScreen);

  const [detail, setDetail] = useState<EventDetailDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("fields");
  const [fieldQuery, setFieldQuery] = useState("");

  const load = useCallback(async () => {
    setError(null);
    try {
      const d = await ipc.getEvent(eventId);
      setDetail(d);
      if (d.decoded) setTab("decoded");
    } catch (e) {
      setError(String(e));
    }
  }, [eventId]);

  useEffect(() => {
    void load();
  }, [load]);

  const fieldRows = useMemo(() => {
    if (!detail) return [];
    const q = fieldQuery.trim().toLowerCase();
    return Object.entries(detail.fields)
      .map(([k, v]) => ({ key: k, value: fieldText(v) }))
      .filter(
        (r) =>
          !q ||
          r.key.toLowerCase().includes(q) ||
          r.value.toLowerCase().includes(q),
      )
      .sort((a, b) => a.key.localeCompare(b.key));
  }, [detail, fieldQuery]);

  const tabs: { id: Tab; label: string; hidden?: boolean }[] = [
    { id: "fields", label: "Fields" },
    { id: "raw", label: "Raw JSON" },
    { id: "xml", label: "XML" },
    { id: "detections", label: "Detections" },
    { id: "decoded", label: "Decoded", hidden: !detail?.decoded },
  ];

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="shrink-0 border-b border-border/60 pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="font-display text-xl font-semibold tracking-tight">
              Event {detail?.event_id ?? "…"}
            </h2>
            <p className="mt-1 text-xs text-muted-foreground">
              {detail?.description ?? detail?.channel ?? "Loading…"}
            </p>
          </div>
          {onClose && (
            <Button variant="ghost" className="h-8 px-2 text-xs" onClick={onClose}>
              Close
            </Button>
          )}
        </div>
        {error && (
          <p className="mt-2 text-sm text-red-300">{error}</p>
        )}
        {detail && (
          <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-3">
            <Meta label="UTC" value={formatTsMicros(detail.ts, true)} />
            <Meta label="Local" value={formatTsMicros(detail.ts, false)} />
            <Meta label="Channel" value={detail.channel} />
            <Meta label="Provider" value={detail.provider} />
            <Meta label="Computer" value={detail.computer} />
            <Meta label="Record ID" value={String(detail.record_id)} />
            <Meta label="User" value={detail.user_name ?? "—"} />
            <Meta label="Src IP" value={detail.src_ip ?? "—"} />
            <Meta
              label="Source"
              value={detail.source_path ?? `file#${detail.file_id}`}
            />
          </dl>
        )}
      </header>

      <div className="mt-3 flex shrink-0 flex-wrap gap-1 border-b border-border/50 pb-2">
        {tabs
          .filter((t) => !t.hidden)
          .map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={
                tab === t.id
                  ? "rounded-md bg-primary/15 px-2.5 py-1 text-xs text-foreground"
                  : "rounded-md px-2.5 py-1 text-xs text-muted-foreground hover:bg-muted/50"
              }
            >
              {t.label}
            </button>
          ))}
      </div>

      <div className="min-h-0 flex-1 overflow-auto pt-3">
        {!detail ? (
          <p className="text-sm text-muted-foreground">Loading event…</p>
        ) : tab === "fields" ? (
          <div className="flex flex-col gap-2">
            <input
              className="h-8 w-full rounded-md border border-border bg-background/60 px-2 text-sm"
              placeholder="Search fields"
              value={fieldQuery}
              onChange={(e) => setFieldQuery(e.target.value)}
              aria-label="Search fields"
            />
            <table className="w-full text-left text-xs">
              <thead className="text-muted-foreground">
                <tr>
                  <th className="py-1 pr-3 font-medium">Field</th>
                  <th className="py-1 font-medium">Value</th>
                </tr>
              </thead>
              <tbody>
                {fieldRows.map((r) => (
                  <tr
                    key={r.key}
                    className="border-t border-border/40 align-top"
                    onContextMenu={(e) => {
                      e.preventDefault();
                      setFilter({ text: r.value.slice(0, 200) });
                      setScreen("detections");
                    }}
                  >
                    <td className="py-1.5 pr-3 font-mono text-muted-foreground whitespace-nowrap">
                      {r.key}
                    </td>
                    <td className="py-1.5 font-mono whitespace-pre-wrap break-all">
                      {r.value}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : tab === "raw" ? (
          <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground/90">
            {prettyJson(detail.raw_json) ?? "(no raw JSON stored)"}
          </pre>
        ) : tab === "xml" ? (
          <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground/90">
            {detail.xml ?? "(no XML)"}
          </pre>
        ) : tab === "decoded" && detail.decoded ? (
          <div className="space-y-2 text-sm">
            <p className="text-xs text-muted-foreground">
              Decoded {detail.decoded.field} ({detail.decoded.encoding})
            </p>
            <pre className="whitespace-pre-wrap break-all font-mono text-xs">
              {detail.decoded.text}
            </pre>
          </div>
        ) : tab === "detections" ? (
          <ul className="space-y-2 text-sm">
            {detail.related_detection_ids.length === 0 ? (
              <li className="text-muted-foreground">No linked detections</li>
            ) : (
              detail.related_detection_ids.map((id) => (
                <li key={id}>
                  <button
                    type="button"
                    className="text-primary underline-offset-2 hover:underline"
                    onClick={() => onOpenDetection?.(id)}
                  >
                    Detection #{id}
                  </button>
                </li>
              ))
            )}
          </ul>
        ) : null}
      </div>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="truncate font-mono" title={value}>
        {value}
      </dd>
    </div>
  );
}

function prettyJson(raw: string | null): string | null {
  if (!raw) return null;
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}
