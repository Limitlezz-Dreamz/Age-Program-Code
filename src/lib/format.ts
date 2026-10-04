/** Format UTC micros as ISO-like string (UTC or local). */
export function formatTsMicros(ts: number | null | undefined, useUtc = true): string {
  if (ts == null) return "—";
  const ms = Math.floor(ts / 1000);
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return String(ts);
  if (useUtc) {
    return d.toISOString().replace(".000Z", "Z");
  }
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function severityLabel(sev: string): string {
  switch (sev) {
    case "critical":
      return "Critical";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    case "informational":
      return "Info";
    default:
      return sev;
  }
}

export function severityClass(sev: string): string {
  switch (sev) {
    case "critical":
      return "bg-red-950/60 text-red-200 border-red-800/60";
    case "high":
      return "bg-orange-950/50 text-orange-200 border-orange-800/50";
    case "medium":
      return "bg-amber-950/40 text-amber-100 border-amber-800/40";
    case "low":
      return "bg-sky-950/40 text-sky-100 border-sky-800/40";
    default:
      return "bg-muted/50 text-muted-foreground border-border";
  }
}

/** Plain-text field value for XSS-safe rendering. */
export function fieldText(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
