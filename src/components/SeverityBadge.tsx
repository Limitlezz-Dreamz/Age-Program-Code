import { cn } from "@/lib/utils";
import { severityClass, severityLabel } from "@/lib/format";

export function SeverityBadge({
  severity,
  className,
}: {
  severity: string;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide",
        severityClass(severity),
        className,
      )}
    >
      {severityLabel(severity)}
    </span>
  );
}
