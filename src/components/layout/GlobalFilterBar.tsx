import { useAppStore } from "@/stores/app-store";
import { Button } from "@/components/ui/button";

export function GlobalFilterBar() {
  const filter = useAppStore((s) => s.filter);
  const setFilter = useAppStore((s) => s.setFilter);
  const clearFilter = useAppStore((s) => s.clearFilter);

  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border/60 bg-[hsl(222_22%_11%)]/70 px-4 py-2">
      <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        Filter
      </span>
      <input
        className="h-8 min-w-[12rem] flex-1 rounded-md border border-border bg-background/60 px-2 text-sm outline-none ring-ring focus:ring-1"
        placeholder="Text / FTS (events & detections)"
        value={filter.text ?? ""}
        onChange={(e) => setFilter({ text: e.target.value || null })}
        aria-label="Global text filter"
      />
      <input
        className="h-8 w-28 rounded-md border border-border bg-background/60 px-2 text-sm outline-none ring-ring focus:ring-1"
        placeholder="Host"
        value={filter.computers[0] ?? ""}
        onChange={(e) =>
          setFilter({ computers: e.target.value ? [e.target.value] : [] })
        }
        aria-label="Computer filter"
      />
      <input
        className="h-8 w-28 rounded-md border border-border bg-background/60 px-2 text-sm outline-none ring-ring focus:ring-1"
        placeholder="User"
        value={filter.users[0] ?? ""}
        onChange={(e) =>
          setFilter({ users: e.target.value ? [e.target.value] : [] })
        }
        aria-label="User filter"
      />
      <select
        className="h-8 rounded-md border border-border bg-background/60 px-2 text-sm"
        value={filter.severities[0] ?? ""}
        onChange={(e) =>
          setFilter({ severities: e.target.value ? [e.target.value] : [] })
        }
        aria-label="Severity filter"
      >
        <option value="">Severity</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="informational">Info</option>
      </select>
      <Button variant="ghost" className="h-8 px-2 text-xs" onClick={clearFilter}>
        Clear
      </Button>
    </div>
  );
}
