import { Button } from "@/components/ui/button";
import { useAppStore } from "@/stores/app-store";

export function PlaceholderScreen({
  title,
  blurb,
}: {
  title: string;
  blurb: string;
}) {
  const setScreen = useAppStore((s) => s.setScreen);
  return (
    <div className="mx-auto flex max-w-xl flex-col gap-4 py-12">
      <h1 className="font-display text-3xl font-semibold tracking-tight">{title}</h1>
      <p className="text-muted-foreground">{blurb}</p>
      <p className="text-sm text-muted-foreground">
        This screen lands in a later milestone. Case ingest and settings are available now.
      </p>
      <Button variant="outline" className="w-fit" onClick={() => setScreen("case")}>
        Back to Case
      </Button>
    </div>
  );
}
