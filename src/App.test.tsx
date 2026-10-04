import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import { APP_NAME } from "./lib/constants";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn().mockRejectedValue(new Error("no tauri")),
  Channel: class {
    onmessage: ((v: unknown) => void) | null = null;
  },
}));

vi.mock("@tauri-apps/api/webview", () => ({
  getCurrentWebview: () => ({
    onDragDropEvent: vi.fn().mockResolvedValue(() => {}),
  }),
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(),
}));

describe("App", () => {
  it("renders the shell with product name in the nav", async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
    });
    expect(screen.getAllByText(APP_NAME).length).toBeGreaterThan(0);
    expect(screen.getByTestId("run-status")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create case" })).toBeInTheDocument();
  });
});
