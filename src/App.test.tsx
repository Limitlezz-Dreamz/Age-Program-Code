import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import { APP_NAME } from "./lib/constants";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn().mockRejectedValue(new Error("no tauri")),
}));

describe("App", () => {
  it("renders the product name", async () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: APP_NAME })).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByTestId("status")).toHaveTextContent(
        "Frontend-only mode (Tauri IPC unavailable)",
      );
    });
  });
});
