import { describe, expect, it } from "vitest";
import { fieldText, formatTsMicros, severityLabel } from "./format";

describe("fieldText XSS safety", () => {
  it("returns attacker HTML as plain text (no stripping that would hide the payload)", () => {
    const payload = '<img src=x onerror=alert(1)>';
    expect(fieldText(payload)).toBe(payload);
    expect(fieldText({ CommandLine: payload })).toContain("<img");
  });

  it("stringifies nested values without throwing", () => {
    expect(fieldText(null)).toBe("");
    expect(fieldText(42)).toBe("42");
    expect(fieldText(true)).toBe("true");
  });
});

describe("format helpers", () => {
  it("formats UTC micros", () => {
    expect(formatTsMicros(null)).toBe("—");
    expect(formatTsMicros(1_700_000_000_000_000, true)).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("labels severities", () => {
    expect(severityLabel("critical")).toBe("Critical");
    expect(severityLabel("informational")).toBe("Info");
  });
});
