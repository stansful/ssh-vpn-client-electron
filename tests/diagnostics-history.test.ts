import { describe, expect, it } from "vitest";
import {
  appendBoundedDiagnosticEntries,
  diagnosticEntryByteLength,
  normalizeDiagnosticEntry,
  truncateUtf8
} from "../src/shared/diagnostics-history.js";
import { utf8ByteLength } from "../src/shared/terminal-history.js";
import type { DiagnosticsEntry } from "../src/shared/types.js";

describe("diagnostics history bounds", () => {
  it("truncates multibyte messages on a UTF-8 boundary", () => {
    const truncated = truncateUtf8("🙂".repeat(100), 40, "...");

    expect(utf8ByteLength(truncated)).toBeLessThanOrEqual(40);
    expect(truncated.endsWith("...")).toBe(true);
    expect(truncated).not.toContain("�");
  });

  it("normalizes untrusted metadata and bounds a single message", () => {
    const normalized = normalizeDiagnosticEntry(
      entry("x".repeat(500), "🙂".repeat(100)),
      64
    );

    expect(normalized.id.length).toBeLessThanOrEqual(128);
    expect(utf8ByteLength(normalized.message)).toBeLessThanOrEqual(64);
  });

  it("retains the newest entries under an aggregate byte cap", () => {
    const first = entry("first", "a".repeat(40));
    const second = entry("second", "b".repeat(40));
    const maxBytes = diagnosticEntryByteLength(second) + 1;

    expect(appendBoundedDiagnosticEntries([first], [second], 10, maxBytes).map((item) => item.id)).toEqual([
      "second"
    ]);
  });
});

function entry(id: string, message: string): DiagnosticsEntry {
  return { id, at: "now", level: "info", message };
}
