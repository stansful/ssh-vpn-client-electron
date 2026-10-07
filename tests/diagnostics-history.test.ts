import { describe, expect, it } from "vitest";
import {
  appendBoundedDiagnosticEntries,
  classifyDiagnosticSource,
  diagnosticEntryByteLength,
  normalizeDiagnosticEntry,
  truncateUtf8,
  withDiagnosticSource
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

describe("diagnostics source", () => {
  it("drops a source value that is not one of the known parts of the app", () => {
    const untrusted = { ...entry("id", "message"), source: "kernel" } as unknown as DiagnosticsEntry;
    expect(normalizeDiagnosticEntry(untrusted)).not.toHaveProperty("source");
    const trusted: DiagnosticsEntry = { ...entry("id", "message"), source: "xray" };
    expect(normalizeDiagnosticEntry(trusted)).toBe(trusted);
  });

  it("files transport messages about routing under routing", () => {
    expect(classifyDiagnosticSource("TUN routing is unavailable, continuing on the Windows proxy path: x", "ssh")).toBe("routing");
    expect(classifyDiagnosticSource("Routing mode changed while connected: mode=selected-rules", "xray")).toBe("routing");
    expect(classifyDiagnosticSource("Selected routing prepared: enabled=3", "ssh")).toBe("routing");
    expect(classifyDiagnosticSource("Windows proxy restore failed: denied", "xray")).toBe("routing");
    expect(classifyDiagnosticSource("Reconnect attempt 1 scheduled in 8 s: SSH keepalive timed out.", "ssh")).toBe("ssh");
    expect(classifyDiagnosticSource("Xray runtime exited with code 1.", "xray")).toBe("xray");
    expect(classifyDiagnosticSource("TUN routing is unavailable", "app")).toBe("app");
  });

  it("keeps a source the entry already has", () => {
    expect(withDiagnosticSource({ ...entry("id", "TUN routing is active"), source: "update" }, "ssh").source).toBe("update");
    expect(withDiagnosticSource(entry("id", "TUN routing is active"), "ssh").source).toBe("routing");
    expect(withDiagnosticSource(entry("id", "SSH session disconnected."), "ssh").source).toBe("ssh");
  });
});

function entry(id: string, message: string): DiagnosticsEntry {
  return { id, at: "now", level: "info", message };
}
