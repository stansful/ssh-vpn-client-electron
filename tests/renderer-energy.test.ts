import { describe, expect, it } from "vitest";
import { BoundedRendererEventQueue } from "../src/renderer/lib/renderer-event-queue.js";
import { nextRenderPageCount, sliceRenderPage } from "../src/renderer/lib/render-page.js";
import { buildTerminalDisplay } from "../src/renderer/components/pages/connect/terminal-view.js";
import { createDefaultRuntimeStatus } from "../src/shared/defaults.js";
import type { RendererEvent } from "../src/shared/ipc.js";
import type { TerminalLine } from "../src/shared/types.js";

describe("renderer energy bounds", () => {
  it("renders only the live terminal tail, by characters and by rows", () => {
    const history = [line("one", "abc\n"), line("two", "def\n"), line("three", "gh\n")];

    expect(buildTerminalDisplay(history, 6)).toEqual({
      lines: [
        { text: "ef", cls: "" },
        { text: "gh", cls: "" }
      ],
      truncated: true
    });
    expect(buildTerminalDisplay(history, 1000, 2)).toEqual({
      lines: [
        { text: "def", cls: "" },
        { text: "gh", cls: "" }
      ],
      truncated: true
    });
    expect(buildTerminalDisplay([])).toEqual({ lines: [], truncated: false });
  });

  it("bounds queued output without dropping the latest authoritative status", () => {
    const queue = new BoundedRendererEventQueue({ maxEvents: 4, maxTerminalBytes: 3 });
    queue.enqueue(statusEvent("Connecting"));
    queue.enqueue({ type: "terminal-output", line: line("one", "ab") });
    queue.enqueue({
      type: "diagnostics-appended",
      entry: { id: "diagnostic", at: "now", level: "info", message: "message" }
    });
    queue.enqueue(statusEvent("Connected"));
    queue.enqueue({ type: "terminal-output", line: line("two", "cd") });

    const drained = queue.drain();
    expect(drained.some((event) => event.type === "terminal-output" && event.line.id === "one")).toBe(false);
    expect(drained.find((event) => event.type === "status-changed")?.status.state).toBe("Connected");
    expect(queue.size).toBe(0);
  });

  it("bounds queued diagnostics by UTF-8 bytes as well as event count", () => {
    const queue = new BoundedRendererEventQueue({
      maxEvents: 10,
      maxTerminalBytes: 10,
      maxDiagnosticBytes: 70
    });
    queue.enqueue({ type: "terminal-output", line: line("terminal", "ok") });
    queue.enqueue({
      type: "diagnostics-appended",
      entry: { id: "old", at: "now", level: "info", message: "x".repeat(40) }
    });
    queue.enqueue({
      type: "diagnostics-appended",
      entry: { id: "new", at: "now", level: "warning", message: "y".repeat(40) }
    });

    const drained = queue.drain();
    expect(
      drained
        .filter((event) => event.type === "diagnostics-appended")
        .map((event) => event.entry.id)
    ).toEqual(["new"]);
    expect(drained.some((event) => event.type === "terminal-output" && event.line.id === "terminal")).toBe(true);
  });

  it("limits large collections to explicit render pages", () => {
    const items = Array.from({ length: 10_000 }, (_, index) => index);
    expect(sliceRenderPage(items, 200)).toHaveLength(200);
    expect(nextRenderPageCount(200, items.length, 200)).toBe(400);
    expect(nextRenderPageCount(9_900, items.length, 200)).toBe(10_000);
  });
});

function line(id: string, text: string): TerminalLine {
  return { id, at: "now", stream: "stdout", text };
}

function statusEvent(state: "Connecting" | "Connected"): RendererEvent {
  const status = createDefaultRuntimeStatus({
    platform: "unknown",
    arch: "unknown",
    serviceExecutableName: "shadow-ssh-service",
    serviceRelativePath: "native/unknown/unknown/shadow-ssh-service",
    supportsPrivilegedService: false
  });
  return {
    type: "status-changed",
    status: { ...status, state }
  };
}
