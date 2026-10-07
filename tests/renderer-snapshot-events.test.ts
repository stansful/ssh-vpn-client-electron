import { describe, expect, it } from "vitest";
import {
  applyLiveServiceEventsToSnapshot,
  applyServiceEventsToSnapshot,
  diagnosticSource
} from "../src/renderer/lib/diagnostics.js";
import { BoundedRendererEventQueue } from "../src/renderer/lib/renderer-event-queue.js";
import type { AttentionEvent, TunnelCheckResult } from "../src/shared/types.js";
import { createTestRuntime, createTestSnapshot } from "./renderer-fixtures.js";

describe("renderer startup event replay", () => {
  it("replays events received around the initial snapshot without duplicating IDs", () => {
    const snapshot = createTestSnapshot();
    const connected = { ...snapshot.runtime, state: "Connected" as const, message: "Connected after snapshot." };
    snapshot.diagnostics.push({ id: "existing", at: "1", level: "info", message: "already captured" });
    snapshot.terminal.push({ id: "line-existing", at: "1", stream: "stdout", text: "old" });

    const replayed = applyServiceEventsToSnapshot(snapshot, [
      { type: "diagnostics-appended", entry: { id: "existing", at: "1", level: "info", message: "already captured" } },
      { type: "diagnostics-appended", entry: { id: "new", at: "2", level: "warning", message: "new event" } },
      { type: "terminal-output", line: { id: "line-existing", at: "1", stream: "stdout", text: "old" } },
      { type: "terminal-output", line: { id: "line-new", at: "2", stream: "stdout", text: "new" } },
      { type: "status-changed", status: connected }
    ]);

    expect(replayed.diagnostics.map((entry) => entry.id)).toEqual(["existing", "new"]);
    expect(replayed.terminal.map((line) => line.id)).toEqual(["line-existing", "line-new"]);
    expect(replayed.runtime).toEqual(connected);
  });

  it("applies a terminal frame as one ordered burst and ignores empty output", () => {
    const snapshot = createTestSnapshot();
    const updated = applyLiveServiceEventsToSnapshot(snapshot, [
      { type: "terminal-output", line: { id: "empty", at: "1", stream: "stdout", text: "" } },
      { type: "terminal-output", line: { id: "one", at: "2", stream: "stdout", text: "one" } },
      { type: "terminal-output", line: { id: "two", at: "3", stream: "stderr", text: "two" } }
    ]);

    expect(updated?.terminal.map((line) => line.id)).toEqual(["one", "two"]);
  });

  it("skips live events whose entries an IPC reply already delivered", () => {
    const snapshot = createTestSnapshot();
    snapshot.diagnostics.push({ id: "check", at: "1", level: "info", message: "Tunnel check passed." });
    snapshot.terminal.push({ id: "prompt", at: "1", stream: "stdout", text: "$ " });

    const updated = applyLiveServiceEventsToSnapshot(snapshot, [
      { type: "diagnostics-appended", entry: { id: "check", at: "1", level: "info", message: "Tunnel check passed." } },
      { type: "diagnostics-appended", entry: { id: "next", at: "2", level: "info", message: "Next." } },
      { type: "diagnostics-appended", entry: { id: "next", at: "2", level: "info", message: "Next." } },
      { type: "terminal-output", line: { id: "prompt", at: "1", stream: "stdout", text: "$ " } },
      { type: "terminal-output", line: { id: "out", at: "2", stream: "stdout", text: "ok" } }
    ]);

    expect(updated?.diagnostics.map((entry) => entry.id)).toEqual(["check", "next"]);
    expect(updated?.terminal.map((line) => line.id)).toEqual(["prompt", "out"]);
  });

  it("follows tunnel checks that run anywhere", () => {
    const snapshot = createTestSnapshot();
    expect(applyLiveServiceEventsToSnapshot(snapshot, [{ type: "tunnel-check-changed", running: true }])?.tunnelCheckRunning).toBe(true);
    const queue = new BoundedRendererEventQueue({ maxEvents: 10, maxTerminalBytes: 100 });
    queue.enqueue({ type: "tunnel-check-changed", running: true });
    queue.enqueue({ type: "tunnel-check-changed", running: false });
    expect(queue.drain()).toEqual([{ type: "tunnel-check-changed", running: false }]);
  });

  it("applies attention changes and active transport switches", () => {
    const snapshot = createTestSnapshot();
    const attention: AttentionEvent[] = [
      { id: "a1", at: "now", kind: "tun-unavailable", level: "warning", source: "routing", title: "TUN off", message: "Not elevated." }
    ];
    const xrayStatus = createTestRuntime({ state: "Connecting", transport: "xray", message: "Starting." });

    const updated = applyLiveServiceEventsToSnapshot(snapshot, [
      { type: "attention-changed", attention },
      { type: "active-transport-changed", transport: "xray", status: xrayStatus }
    ]);

    expect(updated?.attention).toEqual(attention);
    expect(updated?.activeTransport).toBe("xray");
    expect(updated?.runtime).toEqual(xrayStatus);
  });

  it("drops a stale tunnel check when the tunnel stops or a new connect starts", () => {
    const check: TunnelCheckResult = { endpoint: "youtube.com:443", ok: true, at: "now", message: "ok", latencyMs: 184 };
    const connected = createTestSnapshot({ runtime: createTestRuntime({ state: "Connected" }), lastTunnelCheck: check });

    const stillConnected = applyLiveServiceEventsToSnapshot(connected, [
      { type: "status-changed", status: createTestRuntime({ state: "Connected", message: "still up" }) }
    ]);
    expect(stillConnected?.lastTunnelCheck).toEqual(check);

    const stopped = applyLiveServiceEventsToSnapshot(connected, [
      { type: "status-changed", status: createTestRuntime({ state: "Disconnected" }) }
    ]);
    expect(stopped?.lastTunnelCheck).toBeUndefined();

    const reconnecting = applyLiveServiceEventsToSnapshot(connected, [
      { type: "status-changed", status: createTestRuntime({ state: "Reconnecting" }) }
    ]);
    expect(reconnecting?.lastTunnelCheck).toEqual(check);
  });

  it("keeps only the latest whole-state events in the pending queue", () => {
    const queue = new BoundedRendererEventQueue({ maxEvents: 10, maxTerminalBytes: 100 });
    queue.enqueue({ type: "attention-changed", attention: [] });
    queue.enqueue({ type: "snapshot-invalidated", reason: "tray" });
    queue.enqueue({ type: "attention-changed", attention: [] });
    queue.enqueue({ type: "snapshot-invalidated", reason: "tray again" });

    const drained = queue.drain();
    expect(drained.map((event) => event.type)).toEqual(["attention-changed", "snapshot-invalidated"]);
  });
});

describe("diagnostic sources", () => {
  it("keeps a stamped source and guesses one for older entries", () => {
    expect(diagnosticSource({ source: "update", message: "SSH" })).toBe("update");
    expect(diagnosticSource({ message: "Xray: [Error] core failed" })).toBe("xray");
    expect(diagnosticSource({ message: "Starting Hysteria 2 profile fi-hel-hy2." })).toBe("xray");
    expect(diagnosticSource({ message: "Imported 2 hy2 links." })).toBe("xray");
    expect(diagnosticSource({ message: "TUN adapter skipped: not elevated." })).toBe("routing");
    expect(diagnosticSource({ message: "Update 2.3.0 is available for Windows x64." })).toBe("update");
    expect(diagnosticSource({ message: "SSH session established." })).toBe("ssh");
    expect(diagnosticSource({ message: "Window hidden to tray." })).toBe("app");
  });
});
