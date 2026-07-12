import { describe, expect, it } from "vitest";
import { createDefaultRuntimeStatus, createDefaultStore } from "../src/shared/defaults.js";
import {
  applyLiveServiceEventsToSnapshot,
  applyServiceEventsToSnapshot
} from "../src/renderer/lib/diagnostics.js";
import type { AppSnapshot } from "../src/shared/types.js";

describe("renderer startup event replay", () => {
  it("replays events received around the initial snapshot without duplicating IDs", () => {
    const snapshot = createSnapshot();
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
    const snapshot = createSnapshot();
    const updated = applyLiveServiceEventsToSnapshot(snapshot, [
      { type: "terminal-output", line: { id: "empty", at: "1", stream: "stdout", text: "" } },
      { type: "terminal-output", line: { id: "one", at: "2", stream: "stdout", text: "one" } },
      { type: "terminal-output", line: { id: "two", at: "3", stream: "stderr", text: "two" } }
    ]);

    expect(updated?.terminal.map((line) => line.id)).toEqual(["one", "two"]);
  });
});

function createSnapshot(): AppSnapshot {
  return {
    store: createDefaultStore(),
    runtime: createDefaultRuntimeStatus({
      platform: "unknown",
      arch: "unknown",
      serviceExecutableName: "shadow-ssh-service",
      serviceRelativePath: "native/unknown/unknown/shadow-ssh-service",
      supportsPrivilegedService: false
    }),
    diagnostics: [],
    terminal: [],
    logFilePaths: []
  };
}
