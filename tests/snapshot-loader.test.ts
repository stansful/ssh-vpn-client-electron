import { afterEach, describe, expect, it, vi } from "vitest";
import { loadSnapshotWithTimeout } from "../src/renderer/lib/snapshot-loader.js";
import { createDefaultRuntimeStatus, createDefaultStore } from "../src/shared/defaults.js";
import type { AppSnapshot } from "../src/shared/types.js";

afterEach(() => {
  vi.useRealTimers();
});

describe("renderer snapshot loader", () => {
  it("resolves a preload snapshot", async () => {
    const snapshot = createSnapshot();

    await expect(loadSnapshotWithTimeout(async () => snapshot, 100)).resolves.toBe(snapshot);
  });

  it("converts a synchronous preload throw into a rejected promise", async () => {
    await expect(
      loadSnapshotWithTimeout(() => {
        throw new Error("preload bridge failed");
      }, 100)
    ).rejects.toThrow("preload bridge failed");
  });

  it("rejects a never-settling IPC invoke after the startup deadline", async () => {
    vi.useFakeTimers();
    const pending = loadSnapshotWithTimeout(() => new Promise<AppSnapshot>(() => undefined), 1_000);
    const rejection = expect(pending).rejects.toThrow("did not arrive within 1 seconds");

    await vi.advanceTimersByTimeAsync(1_000);

    await rejection;
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
