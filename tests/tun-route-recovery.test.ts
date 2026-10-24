import { describe, expect, it, vi } from "vitest";
import type { NativeServiceHandshake } from "../src/service/local-ipc-protocol.js";
import {
  describeTunRouteRecovery,
  recoverLeftoverTunRoutes,
  type RouteRecoveryHelper,
  type TunRouteRecoveryOptions
} from "../src/service/tun-route-recovery.js";

// A helper that was killed leaves its routing changes and their journal
// behind, and only the next TUN start used to undo them. These cases pin the
// startup replay: when it runs, when it must not, and what it says.

const JOURNAL = "C:\\Users\\u\\AppData\\Roaming\\Shadow SSH\\tun-routing-journal.json";

function fakeHelper(options: { routeRecovery?: boolean; recovered?: number; error?: Error } = {}): RouteRecoveryHelper & {
  recoverRoutes: ReturnType<typeof vi.fn>;
  dispose: ReturnType<typeof vi.fn>;
} {
  const capabilities = { routeRecovery: options.routeRecovery } as unknown as NativeServiceHandshake["capabilities"];
  return {
    handshake: { protocolVersion: 1, capabilities },
    recoverRoutes: vi.fn(async () => {
      if (options.error) {
        throw options.error;
      }
      return options.recovered ?? 0;
    }),
    dispose: vi.fn(async () => undefined)
  };
}

function recover(overrides: Partial<TunRouteRecoveryOptions>): ReturnType<typeof recoverLeftoverTunRoutes> {
  return recoverLeftoverTunRoutes({
    journalPath: JOURNAL,
    isElevated: async () => true,
    journalSize: async () => 120,
    startHelper: async () => fakeHelper({ routeRecovery: true }),
    ...overrides
  });
}

describe("TUN route recovery at startup", () => {
  it("does nothing without a journal, or with an empty one", async () => {
    const startHelper = vi.fn(async () => fakeHelper({ routeRecovery: true }));
    const isElevated = vi.fn(async () => true);
    await expect(recover({ journalSize: async () => undefined, startHelper, isElevated })).resolves.toEqual({ kind: "nothing-to-recover" });
    await expect(recover({ journalSize: async () => 0, startHelper, isElevated })).resolves.toEqual({ kind: "nothing-to-recover" });
    expect(startHelper).not.toHaveBeenCalled();
    expect(isElevated).not.toHaveBeenCalled();
  });

  it("leaves the journal for an elevated start when the app is not elevated", async () => {
    const startHelper = vi.fn(async () => fakeHelper({ routeRecovery: true }));
    const outcome = await recover({ isElevated: async () => false, startHelper });
    expect(outcome).toEqual({ kind: "not-elevated" });
    expect(startHelper).not.toHaveBeenCalled();
    expect(describeTunRouteRecovery(outcome)?.message).toContain("next time Shadow starts as administrator");
  });

  it("never sends the command to a helper that does not advertise it", async () => {
    // Committed helper binaries from before the command answer it with an
    // error at best.
    const helper = fakeHelper({ routeRecovery: undefined });
    await expect(recover({ startHelper: async () => helper })).resolves.toEqual({ kind: "unsupported" });
    expect(helper.recoverRoutes).not.toHaveBeenCalled();
    expect(helper.dispose).toHaveBeenCalledTimes(1);
    expect(describeTunRouteRecovery({ kind: "unsupported" })).toBeUndefined();
  });

  it("replays the journal once and lets the helper go", async () => {
    const helper = fakeHelper({ routeRecovery: true, recovered: 3 });
    const outcome = await recover({ startHelper: async () => helper });
    expect(outcome).toEqual({ kind: "recovered", recovered: 3 });
    expect(helper.recoverRoutes).toHaveBeenCalledExactlyOnceWith(JOURNAL);
    expect(helper.dispose).toHaveBeenCalledTimes(1);
    expect(describeTunRouteRecovery(outcome)).toEqual({ level: "info", message: "Undid 3 routing changes left by an earlier TUN session." });
    expect(describeTunRouteRecovery({ kind: "recovered", recovered: 0 })).toBeUndefined();
  });

  it("reports a failure instead of throwing, and still lets the helper go", async () => {
    const helper = fakeHelper({ routeRecovery: true, error: new Error("netsh did not answer") });
    const outcome = await recover({ startHelper: async () => helper });
    expect(outcome).toEqual({ kind: "failed", message: "netsh did not answer" });
    expect(helper.dispose).toHaveBeenCalledTimes(1);
    expect(describeTunRouteRecovery(outcome)).toMatchObject({ level: "warning", message: expect.stringContaining("netsh did not answer") });

    await expect(recover({ startHelper: async () => Promise.reject(new Error("spawn ENOENT")) })).resolves.toEqual({
      kind: "failed",
      message: "spawn ENOENT"
    });
    await expect(recover({ isElevated: async () => Promise.reject(new Error("whoami failed")) })).resolves.toMatchObject({ kind: "failed" });
  });
});
