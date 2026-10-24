import { stat } from "node:fs/promises";
import { NativeHelperClient } from "./native-helper-client.js";
import type { NativeServiceHandshake } from "./local-ipc-protocol.js";

/**
 * Undoing what a killed TUN helper left behind, as soon as the app starts.
 *
 * A helper that exits normally takes its routes down itself. One that was
 * killed - a crash, a forced quit, a power cut - leaves its routing changes
 * and the journal that describes them, and the next dataplane start undoes
 * them first. That start may be days away: a user who connects without
 * administrator rights, or with TUN off, never gets one, and in the meantime
 * the server's host route stays on the network card through every network
 * change. So the journal is replayed at startup too, whenever the app runs
 * with the rights to do it.
 */

/** The part of the helper this needs, so a test can stand in for it. */
export interface RouteRecoveryHelper {
  readonly handshake: NativeServiceHandshake | undefined;
  recoverRoutes(journalPath: string): Promise<number>;
  dispose(options?: { exitGraceMs?: number }): Promise<void>;
}

export interface TunRouteRecoveryOptions {
  /** `<userData>/tun-routing-journal.json`, the file both transports' helpers write. */
  journalPath: string;
  /** Whether this process runs elevated; the helper inherits its rights. */
  isElevated: () => Promise<boolean>;
  /** The native helper binary; used unless `startHelper` is given. */
  executablePath?: string;
  /** Injection seam for tests; defaults to spawning the helper. */
  startHelper?: () => Promise<RouteRecoveryHelper>;
  /** Injection seam for tests; defaults to the file's size on disk. */
  journalSize?: (journalPath: string) => Promise<number | undefined>;
}

export type TunRouteRecoveryOutcome =
  /** No journal, or an empty one: nothing was left behind. */
  | { kind: "nothing-to-recover" }
  /** A journal is there, but undoing it needs administrator rights. */
  | { kind: "not-elevated" }
  /** The helper predates `recover-routes`; the next dataplane start recovers instead. */
  | { kind: "unsupported" }
  | { kind: "recovered"; recovered: number }
  | { kind: "failed"; message: string };

/**
 * Replays the TUN route journal once, when there is one and the helper can.
 * Never throws: every way it can end is an outcome for the caller to log.
 */
export async function recoverLeftoverTunRoutes(options: TunRouteRecoveryOptions): Promise<TunRouteRecoveryOutcome> {
  const size = await (options.journalSize ?? fileSize)(options.journalPath).catch(() => undefined);
  if (size === undefined || size <= 0) {
    return { kind: "nothing-to-recover" };
  }
  try {
    if (!(await options.isElevated())) {
      return { kind: "not-elevated" };
    }
  } catch (error) {
    return { kind: "failed", message: `the elevation check failed: ${errorMessage(error)}` };
  }

  let helper: RouteRecoveryHelper;
  try {
    helper = await (options.startHelper ?? (() => startRecoveryHelper(options.executablePath)))();
  } catch (error) {
    return { kind: "failed", message: errorMessage(error) };
  }
  try {
    // Helpers built before the command answer it with an error at best;
    // only one that says it understands it is sent it.
    if (helper.handshake?.capabilities.routeRecovery !== true) {
      return { kind: "unsupported" };
    }
    const recovered = await helper.recoverRoutes(options.journalPath);
    return { kind: "recovered", recovered };
  } catch (error) {
    return { kind: "failed", message: errorMessage(error) };
  } finally {
    // It holds nothing once the command has answered; give it a moment to
    // exit on its own rather than killing it mid-write.
    await helper.dispose({ exitGraceMs: 2_000 }).catch(() => undefined);
  }
}

/** One line for the log and Activity, or nothing when there is nothing worth saying. */
export function describeTunRouteRecovery(outcome: TunRouteRecoveryOutcome): { level: "info" | "warning"; message: string } | undefined {
  switch (outcome.kind) {
    case "nothing-to-recover":
    case "unsupported":
      return undefined;
    case "not-elevated":
      return {
        level: "info",
        message: "Routing changes left by an earlier TUN session were found. They are undone the next time Shadow starts as administrator."
      };
    case "recovered":
      return outcome.recovered > 0
        ? { level: "info", message: `Undid ${outcome.recovered} routing change${outcome.recovered === 1 ? "" : "s"} left by an earlier TUN session.` }
        : undefined;
    case "failed":
      return {
        level: "warning",
        message: `Routing changes left by an earlier TUN session could not be undone at startup: ${outcome.message}`
      };
  }
}

async function startRecoveryHelper(executablePath: string | undefined): Promise<RouteRecoveryHelper> {
  if (!executablePath) {
    throw new Error("The native helper is not available in this build.");
  }
  // Like the dataplane's helper, it finishes the undo it is in the middle of
  // if the app quits meanwhile.
  return NativeHelperClient.start(executablePath, { detached: process.platform === "win32" });
}

async function fileSize(filePath: string): Promise<number | undefined> {
  try {
    const info = await stat(filePath);
    return info.isFile() ? info.size : undefined;
  } catch {
    return undefined;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
