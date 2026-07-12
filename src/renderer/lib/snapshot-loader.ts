import type { AppSnapshot } from "../../shared/types.js";

export const SNAPSHOT_LOAD_TIMEOUT_MS = 10_000;

/**
 * Converts synchronous preload failures and indefinitely pending IPC invokes
 * into one bounded promise so startup can always render an actionable error.
 */
export function loadSnapshotWithTimeout(
  load: () => Promise<AppSnapshot>,
  timeoutMs = SNAPSHOT_LOAD_TIMEOUT_MS
): Promise<AppSnapshot> {
  return new Promise<AppSnapshot>((resolve, reject) => {
    let settled = false;
    const finish = (operation: () => void): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      operation();
    };
    const timer = setTimeout(() => {
      finish(() => reject(new Error(
        `Initial application state did not arrive within ${Math.ceil(timeoutMs / 1000)} seconds. Check main.log and retry.`
      )));
    }, timeoutMs);

    Promise.resolve()
      .then(load)
      .then(
        (snapshot) => finish(() => resolve(snapshot)),
        (error: unknown) => finish(() => reject(error))
      );
  });
}
