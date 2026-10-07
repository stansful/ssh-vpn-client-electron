import { useCallback, useRef, useState } from "react";
import { describeError } from "../lib/errors.js";
import type { AppSnapshot } from "../../shared/types.js";
import type { ToastApi, ToastInput } from "./useToasts.js";

export interface RunOptions {
  /** Toast shown when the action succeeds (a title string is a success toast). */
  success?: string | ToastInput;
  /** Title of the error toast, e.g. "Couldn't save server". The message comes from describeError. */
  errorTitle?: string;
  /** What was being reached, for friendly network errors ("GitHub"). */
  errorTarget?: string;
  /** Replace an earlier error toast about the same thing. */
  errorToastId?: string;
  /** Show no error toast; the caller reports the failure itself (combine with rethrow). */
  silent?: boolean;
  /** Re-throw the original error after reporting it. */
  rethrow?: boolean;
  /** Keep out of the global busy flag (long background work such as an update download). */
  background?: boolean;
}

/**
 * Runs an IPC action. A returned AppSnapshot, or an object carrying
 * `snapshot` (routing, imports, update checks), replaces the app snapshot.
 * Resolves to the action's result, or undefined when it failed.
 */
export type RunAction = <T>(action: () => Promise<T>, options?: RunOptions) => Promise<T | undefined>;

export function isAppSnapshot(value: unknown): value is AppSnapshot {
  return (
    typeof value === "object" &&
    value !== null &&
    "store" in value &&
    "runtime" in value &&
    "diagnostics" in value
  );
}

/** The snapshot inside an IPC result, if any. */
export function snapshotOf(value: unknown): AppSnapshot | undefined {
  if (isAppSnapshot(value)) {
    return value;
  }
  if (typeof value === "object" && value !== null && "snapshot" in value) {
    const nested = (value as { snapshot: unknown }).snapshot;
    return isAppSnapshot(nested) ? nested : undefined;
  }
  return undefined;
}

export function useAsyncAction({
  setSnapshot,
  toast
}: {
  setSnapshot: (snapshot: AppSnapshot) => void;
  toast: ToastApi["toast"];
}): { busy: boolean; run: RunAction } {
  const [busy, setBusy] = useState(false);
  const busyOperations = useRef(0);

  const track = useCallback((delta: 1 | -1): void => {
    busyOperations.current = Math.max(0, busyOperations.current + delta);
    setBusy(busyOperations.current > 0);
  }, []);

  const run = useCallback<RunAction>(async (action, options = {}) => {
    if (!options.background) {
      track(1);
    }
    try {
      const result = await action();
      const next = snapshotOf(result);
      if (next) {
        setSnapshot(next);
      }
      if (options.success) {
        toast(typeof options.success === "string" ? { tone: "success", title: options.success } : options.success);
      }
      return result;
    } catch (error) {
      if (!options.silent) {
        const described = describeError(error, { title: options.errorTitle, target: options.errorTarget });
        toast({
          id: options.errorToastId,
          tone: "error",
          title: described.title,
          message: described.message,
          details: described.technical
        });
      }
      if (options.rethrow) {
        throw error;
      }
      return undefined;
    } finally {
      if (!options.background) {
        track(-1);
      }
    }
  }, [setSnapshot, toast, track]);

  return { busy, run };
}
