import { useCallback, useMemo, useRef, useState } from "react";
import { snapshotOf } from "../../../hooks/useAsyncAction.js";
import type { SnapshotUpdate } from "../../../hooks/useSnapshot.js";
import { describeError } from "../../../lib/errors.js";
import type { AppSnapshot, RoutingMutationResult } from "../../../../shared/types.js";

export type SaveStatus = "saved" | "saving" | "failed" | "unapplied";

export interface AutosaveState {
  status: SaveStatus;
  /** Plain reason of the failed save, or of the change that couldn't be applied. */
  reason?: string;
}

export interface SaveOptions {
  /** Repeats the change after it failed to save (Try again). */
  retry?: () => void;
  /** The caller shows errors inline (list downloads); the badge returns to its previous state. */
  inlineErrors?: boolean;
  /** Leave the badge alone while the change runs (list refreshes). */
  quiet?: boolean;
}

export type SaveOutcome =
  | { ok: true; snapshot?: AppSnapshot; applyError?: string }
  | { ok: false; error: unknown };

export interface RoutingAutosave {
  state: AutosaveState;
  /** Runs a routing mutation and tracks it in the badge. Only the latest save decides the badge. */
  save: (operation: () => Promise<RoutingMutationResult | AppSnapshot>, options?: SaveOptions) => Promise<SaveOutcome>;
  /** Try again: repeats a failed save, or re-applies a saved change the tunnel didn't take. */
  retry: () => void;
  /** Nothing is left to apply (the session ended). */
  clearUnapplied: () => void;
}

/**
 * Autosave for the Routing page. Changes save first and apply second, so the
 * badge tells "Not saved" (a write failed) apart from "Saved · not applied"
 * (the running tunnel refused it). Every returned snapshot is applied: the
 * main process handles mutations in order, so a later one already contains
 * the earlier ones.
 */
export function useRoutingAutosave(setSnapshot: (update: SnapshotUpdate) => void, reapply: () => void): RoutingAutosave {
  const [state, setState] = useState<AutosaveState>({ status: "saved" });
  const sequence = useRef(0);
  const settled = useRef<AutosaveState>({ status: "saved" });
  const retryRef = useRef<(() => void) | undefined>();
  const reapplyRef = useRef(reapply);
  reapplyRef.current = reapply;

  const settle = useCallback((next: AutosaveState): void => {
    settled.current = next;
    setState(next);
  }, []);

  const save = useCallback<RoutingAutosave["save"]>(async (operation, options = {}) => {
    const token = options.quiet ? sequence.current : ++sequence.current;
    if (!options.quiet) {
      setState({ status: "saving" });
    }
    try {
      const result = await operation();
      const snapshot = snapshotOf(result);
      if (snapshot) {
        setSnapshot(snapshot);
      }
      const applyError = !snapshot || "store" in result ? undefined : result.applyError;
      if (token === sequence.current) {
        if (applyError) {
          retryRef.current = undefined;
          settle({ status: "unapplied", reason: describeError(applyError).message });
        } else if (!options.quiet || settled.current.status === "unapplied") {
          retryRef.current = undefined;
          settle({ status: "saved" });
        }
      }
      return { ok: true, snapshot, applyError };
    } catch (error) {
      if (token === sequence.current && !options.quiet) {
        if (options.inlineErrors) {
          setState(settled.current);
        } else {
          retryRef.current = options.retry;
          settle({ status: "failed", reason: describeError(error).message });
        }
      }
      return { ok: false, error };
    }
  }, [setSnapshot, settle]);

  const retry = useCallback((): void => {
    if (settled.current.status === "failed" && retryRef.current) {
      retryRef.current();
    } else {
      reapplyRef.current();
    }
  }, []);

  const clearUnapplied = useCallback((): void => {
    if (settled.current.status === "unapplied") {
      settle({ status: "saved" });
    }
  }, [settle]);

  return useMemo(() => ({ state, save, retry, clearUnapplied }), [clearUnapplied, retry, save, state]);
}
