import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { LeaveGuards, type LeaveGuard } from "../lib/leave-guards.js";
import type { NavigationIntent, View } from "../types.js";

export type NavigateFn = (view: View, intent?: NavigationIntent) => void;

export interface NavigationState {
  view: View;
  /** Set by `navigate(view, intent)`; a new object per call. */
  intent?: NavigationIntent;
  /** Increments on every navigation (also to the same view), for focus and scroll resets. */
  navigationId: number;
}

export interface NavigationApi extends NavigationState {
  /** Asks the registered leave guards first; navigates only when all of them agree. */
  navigate: NavigateFn;
  /** Drops the current intent once a page has acted on it. */
  clearIntent: () => void;
  /** Registers a check that runs before any navigation; returns its removal. */
  addLeaveGuard: (guard: LeaveGuard) => () => void;
}

export const NavigationContext = createContext<NavigationApi>({
  view: "connect",
  navigationId: 0,
  navigate: () => undefined,
  clearIntent: () => undefined,
  addLeaveGuard: () => () => undefined
});

/** Current view, intent and `navigate(view, intent?)`. */
export function useNavigation(): NavigationApi {
  return useContext(NavigationContext);
}

/** Owns navigation state for the app root. */
export function useNavigationState(initial: View = "connect"): NavigationApi {
  const [state, setState] = useState<NavigationState>({ view: initial, navigationId: 0 });
  const counter = useRef(0);
  const guards = useRef(new LeaveGuards());

  const navigate = useCallback<NavigateFn>((view, intent) => {
    const go = (): void => {
      counter.current += 1;
      const navigationId = counter.current;
      // Copy the intent so a page effect keyed on it always fires, even for a
      // repeated request with an equal value.
      setState({ view, intent: intent ? { ...intent } : undefined, navigationId });
    };
    if (guards.current.isEmpty) {
      go();
      return;
    }
    void guards.current.confirmLeave().then((leave) => {
      if (leave) {
        go();
      }
    });
  }, []);

  const clearIntent = useCallback((): void => {
    setState((current) => (current.intent ? { ...current, intent: undefined } : current));
  }, []);

  const addLeaveGuard = useCallback((guard: LeaveGuard) => guards.current.add(guard), []);

  return useMemo(() => ({ ...state, navigate, clearIntent, addLeaveGuard }), [addLeaveGuard, clearIntent, navigate, state]);
}

/**
 * Asks `guard` before navigating away while it is set, e.g. a form's
 * "Discard changes?" while it has unsaved edits. Pass undefined to stop.
 */
export function useLeaveGuard(guard: LeaveGuard | undefined): void {
  const { addLeaveGuard } = useNavigation();
  const latest = useRef(guard);
  latest.current = guard;
  const active = guard !== undefined;
  useEffect(() => {
    if (!active) {
      return undefined;
    }
    return addLeaveGuard(() => latest.current?.() ?? Promise.resolve(true));
  }, [active, addLeaveGuard]);
}
