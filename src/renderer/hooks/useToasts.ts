import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { pushToast, removeToast, type ToastInput, type ToastRecord } from "../lib/toast-queue.js";

export type { ToastAction, ToastInput, ToastRecord, ToastTone } from "../lib/toast-queue.js";

export interface ToastApi {
  /** Shows a toast and returns its id. Pass `id` to replace an earlier toast about the same thing. */
  toast: (input: ToastInput) => string;
  /** Closes a toast with its exit animation. */
  dismiss: (id: string) => void;
}

/** A toast on screen, possibly playing its exit animation. */
export interface VisibleToast extends ToastRecord {
  leaving: boolean;
}

const TOAST_EXIT_MS = 220;

const noopApi: ToastApi = {
  toast: () => "",
  dismiss: () => undefined
};

export const ToastContext = createContext<ToastApi>(noopApi);

/** Imperative toasts from anywhere under the app shell. */
export function useToasts(): ToastApi {
  return useContext(ToastContext);
}

/** Owns the toast stack; the app root provides `api` and renders `toasts`. */
export function useToastController(): { toasts: VisibleToast[]; api: ToastApi } {
  const [records, setRecords] = useState<ToastRecord[]>([]);
  const [leaving, setLeaving] = useState<ReadonlySet<string>>(new Set());
  const counter = useRef(0);
  const exitTimers = useRef(new Map<string, number>());

  const finishExit = useCallback((id: string): void => {
    exitTimers.current.delete(id);
    setRecords((current) => removeToast(current, id));
    setLeaving((current) => {
      if (!current.has(id)) {
        return current;
      }
      const next = new Set(current);
      next.delete(id);
      return next;
    });
  }, []);

  const dismiss = useCallback((id: string): void => {
    if (exitTimers.current.has(id)) {
      return;
    }
    setLeaving((current) => new Set(current).add(id));
    exitTimers.current.set(id, window.setTimeout(() => finishExit(id), TOAST_EXIT_MS));
  }, [finishExit]);

  const toast = useCallback((input: ToastInput): string => {
    counter.current += 1;
    const id = input.id ?? `toast-${counter.current}`;
    const pendingExit = exitTimers.current.get(id);
    if (pendingExit !== undefined) {
      window.clearTimeout(pendingExit);
      exitTimers.current.delete(id);
      setLeaving((current) => {
        const next = new Set(current);
        next.delete(id);
        return next;
      });
    }
    setRecords((current) => pushToast(current, input, id));
    return id;
  }, []);

  useEffect(() => {
    const timers = exitTimers.current;
    return () => {
      for (const timer of timers.values()) {
        window.clearTimeout(timer);
      }
      timers.clear();
    };
  }, []);

  const api = useMemo<ToastApi>(() => ({ toast, dismiss }), [dismiss, toast]);
  const toasts = useMemo(
    () => records.map((record) => ({ ...record, leaving: leaving.has(record.id) })),
    [leaving, records]
  );
  return { toasts, api };
}
