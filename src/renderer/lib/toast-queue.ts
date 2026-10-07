import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export type ToastTone = "success" | "info" | "warning" | "error";

export interface ToastAction {
  label: string;
  onClick: () => void | Promise<void>;
  icon?: LucideIcon;
  /** "side" puts a short action (Undo) next to the text; "below" (default) under it. */
  placement?: "side" | "below";
  /** Close the toast after the action runs. Default true. */
  dismiss?: boolean;
}

export interface ToastInput {
  tone: ToastTone;
  title: string;
  message?: ReactNode;
  /** Raw technical text, shown under a collapsible "Technical details" with Copy. */
  details?: string;
  action?: ToastAction;
  /** Milliseconds; `null` keeps the toast until closed. Defaults by tone (see toastDuration). */
  duration?: number | null;
  /** Reuse an id to replace the toast about the same thing instead of stacking a new one. */
  id?: string;
  /** Overrides the tone's icon in the tile. */
  icon?: LucideIcon;
}

export interface ToastRecord extends Omit<ToastInput, "id" | "duration"> {
  id: string;
  /** Resolved lifetime in ms, or null for sticky toasts. */
  duration: number | null;
  /** Bumps when a toast with the same id replaces it, restarting its timer. */
  revision: number;
}

/** Up to three toasts at once; the oldest one leaves first. */
export const MAX_VISIBLE_TOASTS = 3;
export const TOAST_DURATION_MS = 5000;
export const TOAST_WITH_ACTION_DURATION_MS = 8000;

/**
 * Success and info close after 5 s, 8 s when they carry an action; warnings
 * stay while the state lasts and errors until closed.
 */
export function toastDuration(input: Pick<ToastInput, "tone" | "action" | "duration">): number | null {
  if (input.duration !== undefined) {
    return input.duration;
  }
  if (input.tone === "warning" || input.tone === "error") {
    return null;
  }
  return input.action ? TOAST_WITH_ACTION_DURATION_MS : TOAST_DURATION_MS;
}

/** Adds or replaces a toast and trims the stack to `max`, dropping the oldest first. */
export function pushToast(list: readonly ToastRecord[], input: ToastInput, id: string, max = MAX_VISIBLE_TOASTS): ToastRecord[] {
  const existing = list.find((toast) => toast.id === id);
  const record: ToastRecord = {
    ...input,
    id,
    duration: toastDuration(input),
    revision: existing ? existing.revision + 1 : 0
  };
  const next = existing ? list.map((toast) => (toast.id === id ? record : toast)) : [...list, record];
  return next.length > max ? next.slice(next.length - max) : next;
}

export function removeToast(list: readonly ToastRecord[], id: string): ToastRecord[] {
  return list.filter((toast) => toast.id !== id);
}
