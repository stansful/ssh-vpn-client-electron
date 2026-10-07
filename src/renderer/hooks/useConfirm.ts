import type { LucideIcon } from "lucide-react";
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { AsyncConfirmationController, type ConfirmationViewState } from "../lib/confirmation-controller.js";

export interface ConfirmOptions {
  /** Names the exact thing: "Delete Frankfurt-01?", "Remove 116 unpinned profiles?". */
  title: string;
  /** One or two sentences under the title about what happens. */
  description?: ReactNode;
  /** Small caps context above the title, e.g. "SSH servers". */
  eyebrow?: string;
  /** Extra content between the header and the buttons (item preview, callouts, key/value facts). */
  body?: ReactNode;
  /** Icon tile tone. Default "danger". */
  tone?: "danger" | "warn" | "info" | "accent";
  /** Icon in the tile. Default Trash2 for danger, TriangleAlert otherwise. */
  icon?: LucideIcon;
  /** Verb that repeats the object or count: "Delete server", "Remove 116 profiles". */
  confirmLabel: string;
  /** Label while the action runs, e.g. "Deleting…". Defaults to `confirmLabel` with a spinner. */
  busyLabel?: string;
  /** Default "danger-solid" (solid danger is reserved for confirmations). */
  confirmVariant?: "danger-solid" | "primary" | "danger";
  confirmIcon?: LucideIcon;
  /** Default "Cancel". Focus opens on it. */
  cancelLabel?: string;
  /** Optional left-aligned helper action in the footer, e.g. "Export first". */
  lead?: { label: string; onClick: () => void | Promise<void>; icon?: LucideIcon };
  /** Title of the inline error shown when `onConfirm` fails. */
  errorTitle?: string;
}

export interface ConfirmRequest extends ConfirmOptions {
  /**
   * Runs while the dialog shows progress; the dialog closes when it resolves.
   * A rejection keeps the dialog open with the error inside it.
   */
  onConfirm?: () => void | Promise<void>;
}

/** Opens the app-wide confirmation dialog. Resolves true when confirmed (and done), false when cancelled. */
export type ConfirmFn = (request: ConfirmRequest) => Promise<boolean>;

export const ConfirmContext = createContext<ConfirmFn>(() => Promise.resolve(false));

/** `const confirm = useConfirm(); if (await confirm({...})) …` */
export function useConfirm(): ConfirmFn {
  return useContext(ConfirmContext);
}

export interface ConfirmController {
  state: ConfirmationViewState<ConfirmOptions> | undefined;
  confirm: ConfirmFn;
  accept: () => Promise<boolean>;
  cancel: () => boolean;
}

/** Owns the single confirmation dialog; the app root renders it from `state`. */
export function useConfirmController(): ConfirmController {
  const [state, setState] = useState<ConfirmationViewState<ConfirmOptions>>();
  const controllerRef = useRef<AsyncConfirmationController<ConfirmOptions>>();
  if (!controllerRef.current) {
    controllerRef.current = new AsyncConfirmationController<ConfirmOptions>(setState);
  }

  const confirm = useCallback<ConfirmFn>(({ onConfirm, ...options }) => controllerRef.current!.request(options, onConfirm), []);
  const accept = useCallback((): Promise<boolean> => controllerRef.current!.confirm(), []);
  const cancel = useCallback((): boolean => controllerRef.current!.cancel(), []);

  return useMemo(() => ({ state, confirm, accept, cancel }), [accept, cancel, confirm, state]);
}
