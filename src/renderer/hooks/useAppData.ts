import { createContext, useContext } from "react";
import type { AppEnvironment, AppSettings, AppSnapshot, AppStore, GlobalTab, RuntimeStatus } from "../../shared/types.js";
import type { ConfirmFn } from "./useConfirm.js";
import type { RunAction } from "./useAsyncAction.js";
import type { NavigateFn } from "./useNavigation.js";
import type { SnapshotUpdate } from "./useSnapshot.js";
import type { ToastApi } from "./useToasts.js";

/**
 * Everything a page needs, provided by App once the snapshot has loaded.
 * Pages read it with `useAppData()` and stay self-contained.
 */
export interface AppData {
  /** The latest snapshot (kept live by renderer events). */
  snapshot: AppSnapshot;
  store: AppStore;
  /** Status of the active transport. */
  runtime: RuntimeStatus;
  /** Which transport owns `runtime` (and the tunnel, if one runs). */
  activeTransport: GlobalTab;
  environment: AppEnvironment;
  /** True while any foreground `run` action is in flight (update downloads excluded). */
  busy: boolean;
  /**
   * Runs an IPC call with busy tracking and error toasts; applies a returned
   * snapshot (or `{ snapshot }`). Resolves to the result or undefined on failure.
   */
  run: RunAction;
  /** Shows a toast; returns its id. */
  toast: ToastApi["toast"];
  dismissToast: ToastApi["dismiss"];
  /** Opens the confirmation dialog; resolves true when confirmed and done. */
  confirm: ConfirmFn;
  navigate: NavigateFn;
  /** Replace or update the snapshot directly (functional updates receive the current one). */
  setSnapshot: (update: SnapshotUpdate) => void;
  /** Saves a settings patch through `run` and applies the returned snapshot. */
  updateSettings: (patch: Partial<AppSettings>) => Promise<AppSnapshot | undefined>;
  /**
   * Copies text with the shared feedback rules: resolves true when copied,
   * shows an error toast when it could not be copied.
   */
  copyText: (text: string) => Promise<boolean>;
  /** Re-reads the whole snapshot from the main process. */
  reloadSnapshot: () => void;
}

export const AppDataContext = createContext<AppData | null>(null);

/** App-wide data and actions. Only valid under the app shell (after the snapshot loaded). */
export function useAppData(): AppData {
  const value = useContext(AppDataContext);
  if (!value) {
    throw new Error("useAppData() must be used inside the Shadow SSH app shell.");
  }
  return value;
}
