import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { applyLiveServiceEventsToSnapshot, applyServiceEventsToSnapshot } from "../lib/diagnostics.js";
import { errorText } from "../lib/errors.js";
import { BoundedRendererEventQueue } from "../lib/renderer-event-queue.js";
import { loadSnapshotWithTimeout } from "../lib/snapshot-loader.js";
import type { AppSnapshot } from "../../shared/types.js";
import {
  MAX_TERMINAL_HISTORY_BYTES,
  MAX_TERMINAL_HISTORY_LINES
} from "../../shared/terminal-history.js";
import { MAX_RENDERER_DIAGNOSTICS } from "../types.js";

const MAX_PENDING_STARTUP_EVENTS = MAX_RENDERER_DIAGNOSTICS + MAX_TERMINAL_HISTORY_LINES + 100;
/** Coalesces bursts of `snapshot-invalidated` (tray actions often send several). */
const INVALIDATION_DEBOUNCE_MS = 40;

export type StartupState =
  | { phase: "loading"; attempts: number }
  | { phase: "ready"; attempts: number }
  | { phase: "error"; attempts: number; error: string };

export type SnapshotUpdate = AppSnapshot | ((current: AppSnapshot) => AppSnapshot);

export interface SnapshotCallbacks {
  /** A service reported an error event (shown as a toast). */
  onServiceError?: (message: string) => void;
  /** Re-reading the snapshot failed after the app was already showing one. */
  onRefreshError?: (error: unknown, retry: () => void) => void;
}

/**
 * Loads the snapshot, keeps it current from renderer events (batched per
 * animation frame), replays events that arrive while a load is in flight,
 * and reloads it when the window becomes visible or the main process says it
 * changed (`snapshot-invalidated`).
 */
export function useSnapshot(callbacks: SnapshotCallbacks = {}): {
  snapshot: AppSnapshot | undefined;
  setSnapshot: (update: SnapshotUpdate) => void;
  startup: StartupState;
  /** Re-reads the snapshot (also the startup screen's Try again). */
  reload: () => void;
} {
  const [snapshot, setSnapshotState] = useState<AppSnapshot | undefined>();
  const [startup, setStartup] = useState<StartupState>({ phase: "loading", attempts: 0 });
  const callbacksRef = useRef(callbacks);
  callbacksRef.current = callbacks;
  const reloadRef = useRef<() => void>(() => undefined);
  const reload = useCallback((): void => reloadRef.current(), []);

  const setSnapshot = useCallback((update: SnapshotUpdate): void => {
    setSnapshotState((current) => {
      if (typeof update === "function") {
        return current ? update(current) : current;
      }
      return update;
    });
  }, []);

  useEffect(() => {
    let active = true;
    let hasSnapshot = false;
    let synchronized = false;
    let synchronizationGeneration = 0;
    let attempts = 0;
    let renderFrame: number | undefined;
    let invalidationTimer: number | undefined;
    const pendingEvents = new BoundedRendererEventQueue({
      maxEvents: MAX_PENDING_STARTUP_EVENTS,
      maxTerminalBytes: MAX_TERMINAL_HISTORY_BYTES
    });
    const renderEvents = new BoundedRendererEventQueue({
      maxEvents: MAX_PENDING_STARTUP_EVENTS,
      maxTerminalBytes: MAX_TERMINAL_HISTORY_BYTES
    });

    const cancelRenderFrame = (): void => {
      if (renderFrame !== undefined) {
        cancelAnimationFrame(renderFrame);
        renderFrame = undefined;
      }
    };

    const flushRenderEvents = (): void => {
      renderFrame = undefined;
      const events = renderEvents.drain();
      if (events.length === 0 || document.hidden) {
        return;
      }
      setSnapshotState((current) => applyLiveServiceEventsToSnapshot(current, events));
    };

    const scheduleRender = (): void => {
      if (renderFrame === undefined) {
        renderFrame = requestAnimationFrame(flushRenderEvents);
      }
    };

    const synchronizeSnapshot = (): void => {
      const generation = synchronizationGeneration + 1;
      synchronizationGeneration = generation;
      synchronized = false;
      pendingEvents.clear();
      renderEvents.clear();
      cancelRenderFrame();
      attempts += 1;
      if (!hasSnapshot) {
        setStartup({ phase: "loading", attempts });
      }

      void loadSnapshotWithTimeout(() => api.loadSnapshot())
        .then((loaded) => {
          if (!active || synchronizationGeneration !== generation) {
            return;
          }
          const replayed = applyServiceEventsToSnapshot(loaded, pendingEvents.drain());
          synchronized = true;
          hasSnapshot = true;
          attempts = 0;
          setStartup({ phase: "ready", attempts: 0 });
          setSnapshotState(replayed);
        })
        .catch((error: unknown) => {
          if (!active || synchronizationGeneration !== generation) {
            return;
          }
          synchronized = false;
          pendingEvents.clear();
          if (hasSnapshot) {
            callbacksRef.current.onRefreshError?.(error, synchronizeSnapshot);
          } else {
            setStartup({ phase: "error", attempts, error: errorText(error) });
          }
        });
    };
    reloadRef.current = synchronizeSnapshot;

    const scheduleInvalidation = (): void => {
      if (invalidationTimer !== undefined) {
        window.clearTimeout(invalidationTimer);
      }
      invalidationTimer = window.setTimeout(() => {
        invalidationTimer = undefined;
        if (active && !document.hidden) {
          synchronizeSnapshot();
        }
      }, INVALIDATION_DEBOUNCE_MS);
    };

    const off = api.onServiceEvent((event) => {
      if (!active || document.hidden) {
        return;
      }
      if (event.type === "error") {
        callbacksRef.current.onServiceError?.(event.message);
        return;
      }
      if (event.type === "snapshot-invalidated") {
        scheduleInvalidation();
        return;
      }
      if (!synchronized) {
        pendingEvents.enqueue(event);
        return;
      }
      renderEvents.enqueue(event);
      scheduleRender();
    });

    const handleVisibilityChange = (): void => {
      document.documentElement.toggleAttribute("data-document-hidden", document.hidden);
      if (document.hidden) {
        synchronized = false;
        pendingEvents.clear();
        renderEvents.clear();
        cancelRenderFrame();
        return;
      }
      synchronizeSnapshot();
    };

    document.addEventListener("visibilitychange", handleVisibilityChange);
    document.documentElement.toggleAttribute("data-document-hidden", document.hidden);
    // The first state request must not depend on Page Visibility. Chromium can
    // report a newly shown Windows renderer as hidden during the first effect.
    synchronizeSnapshot();

    return () => {
      active = false;
      synchronizationGeneration += 1;
      synchronized = false;
      cancelRenderFrame();
      if (invalidationTimer !== undefined) {
        window.clearTimeout(invalidationTimer);
      }
      pendingEvents.clear();
      renderEvents.clear();
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      document.documentElement.removeAttribute("data-document-hidden");
      reloadRef.current = () => undefined;
      off();
    };
  }, []);

  return { snapshot, setSnapshot, startup, reload };
}
