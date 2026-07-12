import { useCallback, useEffect, useRef, useState, type Dispatch, type SetStateAction } from "react";
import { api } from "../api.js";
import { applyLiveServiceEventsToSnapshot, applyServiceEventsToSnapshot } from "../lib/diagnostics.js";
import { BoundedRendererEventQueue } from "../lib/renderer-event-queue.js";
import { loadSnapshotWithTimeout } from "../lib/snapshot-loader.js";
import { toErrorMessage } from "../lib/labels.js";
import type { AppSnapshot } from "../../shared/types.js";
import {
  MAX_TERMINAL_HISTORY_BYTES,
  MAX_TERMINAL_HISTORY_LINES
} from "../../shared/terminal-history.js";
import { MAX_RENDERER_DIAGNOSTICS } from "../types.js";

const MAX_PENDING_STARTUP_EVENTS = MAX_RENDERER_DIAGNOSTICS + MAX_TERMINAL_HISTORY_LINES + 100;

export function useSnapshot(): {
  snapshot: AppSnapshot | undefined;
  setSnapshot: Dispatch<SetStateAction<AppSnapshot | undefined>>;
  notice: string;
  setNotice: Dispatch<SetStateAction<string>>;
  startupError: string;
  retrySnapshot: () => void;
} {
  const [snapshot, setSnapshot] = useState<AppSnapshot | undefined>();
  const [notice, setNotice] = useState("");
  const [startupError, setStartupError] = useState("");
  const retrySnapshotRef = useRef<() => void>(() => undefined);
  const retrySnapshot = useCallback((): void => retrySnapshotRef.current(), []);

  useEffect(() => {
    let active = true;
    let hasSnapshot = false;
    let synchronized = false;
    let synchronizationGeneration = 0;
    let renderFrame: number | undefined;
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
      setSnapshot((current) => applyLiveServiceEventsToSnapshot(current, events));
    };

    const scheduleRender = (): void => {
      if (renderFrame === undefined) {
        renderFrame = requestAnimationFrame(flushRenderEvents);
      }
    };

    const off = api.onServiceEvent((event) => {
      if (!active || document.hidden) {
        return;
      }
      if (event.type === "error") {
        setNotice(event.message);
        return;
      }
      if (!synchronized) {
        pendingEvents.enqueue(event);
        return;
      }
      renderEvents.enqueue(event);
      scheduleRender();
    });

    const synchronizeSnapshot = (): void => {
      const generation = synchronizationGeneration + 1;
      synchronizationGeneration = generation;
      synchronized = false;
      pendingEvents.clear();
      renderEvents.clear();
      cancelRenderFrame();
      if (!hasSnapshot) {
        setStartupError("");
      }

      void loadSnapshotWithTimeout(() => api.loadSnapshot())
        .then((loaded) => {
          if (!active || synchronizationGeneration !== generation) {
            return;
          }
          const replayed = applyServiceEventsToSnapshot(loaded, pendingEvents.drain());
          synchronized = true;
          hasSnapshot = true;
          setStartupError("");
          setSnapshot(replayed);
        })
        .catch((error: unknown) => {
          if (!active || synchronizationGeneration !== generation) {
            return;
          }
          synchronized = false;
          pendingEvents.clear();
          const message = toErrorMessage(error);
          if (hasSnapshot) {
            setNotice(message);
          } else {
            setStartupError(message);
          }
        });
    };
    retrySnapshotRef.current = synchronizeSnapshot;

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
      pendingEvents.clear();
      renderEvents.clear();
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      document.documentElement.removeAttribute("data-document-hidden");
      retrySnapshotRef.current = () => undefined;
      off();
    };
  }, []);

  return { snapshot, setSnapshot, notice, setNotice, startupError, retrySnapshot };
}
