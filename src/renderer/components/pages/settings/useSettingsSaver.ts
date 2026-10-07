import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import type { AppSettings } from "../../../../shared/types.js";
import { withSettingsPatch } from "./settings-model.js";

const SAVED_FLASH_MS = 1800;

export interface SaveOptions {
  /** Wait this long for more changes before saving (colour pickers send a stream of values). */
  debounceMs?: number;
}

export interface SettingsSaver {
  /** Applies the patch at once (optimistically) and saves it. */
  save: (patch: Partial<AppSettings>, options?: SaveOptions) => void;
  /** "saved" for a moment after a save lands; drives the header badge. */
  status: "idle" | "saved";
  /** Bumps on every saved flash so the badge animation replays. */
  savedKey: number;
}

/**
 * Settings apply the moment they change: the snapshot is patched right away
 * (theme and colours repaint live) and saves run one at a time in the
 * background, merging changes made while one is in flight. A failed save
 * reloads the snapshot so the screen shows what is really stored.
 */
export function useSettingsSaver(): SettingsSaver {
  const { run, setSnapshot, reloadSnapshot } = useAppData();
  const [status, setStatus] = useState<"idle" | "saved">("idle");
  const [savedKey, setSavedKey] = useState(0);
  const queued = useRef<Partial<AppSettings>>();
  const inFlight = useRef(false);
  const debounceTimer = useRef<number>();
  const flashTimer = useRef<number>();
  const mounted = useRef(true);

  const flash = useCallback((): void => {
    if (!mounted.current) {
      return;
    }
    setStatus("saved");
    setSavedKey((key) => key + 1);
    window.clearTimeout(flashTimer.current);
    flashTimer.current = window.setTimeout(() => setStatus("idle"), SAVED_FLASH_MS);
  }, []);

  const flush = useCallback(async (): Promise<void> => {
    if (inFlight.current || !queued.current) {
      return;
    }
    const patch = queued.current;
    queued.current = undefined;
    inFlight.current = true;
    // `{ saved }` keeps run() from applying the reply itself: newer local changes may be waiting.
    const result = await run(async () => ({ saved: await api.updateSettings(patch) }), {
      background: true,
      errorTitle: "Couldn't save the setting",
      errorToastId: "settings-save-failed"
    });
    inFlight.current = false;
    if (result) {
      const pending = queued.current;
      setSnapshot(pending ? withSettingsPatch(result.saved, pending) : result.saved);
      if (!pending && debounceTimer.current === undefined) {
        flash();
      }
    } else {
      reloadSnapshot();
    }
    if (queued.current && debounceTimer.current === undefined) {
      void flush();
    }
  }, [flash, reloadSnapshot, run, setSnapshot]);

  const save = useCallback((patch: Partial<AppSettings>, options: SaveOptions = {}): void => {
    setSnapshot((current) => withSettingsPatch(current, patch));
    queued.current = { ...queued.current, ...patch };
    window.clearTimeout(debounceTimer.current);
    debounceTimer.current = undefined;
    if (options.debounceMs) {
      debounceTimer.current = window.setTimeout(() => {
        debounceTimer.current = undefined;
        void flush();
      }, options.debounceMs);
      return;
    }
    void flush();
  }, [flush, setSnapshot]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      window.clearTimeout(flashTimer.current);
      // Leaving the page must not drop a colour that is still waiting for its debounce.
      if (debounceTimer.current !== undefined) {
        window.clearTimeout(debounceTimer.current);
        debounceTimer.current = undefined;
        void flush();
      }
    };
  }, [flush]);

  return { save, status, savedKey };
}
