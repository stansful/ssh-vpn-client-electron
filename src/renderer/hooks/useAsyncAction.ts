import { useCallback, useRef, useState, type Dispatch, type SetStateAction } from "react";
import { toErrorMessage } from "../lib/labels.js";
import type { AppSnapshot } from "../../shared/types.js";

export function useAsyncAction({
  setSnapshot,
  setNotice
}: {
  setSnapshot: Dispatch<SetStateAction<AppSnapshot | undefined>>;
  setNotice: Dispatch<SetStateAction<string>>;
}): {
  busy: boolean;
  setBusy: (value: boolean) => void;
  run: (action: () => Promise<AppSnapshot | void>) => Promise<void>;
  commitSnapshotAction: (action: () => Promise<AppSnapshot>, successMessage?: string) => Promise<void>;
} {
  const [busy, setBusy] = useState(false);
  const busyOperations = useRef(0);
  const setOperationBusy = useCallback((value: boolean): void => {
    busyOperations.current = Math.max(0, busyOperations.current + (value ? 1 : -1));
    setBusy(busyOperations.current > 0);
  }, []);

  const run = useCallback(async (action: () => Promise<AppSnapshot | void>): Promise<void> => {
    setOperationBusy(true);
    setNotice("");
    try {
      const next = await action();
      if (next) {
        setSnapshot(next);
      }
    } catch (error) {
      setNotice(toErrorMessage(error));
    } finally {
      setOperationBusy(false);
    }
  }, [setNotice, setOperationBusy, setSnapshot]);

  const commitSnapshotAction = useCallback(async (
    action: () => Promise<AppSnapshot>,
    successMessage?: string
  ): Promise<void> => {
    setOperationBusy(true);
    setNotice("");
    try {
      const next = await action();
      setSnapshot(next);
      if (successMessage) {
        setNotice(successMessage);
      }
    } catch (error) {
      const message = toErrorMessage(error);
      setNotice(message);
      throw new Error(message);
    } finally {
      setOperationBusy(false);
    }
  }, [setNotice, setOperationBusy, setSnapshot]);

  return { busy, setBusy: setOperationBusy, run, commitSnapshotAction };
}
