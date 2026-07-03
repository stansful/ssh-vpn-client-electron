import { useState, type Dispatch, type SetStateAction } from "react";
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
  setBusy: Dispatch<SetStateAction<boolean>>;
  run: (action: () => Promise<AppSnapshot | void>) => Promise<void>;
  commitSnapshotAction: (action: () => Promise<AppSnapshot>, successMessage?: string) => Promise<void>;
} {
  const [busy, setBusy] = useState(false);

  async function run(action: () => Promise<AppSnapshot | void>): Promise<void> {
    setBusy(true);
    setNotice("");
    try {
      const next = await action();
      if (next) {
        setSnapshot(next);
      }
    } catch (error) {
      setNotice(toErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function commitSnapshotAction(action: () => Promise<AppSnapshot>, successMessage?: string): Promise<void> {
    setBusy(true);
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
      setBusy(false);
    }
  }

  return { busy, setBusy, run, commitSnapshotAction };
}
