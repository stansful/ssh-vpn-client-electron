import type { Dispatch, SetStateAction } from "react";
import { api } from "../api.js";
import type { AppSnapshot } from "../../shared/types.js";

export function useUpdateController({
  run,
  setNotice
}: {
  run: (action: () => Promise<AppSnapshot | void>) => Promise<void>;
  setNotice: Dispatch<SetStateAction<string>>;
}) {
  function checkForUpdates(): void {
    void run(async () => {
      const { snapshot: next, update } = await api.checkForUpdates(true);
      setNotice(update.message);
      return next;
    });
  }

  function downloadUpdate(): void {
    void run(async () => {
      const next = await api.downloadUpdate();
      setNotice(next.updateDownload?.message ?? "Update downloaded.");
      return next;
    });
  }

  function revealDownloadedUpdate(): void {
    void run(async () => {
      const revealed = await api.revealDownloadedUpdate();
      if (!revealed) {
        throw new Error("No downloaded update file is available.");
      }
      setNotice("Opened update folder.");
    });
  }

  return {
    checkForUpdates,
    downloadUpdate,
    revealDownloadedUpdate
  };
}
