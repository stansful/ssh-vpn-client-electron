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

  function openDownloadedUpdate(): void {
    void run(async () => {
      await api.openDownloadedUpdate();
    });
  }

  return {
    checkForUpdates,
    downloadUpdate,
    openDownloadedUpdate
  };
}
