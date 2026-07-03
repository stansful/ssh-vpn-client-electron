import { useEffect, useState, type Dispatch, type SetStateAction } from "react";
import { api } from "../api.js";
import { formatRuntimeDiagnostics } from "../lib/diagnostics.js";
import { toErrorMessage } from "../lib/labels.js";
import type { View } from "../types.js";
import type { AppSnapshot } from "../../shared/types.js";

export function useLogsController({
  view,
  snapshot,
  setSnapshot,
  setNotice
}: {
  view: View;
  snapshot: AppSnapshot | undefined;
  setSnapshot: Dispatch<SetStateAction<AppSnapshot | undefined>>;
  setNotice: Dispatch<SetStateAction<string>>;
}) {
  const [fileLog, setFileLog] = useState("");
  const [fileLogBusy, setFileLogBusy] = useState(false);

  useEffect(() => {
    if (view === "logs") {
      refreshFileLog();
    }
  }, [view]);

  function refreshFileLog(): void {
    setFileLogBusy(true);
    api
      .readLogFile()
      .then(setFileLog)
      .catch((error: unknown) => setNotice(toErrorMessage(error)))
      .finally(() => setFileLogBusy(false));
  }

  function clearUnifiedLog(): void {
    setFileLogBusy(true);
    Promise.all([api.clearLogFile(), api.clearDiagnostics()])
      .then(([log, nextSnapshot]) => {
        setFileLog(log);
        setSnapshot(nextSnapshot);
      })
      .catch((error: unknown) => setNotice(toErrorMessage(error)))
      .finally(() => setFileLogBusy(false));
  }

  function copyUnifiedLog(): void {
    setFileLogBusy(true);
    api
      .readLogFile()
      .then((log) => {
        setFileLog(log);
        void navigator.clipboard.writeText(log || formatRuntimeDiagnostics(snapshot));
      })
      .catch((error: unknown) => setNotice(toErrorMessage(error)))
      .finally(() => setFileLogBusy(false));
  }

  return {
    fileLog,
    fileLogBusy,
    refreshFileLog,
    clearUnifiedLog,
    copyUnifiedLog
  };
}
