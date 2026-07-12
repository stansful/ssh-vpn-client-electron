import { Clipboard, RefreshCw, Trash2 } from "lucide-react";
import { useMemo } from "react";
import { formatRuntimeDiagnostics } from "../../lib/diagnostics.js";
import type { AppSettings, AppSnapshot } from "../../../shared/types.js";

export function LogsView({
  snapshot,
  fileLog,
  fileLogBusy,
  onUpdateSettings,
  onRefresh,
  onCopy,
  onClear
}: {
  snapshot: AppSnapshot;
  fileLog: string;
  fileLogBusy: boolean;
  onUpdateSettings: (patch: Partial<AppSettings>) => void;
  onRefresh: () => void;
  onCopy: () => void;
  onClear: () => void;
}): JSX.Element {
  const displayedLog = useMemo(
    () => fileLog || formatRuntimeDiagnostics(snapshot) || "No log content.",
    [fileLog, snapshot.diagnostics]
  );

  return (
    <section className="screen logs-screen">
      <section className="panel logs-control-panel">
        <div className="section-title">
          <h2>Logging</h2>
          <span>{snapshot.diagnostics.length} live entries</span>
        </div>
        <div className="logging-toggles">
          <label className="switch-row">
            <input
              type="checkbox"
              checked={snapshot.store.settings.diagnosticsLoggingEnabled}
              onChange={(event) => onUpdateSettings({ diagnosticsLoggingEnabled: event.target.checked })}
            />
            <span>Runtime diagnostics</span>
          </label>
          <label className="switch-row">
            <input
              type="checkbox"
              checked={snapshot.store.settings.fileLoggingEnabled}
              onChange={(event) => onUpdateSettings({ fileLoggingEnabled: event.target.checked })}
            />
            <span>File logging</span>
          </label>
        </div>
        <dl className="facts log-facts">
          <div><dt>Live entries</dt><dd>{snapshot.store.settings.diagnosticsLoggingEnabled ? "Enabled" : "Disabled"}</dd></div>
          <div><dt>Unified file</dt><dd>{snapshot.store.settings.fileLoggingEnabled ? "Enabled" : "Disabled"}</dd></div>
          <div className="wide-fact"><dt>Log paths</dt><dd>{snapshot.logFilePaths.join("\n") || "No log path available"}</dd></div>
        </dl>
      </section>

      <section className="panel logs-panel">
        <div className="section-title">
          <h2>Unified log</h2>
          <div className="item-actions">
            <button type="button" className="ghost-button" disabled={fileLogBusy} onClick={onRefresh}>
              <RefreshCw className={fileLogBusy ? "spin" : undefined} size={16} /> Refresh
            </button>
            <button type="button" className="ghost-button" disabled={fileLogBusy} onClick={onCopy}>
              <Clipboard size={16} /> Copy
            </button>
            <button type="button" className="ghost-button" disabled={fileLogBusy} onClick={onClear}>
              <Trash2 size={16} /> Clear
            </button>
          </div>
        </div>
        <textarea className="file-log-output" readOnly value={displayedLog} />
      </section>
    </section>
  );
}
