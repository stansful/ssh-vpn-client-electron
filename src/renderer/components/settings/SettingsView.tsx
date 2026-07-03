import type { AppSettings, AppSnapshot, DesktopPlatform, RoutingMode, ThemeMode } from "../../../shared/types.js";
import { Segmented } from "../ui/index.js";
import { ThemeDesigner } from "./ThemeDesigner.js";

export function SettingsView({
  store,
  loggingEnabled,
  updateInfo,
  updateDownload,
  onCheckForUpdates,
  onDownloadUpdate,
  onRevealDownloadedUpdate,
  onRoutingModeChange,
  onUpdateSettings,
  platform
}: {
  store: AppSnapshot["store"];
  loggingEnabled: boolean;
  updateInfo: AppSnapshot["updateInfo"];
  updateDownload: AppSnapshot["updateDownload"];
  onCheckForUpdates: () => void;
  onDownloadUpdate: () => void;
  onRevealDownloadedUpdate: () => void;
  onRoutingModeChange: (mode: RoutingMode) => void;
  onUpdateSettings: (patch: Partial<AppSettings>) => void;
  platform: DesktopPlatform | undefined;
}): JSX.Element {
  const enabledRules = store.routingRules.filter((rule) => rule.enabled).length;
  const windowsStartupAvailable = platform === "windows";

  return (
    <section className="screen two-column">
      <section className="panel">
        <div className="section-title">
          <h2>Logging</h2>
          <span>{loggingEnabled ? "Enabled" : "Disabled"}</span>
        </div>
        <div className="logging-toggles">
          <label className="switch-row">
            <input
              type="checkbox"
              checked={loggingEnabled}
              onChange={(event) =>
                onUpdateSettings({
                  loggingEnabled: event.target.checked,
                  diagnosticsLoggingEnabled: event.target.checked,
                  fileLoggingEnabled: event.target.checked
                })
              }
            />
            <span>Enable logs</span>
          </label>
          <label className="switch-row">
            <input
              type="checkbox"
              disabled={!loggingEnabled}
              checked={loggingEnabled && store.settings.diagnosticsLoggingEnabled}
              onChange={(event) => onUpdateSettings({ diagnosticsLoggingEnabled: event.target.checked })}
            />
            <span>Runtime entries</span>
          </label>
          <label className="switch-row">
            <input
              type="checkbox"
              disabled={!loggingEnabled}
              checked={loggingEnabled && store.settings.fileLoggingEnabled}
              onChange={(event) => onUpdateSettings({ fileLoggingEnabled: event.target.checked })}
            />
            <span>Write main.log</span>
          </label>
        </div>
        {!loggingEnabled && (
          <div className="warning-row spaced">
            Logs are disabled. The Logs item is hidden and runtime/file log entries are not recorded.
          </div>
        )}
      </section>

      <section className="panel">
        <div className="section-title">
          <h2>Window</h2>
          <span>{store.settings.autoConnectOnStartup ? "Auto-connect" : store.settings.startWithWindowsInTray ? "Startup tray" : store.settings.closeToTrayEnabled ? "Tray close" : "Quit on close"}</span>
        </div>
        <div className="logging-toggles">
          <label className="switch-row">
            <input
              type="checkbox"
              checked={store.settings.autoConnectOnStartup}
              onChange={(event) => onUpdateSettings({ autoConnectOnStartup: event.target.checked })}
            />
            <span>Auto-connect on app start</span>
          </label>
          <label className="switch-row">
            <input
              type="checkbox"
              checked={store.settings.closeToTrayEnabled}
              onChange={(event) => onUpdateSettings({ closeToTrayEnabled: event.target.checked })}
            />
            <span>Close to tray</span>
          </label>
          <label className="switch-row">
            <input
              type="checkbox"
              disabled={!windowsStartupAvailable}
              checked={store.settings.startWithWindowsInTray}
              onChange={(event) => onUpdateSettings({ startWithWindowsInTray: event.target.checked })}
            />
            <span>Start with Windows in tray</span>
          </label>
        </div>
      </section>

      <section className="panel">
        <div className="section-title">
          <h2>Routing</h2>
          <span>{store.routingMode === "proxy-all" ? "Proxy all" : `${enabledRules} rules`}</span>
        </div>
        <Segmented<RoutingMode>
          value={store.routingMode}
          options={[
            ["proxy-all", "Proxy all"],
            ["selected-rules", "Selected rules"]
          ]}
          onChange={onRoutingModeChange}
        />
        {store.routingMode === "selected-rules" && enabledRules === 0 && (
          <div className="warning-row spaced">
            Selected rules mode requires at least one enabled rule before Connect.
          </div>
        )}
      </section>

      <section className="panel settings-wide">
        <div className="section-title">
          <h2>Updates</h2>
          <span>{updateInfo?.latestVersion ? `Latest ${updateInfo.latestVersion}` : "Portable"}</span>
        </div>
        <div className="toolbar">
          <button type="button" className="ghost-button" onClick={onCheckForUpdates}>Check for updates</button>
          <button type="button" className="primary-button" disabled={!updateInfo?.asset || updateDownload?.state === "downloading"} onClick={onDownloadUpdate}>
            {updateDownload?.state === "downloading" ? "Downloading" : "Download portable"}
          </button>
          <button type="button" className="ghost-button" disabled={!updateDownload?.filePath} onClick={onRevealDownloadedUpdate}>Open folder with file</button>
        </div>
        {updateInfo && (
          <dl className="facts log-facts">
            <div><dt>Status</dt><dd>{updateInfo.message}</dd></div>
            <div><dt>Current</dt><dd>{updateInfo.currentVersion}</dd></div>
            <div><dt>Downloaded</dt><dd>{updateDownload?.message ?? "Not downloaded"}</dd></div>
            <div><dt>Progress</dt><dd>{updateDownload?.percent !== undefined ? `${Math.round(updateDownload.percent)}%` : updateDownload?.state ?? "idle"}</dd></div>
          </dl>
        )}
      </section>

      <section className="panel settings-wide">
        <div className="section-title">
          <h2>Theme</h2>
          <span>{store.settings.theme}</span>
        </div>
        <Segmented<ThemeMode>
          value={store.settings.theme}
          options={[
            ["system", "System"],
            ["light", "Light"],
            ["dark", "Dark"],
            ["custom", "Custom"]
          ]}
          onChange={(themeMode) => onUpdateSettings({ theme: themeMode })}
        />
        <ThemeDesigner settings={store.settings} onChange={onUpdateSettings} />
      </section>
    </section>
  );
}
