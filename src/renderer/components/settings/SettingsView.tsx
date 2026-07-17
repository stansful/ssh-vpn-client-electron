import { AppWindow, DownloadCloud, FileClock, FolderOpen, Palette, RefreshCw, Route } from "lucide-react";
import { useMemo } from "react";
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
  const enabledRules = useMemo(
    () => store.routingRules.reduce((count, rule) => count + (rule.enabled ? 1 : 0), 0),
    [store.routingRules]
  );
  const enabledProxyListDomains = store.routingProxyList.enabled ? store.routingProxyList.domains.length : 0;
  const windowsStartupAvailable = platform === "windows";

  return (
    <section className="screen two-column">
      <section className="panel">
        <div className="section-title">
          <div className="panel-heading">
            <span className="panel-heading-icon" aria-hidden="true"><FileClock size={18} /></span>
            <div className="panel-heading-copy"><h2>Logging</h2><p>Diagnostics and local retention</p></div>
          </div>
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
          <div className="panel-heading">
            <span className="panel-heading-icon" aria-hidden="true"><AppWindow size={18} /></span>
            <div className="panel-heading-copy"><h2>Window</h2><p>Startup, tray, and memory behaviour</p></div>
          </div>
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
              disabled={!store.settings.closeToTrayEnabled}
              checked={store.settings.closeToTrayEnabled && store.settings.releaseRendererInTrayEnabled}
              onChange={(event) => onUpdateSettings({ releaseRendererInTrayEnabled: event.target.checked })}
            />
            <span>Release interface memory after 30 seconds in tray</span>
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
        {store.settings.closeToTrayEnabled && store.settings.releaseRendererInTrayEnabled && (
          <div className="warning-row spaced">
            Unsaved form edits are discarded after 30 seconds in the tray. The active tunnel stays connected and the interface reloads its latest saved state when reopened.
          </div>
        )}
      </section>

      <section className="panel">
        <div className="section-title">
          <div className="panel-heading">
            <span className="panel-heading-icon" aria-hidden="true"><Route size={18} /></span>
            <div className="panel-heading-copy"><h2>Routing</h2><p>Default traffic policy</p></div>
          </div>
          <span>{store.routingMode === "proxy-all" ? "Proxy all" : `${enabledRules + enabledProxyListDomains} targets`}</span>
        </div>
        <Segmented<RoutingMode>
          value={store.routingMode}
          ariaLabel="Default routing mode"
          options={[
            ["proxy-all", "Proxy all"],
            ["selected-rules", "Selected rules"]
          ]}
          onChange={onRoutingModeChange}
        />
        {store.routingMode === "selected-rules" && enabledRules === 0 && enabledProxyListDomains === 0 && (
          <div className="warning-row spaced">
            Selected rules mode requires at least one enabled rule or proxy-list domain before Connect.
          </div>
        )}
      </section>

      <section className="panel settings-wide">
        <div className="section-title">
          <div className="panel-heading">
            <span className="panel-heading-icon" aria-hidden="true"><DownloadCloud size={18} /></span>
            <div className="panel-heading-copy"><h2>Updates</h2><p>Portable release delivery</p></div>
          </div>
          <span>{updateInfo?.latestVersion ? `Latest ${updateInfo.latestVersion}` : "Portable"}</span>
        </div>
        <div className="toolbar">
          <button type="button" className="ghost-button" onClick={onCheckForUpdates}><RefreshCw size={16} /> Check for updates</button>
          <button type="button" className="primary-button" disabled={!updateInfo?.asset || updateDownload?.state === "downloading"} onClick={onDownloadUpdate}>
            <DownloadCloud size={16} /> {updateDownload?.state === "downloading" ? "Downloading" : "Download portable"}
          </button>
          <button type="button" className="ghost-button" disabled={!updateDownload?.filePath} onClick={onRevealDownloadedUpdate}><FolderOpen size={16} /> Open folder with file</button>
        </div>
        {updateInfo && (
          <dl className="facts log-facts">
            <div><dt>Status</dt><dd>{updateInfo.message}</dd></div>
            <div><dt>Current</dt><dd>{updateInfo.currentVersion}</dd></div>
            <div><dt>Downloaded</dt><dd role="status" aria-live="polite">{updateDownload?.message ?? "Not downloaded"}</dd></div>
            <div>
              <dt>Progress</dt>
              <dd>
                {updateDownload?.state === "downloading" ? (
                  <span
                    role="progressbar"
                    aria-label="Portable update download"
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={Math.round(updateDownload.percent ?? 0)}
                  >
                    {Math.round(updateDownload.percent ?? 0)}%
                  </span>
                ) : updateDownload?.state ?? "idle"}
              </dd>
            </div>
          </dl>
        )}
      </section>

      <section className="panel settings-wide">
        <div className="section-title">
          <div className="panel-heading">
            <span className="panel-heading-icon" aria-hidden="true"><Palette size={18} /></span>
            <div className="panel-heading-copy"><h2>Theme</h2><p>Appearance tuned to your workspace</p></div>
          </div>
          <span>{store.settings.theme}</span>
        </div>
        <Segmented<ThemeMode>
          value={store.settings.theme}
          ariaLabel="Application theme"
          options={[
            ["system", "System"],
            ["light", "Light"],
            ["dark", "Dark"],
            ["custom", "Custom"]
          ]}
          onChange={(themeMode) => onUpdateSettings({ theme: themeMode })}
        />
        {store.settings.theme !== "custom" && (
          <div className="theme-preset-note">
            <Palette size={18} aria-hidden="true" />
            <div><strong>System surfaces, personal signals</strong><span>Accent and status colours apply everywhere; Custom enables the full palette.</span></div>
          </div>
        )}
        <ThemeDesigner settings={store.settings} onChange={onUpdateSettings} />
      </section>
    </section>
  );
}
