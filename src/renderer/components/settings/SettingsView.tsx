import type { AppSettings, AppSnapshot, ThemeMode } from "../../../shared/types.js";
import { Segmented } from "../ui/index.js";
import { ThemeDesigner } from "./ThemeDesigner.js";

export function SettingsView({
  store,
  loggingEnabled,
  onUpdateSettings
}: {
  store: AppSnapshot["store"];
  loggingEnabled: boolean;
  onUpdateSettings: (patch: Partial<AppSettings>) => void;
}): JSX.Element {
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
          <span>{store.settings.closeToTrayEnabled ? "Tray close" : "Quit on close"}</span>
        </div>
        <label className="switch-row">
          <input
            type="checkbox"
            checked={store.settings.closeToTrayEnabled}
            onChange={(event) => onUpdateSettings({ closeToTrayEnabled: event.target.checked })}
          />
          <span>Close to tray</span>
        </label>
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
