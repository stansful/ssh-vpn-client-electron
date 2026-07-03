import { Check, Power, RefreshCw, SlidersHorizontal, Terminal, X } from "lucide-react";
import type { Dispatch, FormEvent, SetStateAction } from "react";
import { checkButtonClass } from "../../lib/labels.js";
import type { AppSnapshot, RuntimeStatus, SshConfig, TunnelCheckResult } from "../../../shared/types.js";

export function MainView({
  store,
  runtime,
  selectedConfig,
  selectedRulesBlocked,
  busy,
  checking,
  lastTunnelCheck,
  terminalText,
  terminalInput,
  terminalOpening,
  onSelectConfig,
  onConnect,
  onDisconnect,
  onCheckTunnel,
  onEditEndpoint,
  onTerminalToggle,
  onCloseTerminalShell,
  onTerminalInputChange,
  onTerminalSubmit
}: {
  store: AppSnapshot["store"];
  runtime: RuntimeStatus | undefined;
  selectedConfig: SshConfig | undefined;
  selectedRulesBlocked: boolean;
  busy: boolean;
  checking: boolean;
  lastTunnelCheck: TunnelCheckResult | undefined;
  terminalText: string;
  terminalInput: string;
  terminalOpening: boolean;
  onSelectConfig: (id: string) => void;
  onConnect: () => void;
  onDisconnect: () => void;
  onCheckTunnel: () => void;
  onEditEndpoint: () => void;
  onTerminalToggle: (open: boolean) => void;
  onCloseTerminalShell: () => void;
  onTerminalInputChange: Dispatch<SetStateAction<string>>;
  onTerminalSubmit: (event: FormEvent) => void;
}): JSX.Element {
  const sshRuntimeActive = runtime?.transport !== "xray";
  const connected = sshRuntimeActive && (runtime?.state === "Connected" || runtime?.state === "Connecting" || runtime?.state === "Reconnecting");

  return (
    <section className="screen">
      <div className="main-grid">
        <section className="panel connection-panel">
          <div className="section-title">
            <h2>Connection</h2>
            <span>{selectedConfig ? selectedConfig.name : "No configuration selected"}</span>
          </div>

          <label className="field">
            <span>Active SSH configuration</span>
            <select value={store.selectedConfigId ?? ""} onChange={(event) => onSelectConfig(event.target.value)}>
              <option value="" disabled>Select configuration</option>
              {store.sshConfigs.map((config) => (
                <option key={config.id} value={config.id}>{config.name}</option>
              ))}
            </select>
          </label>

          {selectedRulesBlocked && (
            <div className="warning-row">
              Selected rules mode is active in Settings and requires at least one enabled rule before Connect.
            </div>
          )}

          <div className="button-row">
            {connected ? (
              <button className="danger-button" type="button" disabled={busy} onClick={onDisconnect}>
                <X size={18} /> Disconnect
              </button>
            ) : (
              <button className="primary-button" type="button" disabled={busy || !selectedConfig || selectedRulesBlocked} onClick={onConnect}>
                <Power size={18} /> Connect
              </button>
            )}
            <button
              className={checkButtonClass(lastTunnelCheck?.ok, checking)}
              type="button"
              disabled={checking || !sshRuntimeActive || runtime?.state !== "Connected"}
              onClick={onCheckTunnel}
            >
              {checking ? <RefreshCw className="spin" size={18} /> : lastTunnelCheck?.ok ? <Check size={18} /> : lastTunnelCheck ? <X size={18} /> : <RefreshCw size={18} />}
              Check tunnel
            </button>
          </div>

          <div className="field endpoint-summary">
            <span>Check tunnel endpoint</span>
            <div className="endpoint-line">
              <strong>{store.settings.checkEndpoint}</strong>
              <button type="button" className="ghost-button" onClick={onEditEndpoint}>
                <SlidersHorizontal size={16} /> Edit
              </button>
            </div>
          </div>

          <div className="field">
            <span>Routing mode</span>
            <div className="endpoint-line">
              <strong>{store.routingMode === "proxy-all" ? "Proxy all" : "Selected rules"}</strong>
            </div>
          </div>
        </section>

        <section className="panel terminal-panel">
          <details open={store.settings.terminalExpanded} onToggle={(event) => onTerminalToggle(event.currentTarget.open)}>
            <summary>
              <span><Terminal size={18} /> SSH terminal</span>
              {store.settings.terminalExpanded && (
                <button
                  type="button"
                  className="ghost-button"
                  disabled={runtime?.state !== "Connected" || terminalOpening}
                  onClick={(event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    onCloseTerminalShell();
                  }}
                >
                  {terminalOpening ? <RefreshCw className="spin" size={16} /> : <X size={16} />} Close shell
                </button>
              )}
            </summary>
            <textarea className="terminal-output" readOnly value={terminalText} />
            <form className="terminal-input" onSubmit={onTerminalSubmit}>
              <input value={terminalInput} disabled={runtime?.state !== "Connected"} onChange={(event) => onTerminalInputChange(event.target.value)} placeholder="Command input" />
              <button type="submit" disabled={runtime?.state !== "Connected"}>Send</button>
            </form>
          </details>
        </section>
      </div>
    </section>
  );
}
