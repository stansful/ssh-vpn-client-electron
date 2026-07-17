import {
  Activity,
  ArrowUp,
  Check,
  CircleAlert,
  Plus,
  Power,
  RefreshCw,
  Route,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  X
} from "lucide-react";
import type { Dispatch, FormEvent, SetStateAction } from "react";
import { checkButtonClass } from "../../lib/labels.js";
import {
  isConnectionSelectionLocked,
  sshConnectionPresentation
} from "../../lib/connection-presentation.js";
import type { AppSnapshot, RuntimeStatus, SshConfig, TunnelCheckResult } from "../../../shared/types.js";
import { StatusPill } from "../ui/index.js";

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
  onCreateConfig,
  onManageRouting,
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
  onCreateConfig: () => void;
  onManageRouting: () => void;
  onCheckTunnel: () => void;
  onEditEndpoint: () => void;
  onTerminalToggle: (open: boolean) => void;
  onCloseTerminalShell: () => void;
  onTerminalInputChange: Dispatch<SetStateAction<string>>;
  onTerminalSubmit: (event: FormEvent) => void;
}): JSX.Element {
  const sshRuntimeActive = runtime?.transport !== "xray";
  const sshState = sshRuntimeActive ? runtime?.state ?? "Disconnected" : "Disconnected";
  const selectionLocked = isConnectionSelectionLocked(sshState);
  const activeConfig = sshRuntimeActive && runtime?.activeConfigId
    ? store.sshConfigs.find((config) => config.id === runtime.activeConfigId)
    : undefined;
  const displayedConfig = selectionLocked ? activeConfig ?? selectedConfig : selectedConfig;
  const displayedConfigId = selectionLocked
    ? activeConfig?.id ?? store.selectedConfigId ?? ""
    : store.selectedConfigId ?? "";
  const presentation = sshConnectionPresentation(
    sshState,
    sshRuntimeActive && Boolean(runtime?.realTunnelAvailable),
    sshRuntimeActive ? runtime?.message : undefined
  );
  const actionIsDisconnect = presentation.action === "disconnect";
  const actionDisabled = busy || presentation.actionPending || (!actionIsDisconnect && (!selectedConfig || selectedRulesBlocked));
  const actionHint = !actionIsDisconnect && !selectedConfig
    ? "Choose an SSH configuration before connecting."
    : !actionIsDisconnect && selectedRulesBlocked
      ? "Add at least one enabled routing rule before connecting."
      : selectionLocked
        ? "Disconnect before choosing a different SSH server."
        : store.routingMode === "proxy-all"
          ? "All device traffic will use the selected SSH tunnel."
          : "Only enabled routing rules will use the selected SSH tunnel.";
  const connected = sshState === "Connected";
  const routingTitle = store.routingMode === "proxy-all" ? "All traffic through SSH" : "Only selected apps and websites";
  const routingDescription = store.routingMode === "proxy-all"
    ? "The tunnel is the default route; explicit direct rules stay outside it."
    : "Only enabled rules use SSH. Everything else keeps its normal direct connection.";
  const visibleTunnelCheck = connected ? lastTunnelCheck : undefined;
  const checkTitle = checking
    ? "Checking tunnel…"
    : visibleTunnelCheck?.ok
      ? "Tunnel check passed"
      : visibleTunnelCheck
        ? "Tunnel check failed"
        : connected
          ? "Verify routed traffic"
          : "Available after connection";
  const checkDescription = visibleTunnelCheck?.message ?? (connected
    ? `Send a test request through the active route to ${store.settings.checkEndpoint}.`
    : `Connect first, then test the route using ${store.settings.checkEndpoint}.`);

  return (
    <section className="screen">
      <div className="main-grid">
        <section className="panel connection-panel" aria-busy={busy || checking} aria-labelledby="ssh-connection-title">
          <div className="section-title connection-panel-title">
            <div className="panel-heading">
              <span className="panel-heading-icon" aria-hidden="true"><ShieldCheck size={18} /></span>
              <div className="panel-heading-copy">
                <h2 id="ssh-connection-title">SSH connection</h2>
                <p>Choose a server, then turn on secure traffic routing.</p>
              </div>
            </div>
            <StatusPill state={sshState} />
          </div>

          <div className="connection-steps">
            <section className="connection-step" aria-labelledby="ssh-server-step-title">
              <div className="connection-step-heading">
                <span className="connection-step-index" aria-hidden="true">1</span>
                <div>
                  <strong id="ssh-server-step-title">Choose an SSH server</strong>
                  <span>Select which saved configuration will carry your traffic.</span>
                </div>
              </div>

              <div className="connection-selector">
                <label className="field" htmlFor="active-ssh-configuration">
                  <span>SSH configuration</span>
                  <select
                    id="active-ssh-configuration"
                    value={displayedConfigId}
                    disabled={busy || selectionLocked}
                    onChange={(event) => onSelectConfig(event.target.value)}
                  >
                    <option value="" disabled>Select configuration</option>
                    {store.sshConfigs.map((config) => (
                      <option key={config.id} value={config.id}>{config.name}</option>
                    ))}
                  </select>
                  <small className="field-hint">
                    {displayedConfig
                      ? `${displayedConfig.username}@${displayedConfig.host}:${displayedConfig.port}${selectionLocked ? " · Disconnect to change server." : ""}`
                      : "No server selected yet."}
                  </small>
                </label>
                <button type="button" className="ghost-button" disabled={busy} onClick={onCreateConfig}>
                  <Plus size={17} /> New configuration
                </button>
              </div>
            </section>

            <section className="connection-step" aria-labelledby="ssh-tunnel-step-title">
              <div className="connection-step-heading">
                <span className="connection-step-index" aria-hidden="true">2</span>
                <div>
                  <strong id="ssh-tunnel-step-title">Turn the secure tunnel on</strong>
                  <span>The main button below starts or stops SSH routing.</span>
                </div>
              </div>

              {selectedRulesBlocked && (
                <div className="warning-row connection-warning" id="ssh-routing-warning">
                  <CircleAlert size={18} aria-hidden="true" />
                  <div>
                    <strong>Routing rules are required</strong>
                    <span>Selected rules mode is enabled, but no valid rule is active.</span>
                  </div>
                  <button type="button" className="ghost-button" onClick={onManageRouting}>Open routing</button>
                </div>
              )}

              <div className="connection-command">
                <div
                  className="connection-status-card"
                  data-tone={presentation.tone}
                  role="status"
                  aria-live="polite"
                  aria-atomic="true"
                >
                  <div className="connection-status-icon" aria-hidden="true">
                    {presentation.tone === "active" ? <ShieldCheck size={22} /> : presentation.tone === "error" ? <CircleAlert size={22} /> : <Power size={22} />}
                  </div>
                  <div className="connection-status-copy">
                    <span>{presentation.statusLabel}</span>
                    <strong>{presentation.title}</strong>
                    <p>{presentation.description}</p>
                    <small>
                      {displayedConfig
                        ? `${displayedConfig.name} · ${displayedConfig.username}@${displayedConfig.host}:${displayedConfig.port}`
                        : "No SSH configuration selected"}
                    </small>
                  </div>
                </div>

                <button
                  className={`${actionIsDisconnect ? "danger-button" : "primary-button"} connection-primary-action`}
                  type="button"
                  disabled={actionDisabled}
                  aria-describedby="ssh-primary-action-hint"
                  onClick={actionIsDisconnect ? onDisconnect : onConnect}
                >
                  {presentation.actionPending ? <RefreshCw className="spin" size={20} /> : actionIsDisconnect ? <X size={20} /> : <Power size={20} />}
                  <span className="connection-action-copy">
                    <strong>{presentation.actionLabel}</strong>
                    <small>{presentation.actionDetail}</small>
                  </span>
                </button>
              </div>
              <p className="connection-action-hint" id="ssh-primary-action-hint">{actionHint}</p>
            </section>

            <div className="connection-facts">
              <article className="connection-fact">
                <div className="connection-fact-heading">
                  <span className="connection-fact-icon" aria-hidden="true"><Route size={18} /></span>
                  <div>
                    <span>Traffic routing</span>
                    <strong>{routingTitle}</strong>
                  </div>
                </div>
                <p>{routingDescription}</p>
                <button type="button" className="ghost-button" onClick={onManageRouting}>Manage routing</button>
              </article>

              <article className="connection-fact" aria-live="polite">
                <div className="connection-fact-heading">
                  <span className="connection-fact-icon" aria-hidden="true"><Activity size={18} /></span>
                  <div>
                    <span>Connection test</span>
                    <strong>{checkTitle}</strong>
                  </div>
                </div>
                <p>{checkDescription}</p>
                <div className="connection-fact-actions">
                  <button
                    className={checkButtonClass(visibleTunnelCheck?.ok, checking)}
                    type="button"
                    disabled={checking || !connected}
                    onClick={onCheckTunnel}
                  >
                    {checking ? <RefreshCw className="spin" size={17} /> : visibleTunnelCheck?.ok ? <Check size={17} /> : visibleTunnelCheck ? <X size={17} /> : <Activity size={17} />}
                    {checking ? "Checking…" : "Test now"}
                  </button>
                  <button type="button" className="ghost-button" onClick={onEditEndpoint}>
                    <SlidersHorizontal size={16} /> Test settings
                  </button>
                </div>
              </article>
            </div>
          </div>
        </section>

        <section className="panel terminal-panel">
          <details open={store.settings.terminalExpanded} onToggle={(event) => onTerminalToggle(event.currentTarget.open)}>
            <summary>
              <span><Terminal size={18} /> SSH terminal</span>
              <span className="meta-chip">{sshState === "Connected" ? "Live" : "Offline"}</span>
            </summary>
            {store.settings.terminalExpanded && (
              <div className="terminal-toolbar">
                <span className="connection-label">Encrypted interactive shell</span>
                <button
                  type="button"
                  className="ghost-button"
                  disabled={sshState !== "Connected" || terminalOpening}
                  onClick={onCloseTerminalShell}
                >
                  {terminalOpening ? <RefreshCw className="spin" size={16} /> : <X size={16} />} Close shell
                </button>
              </div>
            )}
            <textarea className="terminal-output" aria-label="SSH terminal output" readOnly value={terminalText} />
            <form className="terminal-input" onSubmit={onTerminalSubmit}>
              <input aria-label="SSH command" value={terminalInput} disabled={sshState !== "Connected"} onChange={(event) => onTerminalInputChange(event.target.value)} placeholder="Type a command…" />
              <button type="submit" disabled={sshState !== "Connected"}><ArrowUp size={16} /> Send</button>
            </form>
          </details>
        </section>
      </div>
    </section>
  );
}
