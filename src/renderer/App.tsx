import {
  Check,
  Clipboard,
  Download,
  KeyRound,
  Network,
  Plus,
  Power,
  RefreshCw,
  Save,
  Search,
  Server,
  Settings,
  Shield,
  SlidersHorizontal,
  Square,
  Terminal,
  Trash2,
  Upload,
  X
} from "lucide-react";
import { useEffect, useMemo, useState, type ChangeEvent, type CSSProperties, type FormEvent } from "react";
import { api } from "./api.js";
import { createDefaultStore } from "../shared/defaults.js";
import { normalizeRuleValue, validateRoutingRuleValue } from "../shared/validation.js";
import type {
  AppSettings,
  AppSnapshot,
  AuthType,
  RoutingMode,
  RoutingRule,
  RoutingRuleType,
  SshConfig,
  SshKeyMetadata,
  ThemeMode,
  UpsertSshConfigInput,
  UpsertSshKeyInput
} from "../shared/types.js";

type View = "main" | "configs" | "keys" | "routing" | "settings";

interface ConfigDraft extends UpsertSshConfigInput {
  mode: "create" | "edit";
}

interface KeyDraft extends UpsertSshKeyInput {
  mode: "create" | "edit";
}

const emptyConfigDraft = (): ConfigDraft => ({
  mode: "create",
  name: "",
  host: "",
  port: 22,
  username: "",
  authType: "password",
  password: "",
  privateKeyId: "",
  privateKeyPassphrase: "",
  expectedServerFingerprint: "",
  keepaliveIntervalSec: 30,
  note: ""
});

const emptyKeyDraft = (): KeyDraft => ({
  mode: "create",
  name: "",
  privateKey: ""
});

export function App(): JSX.Element {
  const [snapshot, setSnapshot] = useState<AppSnapshot | undefined>();
  const [view, setView] = useState<View>("main");
  const [busy, setBusy] = useState(false);
  const [checking, setChecking] = useState(false);
  const [notice, setNotice] = useState<string>("");
  const [configDraft, setConfigDraft] = useState<ConfigDraft>(emptyConfigDraft);
  const [keyDraft, setKeyDraft] = useState<KeyDraft>(emptyKeyDraft);
  const [ruleTab, setRuleTab] = useState<RoutingRuleType>("domain");
  const [ruleSearch, setRuleSearch] = useState("");
  const [ruleValue, setRuleValue] = useState("");
  const [ruleError, setRuleError] = useState("");
  const [routingDraft, setRoutingDraft] = useState<RoutingRule[]>([]);
  const [routingDirty, setRoutingDirty] = useState(false);
  const [processSearch, setProcessSearch] = useState("");
  const [processes, setProcesses] = useState<string[]>([]);
  const [terminalInput, setTerminalInput] = useState("");

  useEffect(() => {
    let active = true;
    api
      .loadSnapshot()
      .then((loaded) => {
        if (active) {
          setSnapshot(loaded);
          setRoutingDraft(loaded.store.routingRules);
        }
      })
      .catch((error: unknown) => setNotice(toErrorMessage(error)));

    const off = api.onServiceEvent(() => {
      api
        .loadSnapshot()
        .then((loaded) => {
          if (active) {
            setSnapshot(loaded);
          }
        })
        .catch((error: unknown) => setNotice(toErrorMessage(error)));
    });

    return () => {
      active = false;
      off();
    };
  }, []);

  useEffect(() => {
    if (snapshot && !routingDirty) {
      setRoutingDraft(snapshot.store.routingRules);
    }
  }, [snapshot, routingDirty]);

  const store = snapshot?.store ?? createDefaultStore();
  const runtime = snapshot?.runtime;
  const selectedConfig = store.sshConfigs.find((config) => config.id === store.selectedConfigId);
  const enabledRules = store.routingRules.filter((rule) => rule.enabled);
  const selectedRulesBlocked = store.routingMode === "selected-rules" && enabledRules.length === 0;
  const theme = resolveTheme(store.settings.theme);
  const customStyle = createThemeVars(store.settings);

  const filteredRules = useMemo(
    () =>
      routingDraft.filter(
        (rule) =>
          rule.type === ruleTab &&
          (!ruleSearch.trim() || rule.value.toLowerCase().includes(ruleSearch.trim().toLowerCase()))
      ),
    [routingDraft, ruleSearch, ruleTab]
  );

  const filteredProcesses = useMemo(
    () =>
      processes.filter((name) =>
        processSearch.trim() ? name.toLowerCase().includes(processSearch.trim().toLowerCase()) : true
      ),
    [processSearch, processes]
  );

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

  function updateSettings(patch: Partial<AppSettings>): void {
    void run(() => api.updateSettings({ ...store.settings, ...patch }));
  }

  function editConfig(config: SshConfig): void {
    setConfigDraft({
      mode: "edit",
      id: config.id,
      name: config.name,
      host: config.host,
      port: config.port,
      username: config.username,
      authType: config.authType,
      password: "",
      privateKeyId: config.privateKeyId ?? "",
      privateKeyPassphrase: "",
      expectedServerFingerprint: config.expectedServerFingerprint,
      keepaliveIntervalSec: config.keepaliveIntervalSec,
      note: config.note
    });
    setView("configs");
  }

  function saveConfig(event: FormEvent): void {
    event.preventDefault();
    void run(async () => {
      const next = await api.upsertConfig({
        ...configDraft,
        privateKeyId: configDraft.privateKeyId || undefined,
        password: configDraft.password || undefined,
        privateKeyPassphrase: configDraft.privateKeyPassphrase || undefined
      });
      setConfigDraft(emptyConfigDraft());
      return next;
    });
  }

  function editKey(key: SshKeyMetadata): void {
    setKeyDraft({
      mode: "edit",
      id: key.id,
      name: key.name,
      privateKey: ""
    });
    setView("keys");
  }

  function saveKey(event: FormEvent): void {
    event.preventDefault();
    void run(async () => {
      const payload: UpsertSshKeyInput = {
        id: keyDraft.id,
        name: keyDraft.name,
        privateKey: keyDraft.privateKey || undefined
      };
      const next = await api.upsertKey(payload);
      setKeyDraft(emptyKeyDraft());
      return next;
    });
  }

  function updateRoutingDraft(mutator: (rules: RoutingRule[]) => RoutingRule[]): void {
    setRoutingDraft((current) => mutator(current));
    setRoutingDirty(true);
  }

  function addRule(): void {
    const validation = validateRoutingRuleValue(ruleTab, ruleValue);
    if (!validation.ok) {
      setRuleError(validation.message ?? "Invalid rule.");
      return;
    }

    const normalized = normalizeRuleValue(ruleTab, ruleValue);
    if (routingDraft.some((rule) => rule.type === ruleTab && rule.value === normalized)) {
      setRuleError("This rule already exists.");
      return;
    }

    const now = new Date().toISOString();
    updateRoutingDraft((rules) => [
      ...rules,
      {
        id: crypto.randomUUID(),
        type: ruleTab,
        value: normalized,
        enabled: true,
        createdAt: now,
        updatedAt: now
      }
    ]);
    setRuleValue("");
    setRuleError("");
  }

  function saveRules(): void {
    void run(async () => {
      const next = await api.updateRoutingRules(routingDraft);
      setRoutingDirty(false);
      return next;
    });
  }

  function importRules(event: ChangeEvent<HTMLInputElement>): void {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result)) as RoutingRule[];
        if (!Array.isArray(parsed)) {
          throw new Error("Import file must contain a rules array.");
        }
        const validRules = parsed.filter((rule) => validateRoutingRuleValue(rule.type, rule.value).ok);
        updateRoutingDraft(() => validRules);
        setNotice(`Imported ${validRules.length} valid rules.`);
      } catch (error) {
        setNotice(toErrorMessage(error));
      }
    };
    reader.readAsText(file);
    event.target.value = "";
  }

  function exportRules(): void {
    const blob = new Blob([`${JSON.stringify(routingDraft, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "shadow-ssh-routing-rules.json";
    link.click();
    URL.revokeObjectURL(url);
  }

  function loadProcesses(): void {
    void run(async () => {
      setProcesses(await api.listProcesses());
    });
  }

  function copyDiagnostics(): void {
    const text = (snapshot?.diagnostics ?? [])
      .map((entry) => `[${entry.at}] ${entry.level.toUpperCase()} ${entry.message}`)
      .join("\n");
    void navigator.clipboard.writeText(text);
  }

  function sendTerminalInput(event: FormEvent): void {
    event.preventDefault();
    if (!terminalInput.trim()) {
      return;
    }
    void api.terminalInput(`${terminalInput}\n`);
    setTerminalInput("");
  }

  if (!snapshot) {
    return (
      <div className="app-shell" data-theme={theme} style={customStyle}>
        <main className="loading">Loading Shadow SSH...</main>
      </div>
    );
  }

  return (
    <div className="app-shell" data-theme={theme} style={customStyle}>
      <aside className="sidebar">
        <div className="brand">
          <img src="/icon.svg" alt="" />
          <div>
            <strong>Shadow SSH</strong>
            <span>{runtime?.platformTarget.platform}/{runtime?.platformTarget.arch}</span>
          </div>
        </div>
        <nav>
          <NavButton active={view === "main"} icon={<Power size={18} />} label="Main" onClick={() => setView("main")} />
          <NavButton active={view === "configs"} icon={<Server size={18} />} label="SSH configs" onClick={() => setView("configs")} />
          <NavButton active={view === "keys"} icon={<KeyRound size={18} />} label="SSH keys" onClick={() => setView("keys")} />
          <NavButton active={view === "routing"} icon={<Network size={18} />} label="Routing" onClick={() => setView("routing")} />
          <NavButton active={view === "settings"} icon={<Settings size={18} />} label="Settings" onClick={() => setView("settings")} />
        </nav>
        <div className="service-badge">
          <Shield size={16} />
          <span>{runtime?.transport === "native-ipc" ? "Native IPC ready" : runtime?.transport === "live-ssh" ? "Live SSH" : "Simulator transport"}</span>
        </div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div>
            <h1>{titleForView(view)}</h1>
            <p>{runtime?.message}</p>
          </div>
          <StatusPill state={runtime?.state ?? "Disconnected"} />
        </header>

        {notice && (
          <div className="notice">
            <span>{notice}</span>
            <button type="button" className="icon-button" onClick={() => setNotice("")} aria-label="Dismiss">
              <X size={16} />
            </button>
          </div>
        )}

        {view === "main" && (
          <section className="screen">
            <div className="main-grid">
              <section className="panel connection-panel">
                <div className="section-title">
                  <h2>Connection</h2>
                  <span>{selectedConfig ? selectedConfig.name : "No configuration selected"}</span>
                </div>

                <label className="field">
                  <span>Active SSH configuration</span>
                  <select value={store.selectedConfigId ?? ""} onChange={(event) => void run(() => api.selectConfig(event.target.value))}>
                    <option value="" disabled>Select configuration</option>
                    {store.sshConfigs.map((config) => (
                      <option key={config.id} value={config.id}>{config.name}</option>
                    ))}
                  </select>
                </label>

                {selectedRulesBlocked && (
                  <div className="warning-row">
                    Selected rules mode requires at least one enabled rule before Connect.
                  </div>
                )}

                <div className="button-row">
                  {runtime?.state === "Connected" || runtime?.state === "Connecting" || runtime?.state === "Reconnecting" ? (
                    <button className="danger-button" type="button" disabled={busy} onClick={() => void run(() => api.disconnect())}>
                      <Square size={18} /> Disconnect
                    </button>
                  ) : (
                    <button className="primary-button" type="button" disabled={busy || !selectedConfig || selectedRulesBlocked} onClick={() => void run(() => api.connect())}>
                      <Power size={18} /> Connect
                    </button>
                  )}
                  <button
                    className={checkButtonClass(snapshot.lastTunnelCheck?.ok, checking)}
                    type="button"
                    disabled={checking || runtime?.state !== "Connected"}
                    onClick={() => {
                      setChecking(true);
                      void run(() => api.checkTunnel(store.settings.checkEndpoint)).finally(() => setChecking(false));
                    }}
                  >
                    {checking ? <RefreshCw className="spin" size={18} /> : snapshot.lastTunnelCheck?.ok ? <Check size={18} /> : snapshot.lastTunnelCheck ? <X size={18} /> : <RefreshCw size={18} />}
                    Check tunnel
                  </button>
                </div>

                <dl className="facts">
                  <div><dt>Routing mode</dt><dd>{store.routingMode === "proxy-all" ? "Proxy all" : "Selected rules"}</dd></div>
                  <div><dt>Enabled rules</dt><dd>{enabledRules.length}</dd></div>
                  <div><dt>Check endpoint</dt><dd>{store.settings.checkEndpoint}</dd></div>
                  <div><dt>Reconnect attempts</dt><dd>{runtime?.reconnectAttempt ?? 0}</dd></div>
                </dl>
              </section>

              <section className="panel diagnostics-panel">
                <details open={store.settings.diagnosticsExpanded} onToggle={(event) => updateSettings({ diagnosticsExpanded: event.currentTarget.open })}>
                  <summary>
                    <span><Clipboard size={18} /> Diagnostics</span>
                    <button type="button" className="ghost-button" onClick={(event) => { event.preventDefault(); copyDiagnostics(); }}>
                      <Clipboard size={16} /> Copy logs
                    </button>
                  </summary>
                  <LogList entries={snapshot.diagnostics} />
                </details>
              </section>

              <section className="panel terminal-panel">
                <details open={store.settings.terminalExpanded} onToggle={(event) => updateSettings({ terminalExpanded: event.currentTarget.open })}>
                  <summary>
                    <span><Terminal size={18} /> SSH terminal</span>
                    <button type="button" className="ghost-button" disabled={runtime?.state !== "Connected"} onClick={(event) => { event.preventDefault(); void run(() => api.openTerminal()); }}>
                      <Terminal size={16} /> Open shell
                    </button>
                  </summary>
                  <textarea className="terminal-output" readOnly value={snapshot.terminal.map((line) => line.text).join("")} />
                  <form className="terminal-input" onSubmit={sendTerminalInput}>
                    <input value={terminalInput} disabled={runtime?.state !== "Connected"} onChange={(event) => setTerminalInput(event.target.value)} placeholder="Command input" />
                    <button type="submit" disabled={runtime?.state !== "Connected"}>Send</button>
                  </form>
                </details>
              </section>
            </div>
          </section>
        )}

        {view === "configs" && (
          <section className="screen two-column">
            <section className="panel list-panel">
              <div className="section-title">
                <h2>Saved configurations</h2>
                <button type="button" className="ghost-button" onClick={() => setConfigDraft(emptyConfigDraft())}>
                  <Plus size={16} /> New
                </button>
              </div>
              <div className="item-list">
                {store.sshConfigs.map((config) => (
                  <article className="item" key={config.id}>
                    <div>
                      <strong>{config.name}</strong>
                      <span>{config.username}@{config.host}:{config.port}</span>
                    </div>
                    <div className="item-actions">
                      <button type="button" className="ghost-button" onClick={() => void run(() => api.selectConfig(config.id))}>Select</button>
                      <button type="button" className="icon-button" onClick={() => editConfig(config)} aria-label="Edit configuration"><SlidersHorizontal size={16} /></button>
                      <button type="button" className="icon-button danger" onClick={() => void run(() => api.deleteConfig(config.id))} aria-label="Delete configuration"><Trash2 size={16} /></button>
                    </div>
                  </article>
                ))}
                {store.sshConfigs.length === 0 && <EmptyState text="No SSH configurations yet." />}
              </div>
            </section>

            <ConfigForm draft={configDraft} keys={store.sshKeys} onChange={setConfigDraft} onSubmit={saveConfig} />
          </section>
        )}

        {view === "keys" && (
          <section className="screen two-column">
            <section className="panel list-panel">
              <div className="section-title">
                <h2>Private keys</h2>
                <button type="button" className="ghost-button" onClick={() => setKeyDraft(emptyKeyDraft())}>
                  <Plus size={16} /> New
                </button>
              </div>
              <div className="item-list">
                {store.sshKeys.map((key) => (
                  <article className="item" key={key.id}>
                    <div>
                      <strong>{key.name}</strong>
                      <span>{key.fingerprint}</span>
                    </div>
                    <div className="item-actions">
                      <button type="button" className="icon-button" onClick={() => editKey(key)} aria-label="Edit key"><SlidersHorizontal size={16} /></button>
                      <button type="button" className="icon-button danger" onClick={() => void run(() => api.deleteKey(key.id))} aria-label="Delete key"><Trash2 size={16} /></button>
                    </div>
                  </article>
                ))}
                {store.sshKeys.length === 0 && <EmptyState text="No private keys yet." />}
              </div>
            </section>

            <KeyForm draft={keyDraft} onChange={setKeyDraft} onSubmit={saveKey} />
          </section>
        )}

        {view === "routing" && (
          <section className="screen">
            <section className="panel routing-panel">
              <div className="section-title">
                <h2>Routing rules</h2>
                <span>{routingDraft.filter((rule) => rule.enabled).length} enabled</span>
              </div>
              <div className="toolbar">
                <Segmented<RoutingRuleType>
                  value={ruleTab}
                  options={[
                    ["domain", "Domains"],
                    ["ip", "IPs"],
                    ["process.name", "Processes"]
                  ]}
                  onChange={setRuleTab}
                />
                <div className="search-box">
                  <Search size={16} />
                  <input value={ruleSearch} onChange={(event) => setRuleSearch(event.target.value)} placeholder="Search rules" />
                </div>
                <button type="button" className="ghost-button" onClick={exportRules}><Download size={16} /> Export</button>
                <label className="ghost-button file-button">
                  <Upload size={16} /> Import
                  <input type="file" accept="application/json" onChange={importRules} />
                </label>
                <button type="button" className="primary-button" onClick={saveRules} disabled={!routingDirty}>
                  <Save size={16} /> Save
                </button>
              </div>

              <div className="add-rule">
                <input value={ruleValue} onChange={(event) => setRuleValue(event.target.value)} placeholder={placeholderForRule(ruleTab)} />
                <button type="button" className="primary-button" onClick={addRule}><Plus size={16} /> Add</button>
              </div>
              {ruleError && <div className="inline-error">{ruleError}</div>}

              {ruleTab === "process.name" && (
                <div className="process-picker">
                  <div className="toolbar compact">
                    <div className="search-box">
                      <Search size={16} />
                      <input value={processSearch} onChange={(event) => setProcessSearch(event.target.value)} placeholder="Search active processes" />
                    </div>
                    <button type="button" className="ghost-button" onClick={loadProcesses}><RefreshCw size={16} /> Refresh</button>
                  </div>
                  <div className="process-list">
                    {filteredProcesses.slice(0, 80).map((name) => (
                      <button key={name} type="button" onClick={() => setRuleValue(name)}>{name}</button>
                    ))}
                  </div>
                </div>
              )}

              <div className="rules-list">
                {filteredRules.map((rule) => (
                  <article className="rule-row" key={rule.id}>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        onChange={(event) =>
                          updateRoutingDraft((rules) =>
                            rules.map((candidate) =>
                              candidate.id === rule.id
                                ? { ...candidate, enabled: event.target.checked, updatedAt: new Date().toISOString() }
                                : candidate
                            )
                          )
                        }
                      />
                      <span>{rule.enabled ? "Enabled" : "Disabled"}</span>
                    </label>
                    <strong>{rule.value}</strong>
                    <button
                      type="button"
                      className="icon-button danger"
                      onClick={() => updateRoutingDraft((rules) => rules.filter((candidate) => candidate.id !== rule.id))}
                      aria-label="Delete rule"
                    >
                      <Trash2 size={16} />
                    </button>
                  </article>
                ))}
                {filteredRules.length === 0 && <EmptyState text="No rules match this view." />}
              </div>
            </section>
          </section>
        )}

        {view === "settings" && (
          <section className="screen two-column">
            <section className="panel">
              <div className="section-title">
                <h2>Routing mode</h2>
                <span>{enabledRules.length} enabled rules</span>
              </div>
              <Segmented<RoutingMode>
                value={store.routingMode}
                options={[
                  ["proxy-all", "Proxy all"],
                  ["selected-rules", "Selected rules"]
                ]}
                onChange={(mode) => void run(() => api.updateRoutingMode(mode))}
              />
              {selectedRulesBlocked && <div className="warning-row">Connect is blocked until at least one routing rule is enabled.</div>}

              <label className="field spaced">
                <span>Check tunnel endpoint</span>
                <input
                  value={store.settings.checkEndpoint}
                  onChange={(event) => updateSettings({ checkEndpoint: event.target.value })}
                  placeholder="youtube.com:443"
                />
              </label>
            </section>

            <section className="panel">
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
                onChange={(themeMode) => updateSettings({ theme: themeMode })}
              />
              <div className="color-grid">
                {(["accent", "success", "danger", "surface"] as const).map((key) => (
                  <fieldset key={key}>
                    <legend>{key}</legend>
                    {(["r", "g", "b"] as const).map((channel) => (
                      <label key={channel}>
                        <span>{channel.toUpperCase()}</span>
                        <input
                          type="number"
                          min={0}
                          max={255}
                          value={store.settings.customTheme[key][channel]}
                          onChange={(event) =>
                            updateSettings({
                              customTheme: {
                                ...store.settings.customTheme,
                                [key]: {
                                  ...store.settings.customTheme[key],
                                  [channel]: clampRgb(Number(event.target.value))
                                }
                              }
                            })
                          }
                        />
                      </label>
                    ))}
                  </fieldset>
                ))}
              </div>
            </section>
          </section>
        )}
      </main>
    </div>
  );
}

function ConfigForm({
  draft,
  keys,
  onChange,
  onSubmit
}: {
  draft: ConfigDraft;
  keys: SshKeyMetadata[];
  onChange: (draft: ConfigDraft) => void;
  onSubmit: (event: FormEvent) => void;
}): JSX.Element {
  const set = <K extends keyof ConfigDraft>(key: K, value: ConfigDraft[K]): void => onChange({ ...draft, [key]: value });
  return (
    <form className="panel form-panel" onSubmit={onSubmit}>
      <div className="section-title">
        <h2>{draft.mode === "edit" ? "Edit configuration" : "Add configuration"}</h2>
        <button type="submit" className="primary-button"><Save size={16} /> Save</button>
      </div>
      <div className="form-grid">
        <Field label="Name"><input required value={draft.name} onChange={(event) => set("name", event.target.value)} /></Field>
        <Field label="Host"><input required value={draft.host} onChange={(event) => set("host", event.target.value)} /></Field>
        <Field label="Port"><input required type="number" min={1} max={65535} value={draft.port} onChange={(event) => set("port", Number(event.target.value))} /></Field>
        <Field label="Username"><input required value={draft.username} onChange={(event) => set("username", event.target.value)} /></Field>
        <Field label="Auth type">
          <select value={draft.authType} onChange={(event) => set("authType", event.target.value as AuthType)}>
            <option value="password">Password</option>
            <option value="private-key">Private key</option>
          </select>
        </Field>
        {draft.authType === "password" ? (
          <Field label={draft.mode === "edit" ? "Password (blank keeps current)" : "Password"}>
            <input type="password" value={draft.password} onChange={(event) => set("password", event.target.value)} />
          </Field>
        ) : (
          <>
            <Field label="Private key">
              <select value={draft.privateKeyId ?? ""} onChange={(event) => set("privateKeyId", event.target.value)}>
                <option value="">Select private key</option>
                {keys.map((key) => (
                  <option key={key.id} value={key.id}>{key.name}</option>
                ))}
              </select>
            </Field>
            <Field label="Key passphrase (blank keeps current)">
              <input type="password" value={draft.privateKeyPassphrase} onChange={(event) => set("privateKeyPassphrase", event.target.value)} />
            </Field>
          </>
        )}
        <Field label="Expected server fingerprint">
          <input value={draft.expectedServerFingerprint} onChange={(event) => set("expectedServerFingerprint", event.target.value)} />
        </Field>
        <Field label="Keepalive interval, sec">
          <input type="number" min={5} max={3600} value={draft.keepaliveIntervalSec} onChange={(event) => set("keepaliveIntervalSec", Number(event.target.value))} />
        </Field>
        <label className="field wide">
          <span>Note</span>
          <textarea value={draft.note} onChange={(event) => set("note", event.target.value)} />
        </label>
      </div>
    </form>
  );
}

function KeyForm({
  draft,
  onChange,
  onSubmit
}: {
  draft: KeyDraft;
  onChange: (draft: KeyDraft) => void;
  onSubmit: (event: FormEvent) => void;
}): JSX.Element {
  const set = <K extends keyof KeyDraft>(key: K, value: KeyDraft[K]): void => onChange({ ...draft, [key]: value });
  return (
    <form className="panel form-panel" onSubmit={onSubmit}>
      <div className="section-title">
        <h2>{draft.mode === "edit" ? "Edit private key" : "Add private key"}</h2>
        <button type="submit" className="primary-button"><Save size={16} /> Save</button>
      </div>
      <Field label="Key name"><input required value={draft.name} onChange={(event) => set("name", event.target.value)} /></Field>
      <label className="field">
        <span>{draft.mode === "edit" ? "Private key (blank keeps current)" : "Private key"}</span>
        <textarea className="secret-textarea" value={draft.privateKey} onChange={(event) => set("privateKey", event.target.value)} />
      </label>
    </form>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }): JSX.Element {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
}

function NavButton({ active, icon, label, onClick }: { active: boolean; icon: React.ReactNode; label: string; onClick: () => void }): JSX.Element {
  return (
    <button type="button" className={active ? "nav-button active" : "nav-button"} onClick={onClick}>
      {icon}
      <span>{label}</span>
    </button>
  );
}

function Segmented<T extends string>({
  value,
  options,
  onChange
}: {
  value: T;
  options: Array<[T, string]>;
  onChange: (value: T) => void;
}): JSX.Element {
  return (
    <div className="segmented">
      {options.map(([option, label]) => (
        <button key={option} type="button" className={value === option ? "active" : ""} onClick={() => onChange(option)}>
          {label}
        </button>
      ))}
    </div>
  );
}

function StatusPill({ state }: { state: string }): JSX.Element {
  return <div className={`status-pill ${state.toLowerCase()}`}>{state}</div>;
}

function LogList({ entries }: { entries: AppSnapshot["diagnostics"] }): JSX.Element {
  if (entries.length === 0) {
    return <EmptyState text="No diagnostics in this connection." />;
  }
  return (
    <div className="log-list">
      {entries.map((entry) => (
        <div key={entry.id} className={`log-entry ${entry.level}`}>
          <time>{new Date(entry.at).toLocaleTimeString()}</time>
          <span>{entry.level}</span>
          <p>{entry.message}</p>
        </div>
      ))}
    </div>
  );
}

function EmptyState({ text }: { text: string }): JSX.Element {
  return <div className="empty-state">{text}</div>;
}

function titleForView(view: View): string {
  const titles: Record<View, string> = {
    main: "Main screen",
    configs: "SSH configurations",
    keys: "SSH keys",
    routing: "Routing rules",
    settings: "Settings"
  };
  return titles[view];
}

function placeholderForRule(type: RoutingRuleType): string {
  if (type === "domain") {
    return "youtube.com or *.youtube.com";
  }
  if (type === "ip") {
    return "8.8.8.8 or 2a00:1450::/32";
  }
  return "chrome.exe";
}

function checkButtonClass(ok: boolean | undefined, checking: boolean): string {
  if (checking) {
    return "check-button checking";
  }
  if (ok === true) {
    return "check-button success";
  }
  if (ok === false) {
    return "check-button failure";
  }
  return "check-button";
}

function resolveTheme(mode: ThemeMode): string {
  if (mode === "system") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return mode;
}

function createThemeVars(settings: AppSettings): CSSProperties {
  const { accent, success, danger, surface } = settings.customTheme;
  return {
    "--accent": rgb(accent),
    "--success": rgb(success),
    "--danger": rgb(danger),
    "--custom-surface": rgb(surface)
  } as CSSProperties;
}

function rgb(color: { r: number; g: number; b: number }): string {
  return `rgb(${color.r}, ${color.g}, ${color.b})`;
}

function clampRgb(value: number): number {
  if (Number.isNaN(value)) {
    return 0;
  }
  return Math.max(0, Math.min(255, value));
}

function toErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
