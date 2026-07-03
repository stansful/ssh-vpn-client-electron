import { useEffect, useMemo, useRef, useState, type ChangeEvent, type FormEvent } from "react";
import { api } from "./api.js";
import { ConfigsView } from "./components/configs/ConfigsView.js";
import { ConfigForm } from "./components/forms/ConfigForm.js";
import { EndpointForm } from "./components/forms/EndpointForm.js";
import { KeyForm } from "./components/forms/KeyForm.js";
import { KeysView } from "./components/keys/KeysView.js";
import { Notice } from "./components/layout/Notice.js";
import { Sidebar } from "./components/layout/Sidebar.js";
import { Topbar } from "./components/layout/Topbar.js";
import { LogsView } from "./components/logs/LogsView.js";
import { MainView } from "./components/main/MainView.js";
import { RoutingView } from "./components/routing/RoutingView.js";
import { SettingsView } from "./components/settings/SettingsView.js";
import { Modal } from "./components/ui/index.js";
import { applyServiceEventToSnapshot, formatRuntimeDiagnostics } from "./lib/diagnostics.js";
import { validateEndpointInput } from "./lib/endpoint.js";
import { titleForView, toErrorMessage } from "./lib/labels.js";
import { createThemeVars, resolveTheme } from "./lib/theme.js";
import { emptyConfigDraft, emptyKeyDraft, type ConfigDraft, type KeyDraft, type RoutingSaveState, type View } from "./types.js";
import { createDefaultStore } from "../shared/defaults.js";
import { normalizeRuleValue, validateRoutingRuleValue } from "../shared/validation.js";
import type {
  AppSettings,
  AppSnapshot,
  RoutingRule,
  RoutingRuleType,
  SshConfig,
  SshKeyMetadata,
  UpsertSshKeyInput
} from "../shared/types.js";

export function App(): JSX.Element {
  const [snapshot, setSnapshot] = useState<AppSnapshot | undefined>();
  const [view, setView] = useState<View>("main");
  const [busy, setBusy] = useState(false);
  const [checking, setChecking] = useState(false);
  const [notice, setNotice] = useState<string>("");
  const [configDraft, setConfigDraft] = useState<ConfigDraft>(emptyConfigDraft);
  const [keyDraft, setKeyDraft] = useState<KeyDraft>(emptyKeyDraft);
  const [configModalOpen, setConfigModalOpen] = useState(false);
  const [keyModalOpen, setKeyModalOpen] = useState(false);
  const [endpointModalOpen, setEndpointModalOpen] = useState(false);
  const [configModalError, setConfigModalError] = useState("");
  const [keyModalError, setKeyModalError] = useState("");
  const [endpointModalError, setEndpointModalError] = useState("");
  const [ruleTab, setRuleTab] = useState<RoutingRuleType>("domain");
  const [ruleSearch, setRuleSearch] = useState("");
  const [ruleValue, setRuleValue] = useState("");
  const [ruleError, setRuleError] = useState("");
  const [routingDraft, setRoutingDraft] = useState<RoutingRule[]>([]);
  const [routingSaveState, setRoutingSaveState] = useState<RoutingSaveState>("idle");
  const [processSearch, setProcessSearch] = useState("");
  const [processes, setProcesses] = useState<string[]>([]);
  const [terminalInput, setTerminalInput] = useState("");
  const [terminalOpening, setTerminalOpening] = useState(false);
  const [terminalShellOpen, setTerminalShellOpen] = useState(false);
  const [fileLog, setFileLog] = useState("");
  const [fileLogBusy, setFileLogBusy] = useState(false);
  const [endpointDraft, setEndpointDraft] = useState("youtube.com:443");
  const terminalStartupNormalized = useRef(false);
  const routingSaveSeq = useRef(0);

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

    const off = api.onServiceEvent((event) => {
      if (!active) {
        return;
      }
      setSnapshot((current) => applyServiceEventToSnapshot(current, event));
      if (event.type === "error") {
        setNotice(event.message);
      }
    });

    return () => {
      active = false;
      off();
    };
  }, []);

  useEffect(() => {
    if (snapshot) {
      setRoutingDraft(snapshot.store.routingRules);
    }
  }, [snapshot?.store.routingRules]);

  useEffect(() => {
    if (view === "logs") {
      refreshFileLog();
    }
  }, [view]);

  useEffect(() => {
    if (snapshot?.runtime.state !== "Connected") {
      setTerminalShellOpen(false);
    }
  }, [snapshot?.runtime.state]);

  useEffect(() => {
    if (!snapshot || terminalStartupNormalized.current) {
      return;
    }
    terminalStartupNormalized.current = true;
    if (snapshot.runtime.state !== "Connected" && snapshot.store.settings.terminalExpanded) {
      void api
        .updateSettings({ ...snapshot.store.settings, terminalExpanded: false })
        .then(setSnapshot)
        .catch((error: unknown) => setNotice(toErrorMessage(error)));
    }
  }, [snapshot]);

  useEffect(() => {
    if (snapshot?.runtime.state === "Connected" && snapshot.store.settings.terminalExpanded) {
      void ensureTerminalShellOpen();
    }
  }, [snapshot?.runtime.state, snapshot?.store.settings.terminalExpanded]);

  const store = snapshot?.store ?? createDefaultStore();
  const runtime = snapshot?.runtime;
  const selectedConfig = store.sshConfigs.find((config) => config.id === store.selectedConfigId);
  const enabledRules = store.routingRules.filter((rule) => rule.enabled);
  const selectedRulesBlocked = store.routingMode === "selected-rules" && enabledRules.length === 0;
  const loggingEnabled = store.settings.loggingEnabled;
  const theme = resolveTheme(store.settings.theme);
  const customStyle = createThemeVars(store.settings);
  const terminalText = useMemo(() => (snapshot?.terminal ?? []).map((line) => line.text).join(""), [snapshot?.terminal]);

  useEffect(() => {
    if (!loggingEnabled && view === "logs") {
      setView("main");
    }
  }, [loggingEnabled, view]);

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
    setConfigModalError("");
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
      expectedServerFingerprint: config.expectedServerFingerprint,
      keepaliveIntervalSec: config.keepaliveIntervalSec,
      note: config.note
    });
    setView("configs");
    setConfigModalOpen(true);
  }

  function saveConfig(event: FormEvent): void {
    event.preventDefault();
    setBusy(true);
    setConfigModalError("");
    void api
      .upsertConfig({
        ...configDraft,
        privateKeyId: configDraft.privateKeyId || undefined,
        password: configDraft.password || undefined
      })
      .then((next) => {
        setSnapshot(next);
        setConfigDraft(emptyConfigDraft());
        setConfigModalOpen(false);
      })
      .catch((error: unknown) => setConfigModalError(toErrorMessage(error)))
      .finally(() => setBusy(false));
  }

  function openEndpointModal(): void {
    setEndpointDraft(store.settings.checkEndpoint);
    setEndpointModalError("");
    setEndpointModalOpen(true);
  }

  function saveEndpoint(event: FormEvent): void {
    event.preventDefault();
    const endpoint = endpointDraft.trim();
    const validation = validateEndpointInput(endpoint);
    if (!validation.ok) {
      setEndpointModalError(validation.message);
      return;
    }
    setBusy(true);
    setEndpointModalError("");
    void api
      .updateSettings({ ...store.settings, checkEndpoint: endpoint })
      .then((next) => {
        setSnapshot(next);
        setEndpointModalOpen(false);
      })
      .catch((error: unknown) => setEndpointModalError(toErrorMessage(error)))
      .finally(() => setBusy(false));
  }

  function copySavedPrivateKey(id: string | undefined): void {
    if (!id) {
      setKeyModalError("Save the SSH key before copying the stored private key.");
      return;
    }
    setKeyModalError("");
    void api
      .copyPrivateKey(id)
      .then(() => setKeyModalError("Saved private key copied to clipboard."))
      .catch((error: unknown) => setKeyModalError(toErrorMessage(error)));
  }

  function openKeyModal(draft: KeyDraft): void {
    setKeyModalError("");
    setKeyDraft(draft);
    setKeyModalOpen(true);
  }

  function openConfigModal(draft: ConfigDraft): void {
    setConfigModalError("");
    setConfigDraft(draft);
    setConfigModalOpen(true);
  }

  function closeConfigModal(): void {
    setConfigModalOpen(false);
    setConfigDraft(emptyConfigDraft());
    setConfigModalError("");
  }

  function closeKeyModal(): void {
    setKeyModalOpen(false);
    setKeyDraft(emptyKeyDraft());
    setKeyModalError("");
  }

  function closeEndpointModal(): void {
    setEndpointModalOpen(false);
    setEndpointModalError("");
    setEndpointDraft(store.settings.checkEndpoint);
  }

  function editKey(key: SshKeyMetadata): void {
    openKeyModal({
      mode: "edit",
      id: key.id,
      name: key.name,
      privateKey: "",
      privateKeyPassphrase: ""
    });
    setView("keys");
  }

  function saveKey(event: FormEvent): void {
    event.preventDefault();
    setBusy(true);
    setKeyModalError("");
    const payload: UpsertSshKeyInput = {
      id: keyDraft.id,
      name: keyDraft.name,
      privateKey: keyDraft.privateKey || undefined,
      privateKeyPassphrase: keyDraft.privateKeyPassphrase || undefined
    };
    void api
      .upsertKey(payload)
      .then((next) => {
        setSnapshot(next);
        setKeyDraft(emptyKeyDraft());
        setKeyModalOpen(false);
      })
      .catch((error: unknown) => setKeyModalError(toErrorMessage(error)))
      .finally(() => setBusy(false));
  }

  function persistRoutingRules(nextRules: RoutingRule[], successMessage?: string): void {
    const sequence = routingSaveSeq.current + 1;
    routingSaveSeq.current = sequence;
    setRoutingSaveState("saving");
    void api
      .updateRoutingRules(nextRules)
      .then((next) => {
        if (routingSaveSeq.current !== sequence) {
          return;
        }
        setSnapshot(next);
        setRoutingSaveState("saved");
        if (successMessage) {
          setNotice(successMessage);
        }
      })
      .catch((error: unknown) => {
        if (routingSaveSeq.current !== sequence) {
          return;
        }
        setRoutingSaveState("error");
        setNotice(toErrorMessage(error));
      });
  }

  function updateRoutingDraft(mutator: (rules: RoutingRule[]) => RoutingRule[]): void {
    const next = mutator(routingDraft);
    setRoutingDraft(next);
    persistRoutingRules(next);
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
        setRoutingDraft(validRules);
        persistRoutingRules(validRules, `Imported and saved ${validRules.length} valid rules.`);
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

  function sendTerminalInput(event: FormEvent): void {
    event.preventDefault();
    if (!terminalInput.trim()) {
      return;
    }
    void api.terminalInput(`${terminalInput}\n`);
    setTerminalInput("");
  }

  async function handleTerminalToggle(open: boolean): Promise<void> {
    try {
      const next = await api.updateSettings({ ...store.settings, terminalExpanded: open });
      setSnapshot(next);
      if (open) {
        await ensureTerminalShellOpen();
      } else if (terminalShellOpen && runtime?.state === "Connected") {
        await closeTerminalShell(false);
      }
    } catch (error) {
      setNotice(toErrorMessage(error));
    }
  }

  async function ensureTerminalShellOpen(): Promise<void> {
    if (runtime?.state !== "Connected" || terminalShellOpen || terminalOpening) {
      return;
    }
    setTerminalOpening(true);
    try {
      const next = await api.openTerminal();
      setSnapshot(next);
      setTerminalShellOpen(true);
    } catch (error) {
      setNotice(toErrorMessage(error));
    } finally {
      setTerminalOpening(false);
    }
  }

  async function closeTerminalShell(collapse = true): Promise<void> {
    if (terminalOpening) {
      return;
    }
    setTerminalOpening(true);
    try {
      const next = await api.closeTerminal();
      setSnapshot(next);
      setTerminalShellOpen(false);
      if (collapse) {
        const collapsed = await api.updateSettings({ ...store.settings, terminalExpanded: false });
        setSnapshot(collapsed);
      }
    } catch (error) {
      setNotice(toErrorMessage(error));
    } finally {
      setTerminalOpening(false);
    }
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
      <Sidebar
        view={view}
        platform={runtime?.platformTarget.platform}
        arch={runtime?.platformTarget.arch}
        loggingEnabled={loggingEnabled}
        onViewChange={setView}
      />

      <main className="content">
        <Topbar title={titleForView(view)} message={runtime?.message} state={runtime?.state ?? "Disconnected"} />
        <Notice message={notice} onDismiss={() => setNotice("")} />

        {view === "main" && (
          <MainView
            store={store}
            runtime={runtime}
            selectedConfig={selectedConfig}
            selectedRulesBlocked={selectedRulesBlocked}
            busy={busy}
            checking={checking}
            lastTunnelCheck={snapshot.lastTunnelCheck}
            enabledRulesCount={enabledRules.length}
            terminalText={terminalText}
            terminalInput={terminalInput}
            terminalOpening={terminalOpening}
            onSelectConfig={(id) => void run(() => api.selectConfig(id))}
            onRoutingModeChange={(mode) => void run(() => api.updateRoutingMode(mode))}
            onConnect={() => void run(() => api.connect())}
            onDisconnect={() => void run(() => api.disconnect())}
            onCheckTunnel={() => {
              setChecking(true);
              void run(async () => api.checkTunnel(store.settings.checkEndpoint)).finally(() => setChecking(false));
            }}
            onEditEndpoint={openEndpointModal}
            onTerminalToggle={(open) => void handleTerminalToggle(open)}
            onCloseTerminalShell={() => void closeTerminalShell()}
            onTerminalInputChange={setTerminalInput}
            onTerminalSubmit={sendTerminalInput}
          />
        )}

        {view === "configs" && (
          <ConfigsView
            configs={store.sshConfigs}
            onNew={() => openConfigModal(emptyConfigDraft())}
            onSelect={(id) => void run(() => api.selectConfig(id))}
            onEdit={editConfig}
            onDelete={(config) => {
              if (window.confirm(`Delete SSH configuration "${config.name}"?`)) {
                void run(() => api.deleteConfig(config.id));
              }
            }}
          />
        )}

        {view === "keys" && (
          <KeysView
            keys={store.sshKeys}
            onNew={() => openKeyModal(emptyKeyDraft())}
            onEdit={editKey}
            onDelete={(key) => {
              if (window.confirm(`Delete SSH key "${key.name}"?`)) {
                void run(() => api.deleteKey(key.id));
              }
            }}
          />
        )}

        {view === "routing" && (
          <RoutingView
            ruleTab={ruleTab}
            ruleSearch={ruleSearch}
            ruleValue={ruleValue}
            ruleError={ruleError}
            routingSaveState={routingSaveState}
            filteredRules={filteredRules}
            filteredProcesses={filteredProcesses}
            processSearch={processSearch}
            enabledCount={routingDraft.filter((rule) => rule.enabled).length}
            onRuleTabChange={setRuleTab}
            onRuleSearchChange={setRuleSearch}
            onRuleValueChange={setRuleValue}
            onAddRule={addRule}
            onExportRules={exportRules}
            onImportRules={importRules}
            onProcessSearchChange={setProcessSearch}
            onLoadProcesses={loadProcesses}
            onUpdateRules={updateRoutingDraft}
          />
        )}

        {view === "logs" && (
          <LogsView
            snapshot={snapshot}
            fileLog={fileLog}
            fileLogBusy={fileLogBusy}
            onUpdateSettings={updateSettings}
            onRefresh={refreshFileLog}
            onCopy={copyUnifiedLog}
            onClear={clearUnifiedLog}
          />
        )}

        {view === "settings" && (
          <SettingsView
            store={store}
            loggingEnabled={loggingEnabled}
            onUpdateSettings={updateSettings}
          />
        )}
      </main>

      <Modal
        open={configModalOpen}
        title={configDraft.mode === "edit" ? "Edit SSH configuration" : "Add SSH configuration"}
        onClose={closeConfigModal}
      >
        <ConfigForm
          draft={configDraft}
          error={configModalError}
          keys={store.sshKeys}
          onChange={setConfigDraft}
          onSubmit={saveConfig}
          onCancel={closeConfigModal}
        />
      </Modal>

      <Modal
        open={keyModalOpen}
        title={keyDraft.mode === "edit" ? "Edit SSH key" : "Add SSH key"}
        onClose={closeKeyModal}
      >
        <KeyForm
          draft={keyDraft}
          error={keyModalError}
          onChange={setKeyDraft}
          onSubmit={saveKey}
          onCancel={closeKeyModal}
          onCopySavedPrivateKey={copySavedPrivateKey}
        />
      </Modal>

      <Modal open={endpointModalOpen} title="Edit tunnel check endpoint" onClose={closeEndpointModal}>
        <EndpointForm
          value={endpointDraft}
          error={endpointModalError}
          onChange={setEndpointDraft}
          onSubmit={saveEndpoint}
          onCancel={closeEndpointModal}
        />
      </Modal>
    </div>
  );
}
