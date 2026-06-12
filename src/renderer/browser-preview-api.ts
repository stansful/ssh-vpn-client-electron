import { createDefaultRuntimeStatus, createDefaultStore } from "../shared/defaults.js";
import type { ServiceEvent, ShadowSshApi } from "../shared/ipc.js";
import type {
  AppSettings,
  AppSnapshot,
  DiagnosticsEntry,
  RoutingMode,
  RoutingRule,
  SshConfig,
  SshKeyMetadata,
  TerminalLine,
  TunnelCheckResult,
  UpsertSshConfigInput,
  UpsertSshKeyInput
} from "../shared/types.js";

export function createBrowserPreviewApi(): ShadowSshApi {
  const listeners = new Set<(event: ServiceEvent) => void>();
  let store = createDefaultStore();
  let runtime = createDefaultRuntimeStatus({
    platform: "unknown",
    arch: "unknown",
    serviceExecutableName: "shadow-ssh-service",
    serviceRelativePath: "native/preview/shadow-ssh-service",
    supportsPrivilegedService: false
  });
  let diagnostics: DiagnosticsEntry[] = [];
  let terminal: TerminalLine[] = [];
  let lastTunnelCheck: TunnelCheckResult | undefined;

  runtime = {
    ...runtime,
    message: "Browser preview uses an in-memory simulator. Start Electron for real preload IPC.",
    transport: "simulator",
    realTunnelAvailable: false
  };

  const snapshot = (): AppSnapshot => structuredClone({ store, runtime, diagnostics, terminal, lastTunnelCheck });
  const emit = (event: ServiceEvent): void => {
    for (const listener of listeners) {
      listener(event);
    }
  };
  const appendDiagnostic = (level: DiagnosticsEntry["level"], message: string): void => {
    const entry: DiagnosticsEntry = { id: crypto.randomUUID(), at: new Date().toISOString(), level, message };
    diagnostics = [...diagnostics, entry];
    emit({ type: "diagnostics-appended", entry });
  };
  const setRuntime = (patch: Partial<typeof runtime>): void => {
    runtime = { ...runtime, ...patch };
    emit({ type: "status-changed", status: runtime });
  };
  const appendTerminal = (text: string): void => {
    const line: TerminalLine = { id: crypto.randomUUID(), at: new Date().toISOString(), stream: "system", text };
    terminal = [...terminal, line];
    emit({ type: "terminal-output", line });
  };

  return {
    async loadSnapshot() {
      return snapshot();
    },
    async upsertConfig(input: UpsertSshConfigInput) {
      const now = new Date().toISOString();
      const existing = input.id ? store.sshConfigs.find((config) => config.id === input.id) : undefined;
      const config: SshConfig = {
        id: existing?.id ?? crypto.randomUUID(),
        name: input.name.trim(),
        host: input.host.trim(),
        port: Number(input.port),
        username: input.username.trim(),
        authType: input.authType,
        passwordSecretId: input.password ? `preview-password-${crypto.randomUUID()}` : existing?.passwordSecretId,
        privateKeyId: input.privateKeyId,
        privateKeyPassphraseSecretId: input.privateKeyPassphrase ? `preview-passphrase-${crypto.randomUUID()}` : existing?.privateKeyPassphraseSecretId,
        expectedServerFingerprint: input.expectedServerFingerprint.trim(),
        keepaliveIntervalSec: Number(input.keepaliveIntervalSec),
        note: input.note.trim(),
        createdAt: existing?.createdAt ?? now,
        updatedAt: now
      };
      store = {
        ...store,
        sshConfigs: existing
          ? store.sshConfigs.map((candidate) => (candidate.id === config.id ? config : candidate))
          : [...store.sshConfigs, config],
        selectedConfigId: store.selectedConfigId ?? config.id
      };
      return snapshot();
    },
    async deleteConfig(id: string) {
      store = {
        ...store,
        sshConfigs: store.sshConfigs.filter((config) => config.id !== id),
        selectedConfigId: store.selectedConfigId === id ? store.sshConfigs.find((config) => config.id !== id)?.id : store.selectedConfigId
      };
      return snapshot();
    },
    async selectConfig(id: string) {
      store = { ...store, selectedConfigId: id };
      return snapshot();
    },
    async upsertKey(input: UpsertSshKeyInput) {
      const now = new Date().toISOString();
      const existing = input.id ? store.sshKeys.find((key) => key.id === input.id) : undefined;
      const key: SshKeyMetadata = {
        id: existing?.id ?? crypto.randomUUID(),
        name: input.name.trim(),
        privateKeySecretId: input.privateKey ? `preview-key-${crypto.randomUUID()}` : existing?.privateKeySecretId ?? `preview-key-${crypto.randomUUID()}`,
        fingerprint: existing?.fingerprint ?? `sha256:preview-${crypto.randomUUID().slice(0, 8)}`,
        createdAt: existing?.createdAt ?? now,
        updatedAt: now
      };
      store = {
        ...store,
        sshKeys: existing ? store.sshKeys.map((candidate) => (candidate.id === key.id ? key : candidate)) : [...store.sshKeys, key]
      };
      return snapshot();
    },
    async deleteKey(id: string) {
      if (store.sshConfigs.some((config) => config.privateKeyId === id)) {
        throw new Error("This private key is used by at least one SSH configuration.");
      }
      store = { ...store, sshKeys: store.sshKeys.filter((key) => key.id !== id) };
      return snapshot();
    },
    async updateSettings(settings: AppSettings) {
      store = { ...store, settings };
      return snapshot();
    },
    async updateRoutingMode(mode: RoutingMode) {
      store = { ...store, routingMode: mode };
      return snapshot();
    },
    async updateRoutingRules(rules: RoutingRule[]) {
      store = { ...store, routingRules: rules };
      return snapshot();
    },
    async listProcesses() {
      return ["chrome.exe", "msedge.exe", "telegram.exe", "discord.exe", "code.exe", "powershell.exe"];
    },
    async connect() {
      const selectedConfig = store.sshConfigs.find((config) => config.id === store.selectedConfigId);
      if (!selectedConfig) {
        appendDiagnostic("error", "Select or create an SSH configuration before connecting.");
        return snapshot();
      }
      if (store.routingMode === "selected-rules" && !store.routingRules.some((rule) => rule.enabled)) {
        appendDiagnostic("error", "Selected rules mode requires at least one enabled routing rule.");
        return snapshot();
      }
      diagnostics = [];
      terminal = [];
      lastTunnelCheck = undefined;
      setRuntime({ state: "Connected", activeConfigId: selectedConfig.id, connectedAt: new Date().toISOString(), message: "Browser preview connected to simulator." });
      appendDiagnostic("warning", "Browser preview does not create an SSH tunnel or OS routes.");
      return snapshot();
    },
    async disconnect() {
      setRuntime({ state: "Disconnected", activeConfigId: undefined, connectedAt: undefined, message: "Disconnected." });
      appendDiagnostic("info", "Disconnected by user.");
      return snapshot();
    },
    async checkTunnel(endpoint?: string) {
      lastTunnelCheck = {
        endpoint: endpoint ?? store.settings.checkEndpoint,
        ok: true,
        at: new Date().toISOString(),
        message: "Browser preview check succeeded without network tunnel."
      };
      emit({ type: "tunnel-check-result", result: lastTunnelCheck });
      return snapshot();
    },
    async openTerminal() {
      appendTerminal("Preview shell is open.\n$ ");
      return snapshot();
    },
    async terminalInput() {
      appendTerminal("\n[preview] Command input is hidden and was not sent to a remote shell.\n$ ");
    },
    onServiceEvent(callback: (event: ServiceEvent) => void) {
      listeners.add(callback);
      return () => listeners.delete(callback);
    }
  };
}
