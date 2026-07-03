import { createDefaultRuntimeStatus, createDefaultStore } from "../shared/defaults.js";
import type { ServiceEvent, ShadowSshApi } from "../shared/ipc.js";
import type {
  AppSettings,
  AppUpdateDownload,
  AppUpdateInfo,
  AppSnapshot,
  DiagnosticsEntry,
  ImportProxyProfilesInput,
  RoutingMode,
  RoutingRule,
  ProxyProfile,
  SshConfig,
  SshKeyMetadata,
  TerminalLine,
  TunnelCheckResult,
  UpsertProxyProfileInput,
  UpsertSshConfigInput,
  UpsertSshKeyInput
} from "../shared/types.js";

const MAX_PREVIEW_DIAGNOSTICS = 500;
const MAX_PREVIEW_TERMINAL_LINES = 2000;

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
  let updateInfo: AppUpdateInfo | undefined;
  let updateDownload: AppUpdateDownload = { state: "idle", downloadedBytes: 0 };
  let fileLog = "";

  runtime = {
    ...runtime,
    message: "Browser preview uses an in-memory simulator. Start Electron for real preload IPC.",
    transport: "simulator",
    realTunnelAvailable: false
  };

  const snapshot = (): AppSnapshot =>
    structuredClone({ store, runtime, diagnostics, terminal, logFilePaths: ["browser-preview://main.log"], lastTunnelCheck, updateInfo, updateDownload });
  const emit = (event: ServiceEvent): void => {
    for (const listener of listeners) {
      listener(event);
    }
  };
  const appendDiagnostic = (level: DiagnosticsEntry["level"], message: string): void => {
    if (!store.settings.loggingEnabled || !store.settings.diagnosticsLoggingEnabled) {
      return;
    }
    const entry: DiagnosticsEntry = { id: crypto.randomUUID(), at: new Date().toISOString(), level, message };
    diagnostics = [...diagnostics, entry].slice(-MAX_PREVIEW_DIAGNOSTICS);
    emit({ type: "diagnostics-appended", entry });
  };
  const setRuntime = (patch: Partial<typeof runtime>): void => {
    runtime = { ...runtime, ...patch };
    emit({ type: "status-changed", status: runtime });
  };
  const appendTerminal = (text: string): void => {
    const line: TerminalLine = { id: crypto.randomUUID(), at: new Date().toISOString(), stream: "system", text };
    terminal = [...terminal, line].slice(-MAX_PREVIEW_TERMINAL_LINES);
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
        privateKeyPassphraseSecretId: undefined,
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
        privateKeyPassphraseSecretId: input.privateKeyPassphrase
          ? `preview-passphrase-${crypto.randomUUID()}`
          : existing?.privateKeyPassphraseSecretId,
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
    async copyPrivateKey(id: string) {
      if (!store.sshKeys.some((key) => key.id === id)) {
        throw new Error("SSH key does not exist.");
      }
      return true;
    },
    async deleteKey(id: string) {
      if (store.sshConfigs.some((config) => config.privateKeyId === id)) {
        throw new Error("This private key is used by at least one SSH configuration.");
      }
      store = { ...store, sshKeys: store.sshKeys.filter((key) => key.id !== id) };
      return snapshot();
    },
    async upsertProxyProfile(input: UpsertProxyProfileInput) {
      const now = new Date().toISOString();
      const existing = input.id ? store.proxyProfiles.find((profile) => profile.id === input.id) : undefined;
      const profile = makePreviewProxyProfile(input.rawUri, input.name, existing, input.source ?? "manual");
      store = {
        ...store,
        proxyProfiles: existing
          ? store.proxyProfiles.map((candidate) => (candidate.id === profile.id ? profile : candidate))
          : [...store.proxyProfiles, profile],
        selectedProxyProfileId: store.selectedProxyProfileId ?? profile.id
      };
      store = {
        ...store,
        proxyProfiles: store.proxyProfiles.map((candidate) => ({ ...candidate, isSelected: candidate.id === store.selectedProxyProfileId, updatedAt: now }))
      };
      return snapshot();
    },
    async importProxyProfiles(input: ImportProxyProfilesInput) {
      const links = input.text.split(/\r?\n/u).map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
      const profiles = links.map((line) => makePreviewProxyProfile(line, "", undefined, input.source));
      store = {
        ...store,
        proxyProfiles: [...store.proxyProfiles, ...profiles],
        selectedProxyProfileId: store.selectedProxyProfileId ?? profiles[0]?.id
      };
      return {
        snapshot: snapshot(),
        result: { imported: profiles.length, updated: 0, skipped: 0, failed: 0, errors: [] }
      };
    },
    async refreshProxyProfiles() {
      const profile = makePreviewProxyProfile("vless://preview@example.com:443?security=tls&type=tcp#Preview", "Preview", undefined, "remote");
      store = {
        ...store,
        proxyProfiles: store.proxyProfiles.some((candidate) => candidate.fingerprint === profile.fingerprint)
          ? store.proxyProfiles
          : [...store.proxyProfiles, profile],
        selectedProxyProfileId: store.selectedProxyProfileId ?? profile.id
      };
      return {
        snapshot: snapshot(),
        result: { imported: 1, updated: 0, skipped: 0, failed: 0, errors: [] }
      };
    },
    async selectProxyProfile(id: string) {
      store = {
        ...store,
        selectedProxyProfileId: id,
        proxyProfiles: store.proxyProfiles.map((profile) => ({ ...profile, isSelected: profile.id === id }))
      };
      return snapshot();
    },
    async toggleProxyProfilePin(id: string) {
      store = {
        ...store,
        proxyProfiles: store.proxyProfiles.map((profile) => (profile.id === id ? { ...profile, isPinned: !profile.isPinned } : profile))
      };
      return snapshot();
    },
    async deleteProxyProfile(id: string) {
      store = { ...store, proxyProfiles: store.proxyProfiles.filter((profile) => profile.id !== id) };
      return snapshot();
    },
    async deleteUnpinnedProxyProfiles() {
      store = { ...store, proxyProfiles: store.proxyProfiles.filter((profile) => profile.isPinned) };
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
    async clearDiagnostics() {
      diagnostics = [];
      return snapshot();
    },
    async readLogFile() {
      return store.settings.loggingEnabled && store.settings.fileLoggingEnabled ? fileLog : "";
    },
    async clearLogFile() {
      fileLog = "";
      return fileLog;
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
    async connectProxy() {
      const selectedProfile = store.proxyProfiles.find((profile) => profile.id === store.selectedProxyProfileId);
      if (!selectedProfile) {
        appendDiagnostic("error", "Select or import a proxy profile before connecting.");
        return snapshot();
      }
      setRuntime({
        state: "Connected",
        activeConfigId: selectedProfile.id,
        connectedAt: new Date().toISOString(),
        message: `Browser preview connected to ${selectedProfile.protocol.toUpperCase()} simulator.`,
        transport: "xray",
        realTunnelAvailable: false
      });
      appendDiagnostic("warning", "Browser preview does not start Xray or OS routes.");
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
    async closeTerminal() {
      appendTerminal("\nPreview shell is closed.\n");
      return snapshot();
    },
    async terminalInput() {
      appendTerminal("\n[preview] Command input is hidden and was not sent to a remote shell.\n$ ");
    },
    async checkForUpdates() {
      updateInfo = {
        available: false,
        currentVersion: "0.1.0",
        checkedAt: new Date().toISOString(),
        message: "Browser preview update check is simulated."
      };
      return { snapshot: snapshot(), update: updateInfo };
    },
    async downloadUpdate() {
      updateDownload = { state: "downloaded", downloadedBytes: 1, totalBytes: 1, percent: 100, filePath: "browser-preview://update.exe" };
      return snapshot();
    },
    async revealDownloadedUpdate() {
      return true;
    },
    async copyText(text: string) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        return false;
      }
    },
    async openExternal(url: string) {
      window.open(url, "_blank", "noopener,noreferrer");
      return true;
    },
    onServiceEvent(callback: (event: ServiceEvent) => void) {
      listeners.add(callback);
      return () => listeners.delete(callback);
    }
  };
}

function makePreviewProxyProfile(rawUri: string, name: string, existing: ProxyProfile | undefined, source: ProxyProfile["source"]): ProxyProfile {
  const now = new Date().toISOString();
  const protocol = rawUri.startsWith("vmess://") ? "vmess" : rawUri.startsWith("trojan://") ? "trojan" : "vless";
  let host = "example.com";
  let port = 443;
  try {
    if (protocol !== "vmess") {
      const url = new URL(rawUri);
      host = url.hostname || host;
      port = Number(url.port) || port;
      name ||= decodeURIComponent(url.hash.replace(/^#/u, "")) || `${protocol}-${host}:${port}`;
    }
  } catch {
    name ||= `${protocol}-${host}:${port}`;
  }
  return {
    id: existing?.id ?? crypto.randomUUID(),
    name: name || `${protocol}-${host}:${port}`,
    protocol,
    host,
    port,
    transport: "tcp",
    security: "tls",
    flow: "",
    source,
    rawUriSecretId: existing?.rawUriSecretId ?? `preview-proxy-${crypto.randomUUID()}`,
    fingerprint: existing?.fingerprint ?? `sha256:preview-${crypto.randomUUID()}`,
    isSelected: existing?.isSelected ?? false,
    isPinned: existing?.isPinned ?? false,
    isStale: false,
    lastTestStatus: existing?.lastTestStatus ?? "unknown",
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
    lastSeenAt: now
  };
}
