import type {
  AppSettings,
  AppSnapshot,
  AppUpdateDownload,
  AppUpdateInfo,
  ImportProxyProfilesInput,
  ImportProxyProfilesResult,
  DiagnosticsEntry,
  RoutingMode,
  RoutingRule,
  RuntimeStatus,
  TerminalLine,
  TunnelCheckResult,
  UpsertProxyProfileInput,
  UpsertSshConfigInput,
  UpsertSshKeyInput
} from "./types.js";

export const IPC_CHANNELS = {
  loadSnapshot: "shadow-ssh:load-snapshot",
  upsertConfig: "shadow-ssh:upsert-config",
  deleteConfig: "shadow-ssh:delete-config",
  selectConfig: "shadow-ssh:select-config",
  upsertKey: "shadow-ssh:upsert-key",
  copyPrivateKey: "shadow-ssh:copy-private-key",
  deleteKey: "shadow-ssh:delete-key",
  upsertProxyProfile: "shadow-ssh:upsert-proxy-profile",
  importProxyProfiles: "shadow-ssh:import-proxy-profiles",
  refreshProxyProfiles: "shadow-ssh:refresh-proxy-profiles",
  selectProxyProfile: "shadow-ssh:select-proxy-profile",
  toggleProxyProfilePin: "shadow-ssh:toggle-proxy-profile-pin",
  deleteProxyProfile: "shadow-ssh:delete-proxy-profile",
  deleteUnpinnedProxyProfiles: "shadow-ssh:delete-unpinned-proxy-profiles",
  updateSettings: "shadow-ssh:update-settings",
  updateRoutingMode: "shadow-ssh:update-routing-mode",
  updateRoutingRules: "shadow-ssh:update-routing-rules",
  updateRoutingProxyListEnabled: "shadow-ssh:update-routing-proxy-list-enabled",
  refreshRoutingProxyList: "shadow-ssh:refresh-routing-proxy-list",
  updateRoutingDirectListEnabled: "shadow-ssh:update-routing-direct-list-enabled",
  refreshRoutingDirectList: "shadow-ssh:refresh-routing-direct-list",
  clearDiagnostics: "shadow-ssh:clear-diagnostics",
  readLogFile: "shadow-ssh:read-log-file",
  clearLogFile: "shadow-ssh:clear-log-file",
  listProcesses: "shadow-ssh:list-processes",
  connect: "shadow-ssh:connect",
  connectProxy: "shadow-ssh:connect-proxy",
  disconnect: "shadow-ssh:disconnect",
  checkTunnel: "shadow-ssh:check-tunnel",
  openTerminal: "shadow-ssh:open-terminal",
  closeTerminal: "shadow-ssh:close-terminal",
  terminalInput: "shadow-ssh:terminal-input",
  checkForUpdates: "shadow-ssh:check-for-updates",
  downloadUpdate: "shadow-ssh:download-update",
  revealDownloadedUpdate: "shadow-ssh:reveal-downloaded-update",
  copyText: "shadow-ssh:copy-text",
  openExternal: "shadow-ssh:open-external",
  serviceEvent: "shadow-ssh:service-event"
} as const;

export type ServiceEvent =
  | { type: "status-changed"; status: RuntimeStatus }
  | { type: "diagnostics-appended"; entry: DiagnosticsEntry }
  | { type: "tunnel-check-result"; result: TunnelCheckResult }
  | { type: "terminal-output"; line: TerminalLine }
  | { type: "error"; message: string };

export type RendererEvent = ServiceEvent | { type: "update-download-changed"; download: AppUpdateDownload };

export interface ShadowSshApi {
  loadSnapshot(): Promise<AppSnapshot>;
  upsertConfig(input: UpsertSshConfigInput): Promise<AppSnapshot>;
  deleteConfig(id: string): Promise<AppSnapshot>;
  selectConfig(id: string): Promise<AppSnapshot>;
  upsertKey(input: UpsertSshKeyInput): Promise<AppSnapshot>;
  copyPrivateKey(id: string): Promise<boolean>;
  deleteKey(id: string): Promise<AppSnapshot>;
  upsertProxyProfile(input: UpsertProxyProfileInput): Promise<AppSnapshot>;
  importProxyProfiles(input: ImportProxyProfilesInput): Promise<{ snapshot: AppSnapshot; result: ImportProxyProfilesResult }>;
  refreshProxyProfiles(): Promise<{ snapshot: AppSnapshot; result: ImportProxyProfilesResult }>;
  selectProxyProfile(id: string): Promise<AppSnapshot>;
  toggleProxyProfilePin(id: string): Promise<AppSnapshot>;
  deleteProxyProfile(id: string): Promise<AppSnapshot>;
  deleteUnpinnedProxyProfiles(): Promise<AppSnapshot>;
  updateSettings(patch: Partial<AppSettings>): Promise<AppSnapshot>;
  updateRoutingMode(mode: RoutingMode): Promise<AppSnapshot>;
  updateRoutingRules(rules: RoutingRule[]): Promise<AppSnapshot>;
  updateRoutingProxyListEnabled(enabled: boolean): Promise<AppSnapshot>;
  refreshRoutingProxyList(): Promise<AppSnapshot>;
  updateRoutingDirectListEnabled(enabled: boolean): Promise<AppSnapshot>;
  refreshRoutingDirectList(): Promise<AppSnapshot>;
  clearDiagnostics(): Promise<AppSnapshot>;
  readLogFile(): Promise<string>;
  clearLogFile(): Promise<string>;
  listProcesses(): Promise<string[]>;
  connect(): Promise<AppSnapshot>;
  connectProxy(): Promise<AppSnapshot>;
  disconnect(): Promise<AppSnapshot>;
  checkTunnel(endpoint?: string): Promise<AppSnapshot>;
  openTerminal(): Promise<AppSnapshot>;
  closeTerminal(): Promise<AppSnapshot>;
  terminalInput(input: string): Promise<void>;
  checkForUpdates(force?: boolean): Promise<{ snapshot: AppSnapshot; update: AppUpdateInfo }>;
  downloadUpdate(): Promise<AppSnapshot>;
  revealDownloadedUpdate(): Promise<boolean>;
  copyText(text: string): Promise<boolean>;
  openExternal(url: string): Promise<boolean>;
  onServiceEvent(callback: (event: RendererEvent) => void): () => void;
}
