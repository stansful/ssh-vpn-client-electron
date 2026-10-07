import type {
  AppSettings,
  AppSnapshot,
  AppUpdateDownload,
  AppUpdateInfo,
  AttentionEvent,
  GlobalTab,
  LogFileInfo,
  RoutingMutationResult,
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
  getLogFileInfo: "shadow-ssh:get-log-file-info",
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
  readClipboardText: "shadow-ssh:read-clipboard-text",
  openExternal: "shadow-ssh:open-external",
  dismissConnectionError: "shadow-ssh:dismiss-connection-error",
  dismissAttention: "shadow-ssh:dismiss-attention",
  openLogFolder: "shadow-ssh:open-log-folder",
  openDataFolder: "shadow-ssh:open-data-folder",
  recoverStorage: "shadow-ssh:recover-storage",
  quitApp: "shadow-ssh:quit-app",
  serviceEvent: "shadow-ssh:service-event"
} as const;

export type ServiceEvent =
  | { type: "status-changed"; status: RuntimeStatus }
  | { type: "diagnostics-appended"; entry: DiagnosticsEntry }
  | { type: "tunnel-check-result"; result: TunnelCheckResult }
  | { type: "terminal-output"; line: TerminalLine }
  | { type: "error"; message: string };

export type RendererEvent =
  | ServiceEvent
  | { type: "update-download-changed"; download: AppUpdateDownload }
  | { type: "attention-changed"; attention: AttentionEvent[] }
  /**
   * Main-process state changed outside a renderer request (tray menu actions,
   * auto-connect, storage recovery). The renderer should reload its snapshot.
   */
  | { type: "snapshot-invalidated"; reason: string }
  /** The active transport switched (SSH <-> Xray); `runtime` follows it. */
  | { type: "active-transport-changed"; transport: GlobalTab; status: RuntimeStatus }
  /** A tunnel check started or finished (mirrors `AppSnapshot.tunnelCheckRunning`). */
  | { type: "tunnel-check-changed"; running: boolean };

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
  updateRoutingMode(mode: RoutingMode): Promise<RoutingMutationResult>;
  updateRoutingRules(rules: RoutingRule[]): Promise<RoutingMutationResult>;
  updateRoutingProxyListEnabled(enabled: boolean): Promise<RoutingMutationResult>;
  refreshRoutingProxyList(): Promise<RoutingMutationResult>;
  updateRoutingDirectListEnabled(enabled: boolean): Promise<RoutingMutationResult>;
  refreshRoutingDirectList(): Promise<RoutingMutationResult>;
  clearDiagnostics(): Promise<AppSnapshot>;
  readLogFile(): Promise<string>;
  /** main.log and its rotation archives, newest first, with their sizes on disk. */
  getLogFileInfo(): Promise<LogFileInfo[]>;
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
  /** Plain-text clipboard contents (capped at 2 MiB of characters) for explicit Paste buttons. */
  readClipboardText(): Promise<string>;
  openExternal(url: string): Promise<boolean>;
  /** Leaves the Error state of the active transport and returns it to Disconnected. */
  dismissConnectionError(): Promise<AppSnapshot>;
  /** Dismisses one attention event, or all of them when `id` is omitted. */
  dismissAttention(id?: string): Promise<AppSnapshot>;
  openLogFolder(): Promise<boolean>;
  openDataFolder(): Promise<boolean>;
  /**
   * Recovers from unreadable saved data. "start-fresh" renames the unreadable
   * files to `*.unreadable-<timestamp>.json` (a backup) and starts with defaults.
   */
  recoverStorage(action: "start-fresh"): Promise<AppSnapshot>;
  quitApp(): Promise<void>;
  onServiceEvent(callback: (event: RendererEvent) => void): () => void;
}
