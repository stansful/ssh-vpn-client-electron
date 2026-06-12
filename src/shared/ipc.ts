import type {
  AppSettings,
  AppSnapshot,
  DiagnosticsEntry,
  RoutingMode,
  RoutingRule,
  RuntimeStatus,
  TerminalLine,
  TunnelCheckResult,
  UpsertSshConfigInput,
  UpsertSshKeyInput
} from "./types.js";

export const IPC_CHANNELS = {
  loadSnapshot: "shadow-ssh:load-snapshot",
  upsertConfig: "shadow-ssh:upsert-config",
  deleteConfig: "shadow-ssh:delete-config",
  selectConfig: "shadow-ssh:select-config",
  upsertKey: "shadow-ssh:upsert-key",
  deleteKey: "shadow-ssh:delete-key",
  updateSettings: "shadow-ssh:update-settings",
  updateRoutingMode: "shadow-ssh:update-routing-mode",
  updateRoutingRules: "shadow-ssh:update-routing-rules",
  listProcesses: "shadow-ssh:list-processes",
  connect: "shadow-ssh:connect",
  disconnect: "shadow-ssh:disconnect",
  checkTunnel: "shadow-ssh:check-tunnel",
  openTerminal: "shadow-ssh:open-terminal",
  terminalInput: "shadow-ssh:terminal-input",
  serviceEvent: "shadow-ssh:service-event"
} as const;

export type ServiceEvent =
  | { type: "status-changed"; status: RuntimeStatus }
  | { type: "diagnostics-appended"; entry: DiagnosticsEntry }
  | { type: "tunnel-check-result"; result: TunnelCheckResult }
  | { type: "terminal-output"; line: TerminalLine }
  | { type: "error"; message: string };

export interface ShadowSshApi {
  loadSnapshot(): Promise<AppSnapshot>;
  upsertConfig(input: UpsertSshConfigInput): Promise<AppSnapshot>;
  deleteConfig(id: string): Promise<AppSnapshot>;
  selectConfig(id: string): Promise<AppSnapshot>;
  upsertKey(input: UpsertSshKeyInput): Promise<AppSnapshot>;
  deleteKey(id: string): Promise<AppSnapshot>;
  updateSettings(settings: AppSettings): Promise<AppSnapshot>;
  updateRoutingMode(mode: RoutingMode): Promise<AppSnapshot>;
  updateRoutingRules(rules: RoutingRule[]): Promise<AppSnapshot>;
  listProcesses(): Promise<string[]>;
  connect(): Promise<AppSnapshot>;
  disconnect(): Promise<AppSnapshot>;
  checkTunnel(endpoint?: string): Promise<AppSnapshot>;
  openTerminal(): Promise<AppSnapshot>;
  terminalInput(input: string): Promise<void>;
  onServiceEvent(callback: (event: ServiceEvent) => void): () => void;
}
