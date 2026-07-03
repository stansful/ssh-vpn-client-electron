export type ConnectionState =
  | "Disconnected"
  | "Connecting"
  | "Connected"
  | "Reconnecting"
  | "Disconnecting"
  | "Error";

export type AuthType = "password" | "private-key";
export type RoutingMode = "proxy-all" | "selected-rules";
export type RoutingRuleType = "domain" | "ip" | "process.name";
export type ThemeMode = "system" | "light" | "dark" | "custom";
export type DesktopPlatform = "windows" | "macos" | "linux" | "unknown";
export type RuntimeArch = "x64" | "arm64" | "ia32" | "unknown";
export type ServiceTransport = "native-ipc" | "live-ssh" | "simulator";

export interface SshConfig {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authType: AuthType;
  passwordSecretId?: string;
  privateKeyId?: string;
  /** @deprecated Private-key passphrases belong to SSH keys. Kept for migration from older stores. */
  privateKeyPassphraseSecretId?: string;
  expectedServerFingerprint: string;
  keepaliveIntervalSec: number;
  note: string;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertSshConfigInput {
  id?: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authType: AuthType;
  password?: string;
  privateKeyId?: string;
  expectedServerFingerprint: string;
  keepaliveIntervalSec: number;
  note: string;
}

export interface SshKeyMetadata {
  id: string;
  name: string;
  privateKeySecretId: string;
  privateKeyPassphraseSecretId?: string;
  fingerprint: string;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertSshKeyInput {
  id?: string;
  name: string;
  privateKey?: string;
  privateKeyPassphrase?: string;
}

export interface RoutingRule {
  id: string;
  type: RoutingRuleType;
  value: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface RgbColor {
  r: number;
  g: number;
  b: number;
}

export interface CustomTheme {
  accent: RgbColor;
  success: RgbColor;
  danger: RgbColor;
  background: RgbColor;
  surface: RgbColor;
  text: RgbColor;
  muted: RgbColor;
  border: RgbColor;
}

export interface AppSettings {
  theme: ThemeMode;
  customTheme: CustomTheme;
  diagnosticsExpanded: boolean;
  terminalExpanded: boolean;
  checkEndpoint: string;
  loggingEnabled: boolean;
  diagnosticsLoggingEnabled: boolean;
  fileLoggingEnabled: boolean;
  closeToTrayEnabled: boolean;
}

export interface AppStore {
  schemaVersion: number;
  sshConfigs: SshConfig[];
  sshKeys: SshKeyMetadata[];
  selectedConfigId?: string;
  settings: AppSettings;
  routingMode: RoutingMode;
  routingRules: RoutingRule[];
}

export interface DiagnosticsEntry {
  id: string;
  at: string;
  level: "info" | "warning" | "error";
  message: string;
}

export interface TerminalLine {
  id: string;
  at: string;
  stream: "stdout" | "stderr" | "system";
  text: string;
}

export interface PlatformTarget {
  platform: DesktopPlatform;
  arch: RuntimeArch;
  serviceExecutableName: string;
  serviceRelativePath: string;
  supportsPrivilegedService: boolean;
}

export interface RuntimeStatus {
  state: ConnectionState;
  activeConfigId?: string;
  message: string;
  connectedAt?: string;
  reconnectAttempt: number;
  transport: ServiceTransport;
  platformTarget: PlatformTarget;
  realTunnelAvailable: boolean;
}

export interface TunnelCheckResult {
  endpoint: string;
  ok: boolean;
  at: string;
  message: string;
}

export interface ConnectRequest {
  config: SshConfig;
  routingMode: RoutingMode;
  routingRules: RoutingRule[];
  checkEndpoint: string;
  secrets?: SshServiceSecrets;
}

export interface SshServiceSecrets {
  password?: string;
  privateKey?: string;
  privateKeyPassphrase?: string;
}

export interface AppSnapshot {
  store: AppStore;
  runtime: RuntimeStatus;
  diagnostics: DiagnosticsEntry[];
  terminal: TerminalLine[];
  logFilePaths: string[];
  lastTunnelCheck?: TunnelCheckResult;
}
