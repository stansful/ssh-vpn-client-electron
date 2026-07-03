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
export type ServiceTransport = "native-ipc" | "live-ssh" | "xray" | "simulator";
export type GlobalTab = "ssh" | "xray";
export type ProxyProtocol = "vless" | "vmess" | "trojan";
export type ProxyTransport = "tcp" | "ws" | "grpc" | "xhttp" | "httpupgrade" | "mkcp" | "http" | "hysteria" | "unknown";
export type ProxySecurity = "none" | "tls" | "reality" | "unknown";
export type ProxyProfileSource = "manual" | "clipboard" | "remote";
export type ProxyTestStatus = "unknown" | "available" | "unavailable" | "unsupported";

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
  startWithWindowsInTray: boolean;
  autoConnectOnStartup: boolean;
  sidebarCollapsed: boolean;
  activeGlobalTab: GlobalTab;
  lastConnectedTransport: GlobalTab;
  xrayConsentAccepted: boolean;
  showXrayWarningOnEnter: boolean;
  xrayRiskBannerExpanded: boolean;
  updateCheckCache?: AppUpdateCheckCache;
}

export interface AppStore {
  schemaVersion: number;
  sshConfigs: SshConfig[];
  sshKeys: SshKeyMetadata[];
  proxyProfiles: ProxyProfile[];
  selectedProxyProfileId?: string;
  selectedConfigId?: string;
  settings: AppSettings;
  routingMode: RoutingMode;
  routingRules: RoutingRule[];
}

export interface ProxyProfile {
  id: string;
  name: string;
  protocol: ProxyProtocol;
  host: string;
  port: number;
  transport: ProxyTransport;
  security: ProxySecurity;
  flow: string;
  source: ProxyProfileSource;
  sourceUrl?: string;
  rawUriSecretId: string;
  fingerprint: string;
  isSelected: boolean;
  isPinned: boolean;
  isStale: boolean;
  lastTestStatus: ProxyTestStatus;
  lastLatencyMs?: number;
  lastTestAt?: string;
  createdAt: string;
  updatedAt: string;
  lastSeenAt: string;
}

export interface ParsedProxyProfile {
  name: string;
  protocol: ProxyProtocol;
  host: string;
  port: number;
  transport: ProxyTransport;
  security: ProxySecurity;
  flow: string;
  rawUri: string;
  fingerprint: string;
}

export interface ImportProxyProfilesInput {
  text: string;
  source: ProxyProfileSource;
  sourceUrl?: string;
}

export interface ImportProxyProfilesResult {
  imported: number;
  updated: number;
  skipped: number;
  failed: number;
  errors: string[];
}

export interface UpsertProxyProfileInput {
  id?: string;
  name: string;
  rawUri: string;
  source?: ProxyProfileSource;
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

export interface AppUpdateAsset {
  name: string;
  version: string;
  arch: Extract<RuntimeArch, "x64" | "arm64">;
  size: number;
  digest?: string;
  downloadUrl: string;
}

export interface AppUpdateInfo {
  available: boolean;
  currentVersion: string;
  latestVersion?: string;
  releaseUrl?: string;
  publishedAt?: string;
  asset?: AppUpdateAsset;
  checkedAt: string;
  message: string;
}

export interface AppUpdateCheckCache {
  checkedAt: string;
  eTag?: string;
  latestVersion?: string;
}

export interface AppUpdateDownload {
  state: "idle" | "downloading" | "downloaded" | "error";
  downloadedBytes: number;
  totalBytes?: number;
  percent?: number;
  filePath?: string;
  message?: string;
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

export interface ProxyConnectRequest {
  profile: ProxyProfile;
  routingMode: RoutingMode;
  routingRules: RoutingRule[];
  checkEndpoint: string;
  secrets: ProxyServiceSecrets;
}

export interface RoutingUpdateRequest {
  routingMode: RoutingMode;
  routingRules: RoutingRule[];
  checkEndpoint: string;
}

export interface ProxyServiceSecrets {
  rawUri: string;
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
  updateInfo?: AppUpdateInfo;
  updateDownload?: AppUpdateDownload;
}
