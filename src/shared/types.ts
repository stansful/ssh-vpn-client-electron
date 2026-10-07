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
export type ProxyProtocol = "vless" | "vmess" | "trojan" | "hysteria2";
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

export type SshKeyType = "ed25519" | "rsa" | "ecdsa" | "dsa" | "unknown";
export type SshKeyFormat = "openssh" | "pem" | "pkcs8" | "unknown";

export interface SshKeyMetadata {
  id: string;
  name: string;
  privateKeySecretId: string;
  privateKeyPassphraseSecretId?: string;
  fingerprint: string;
  /** Detected from the key text when it is saved (or lazily for older stores). */
  keyType?: SshKeyType;
  keyFormat?: SshKeyFormat;
  /** True for passphrase-protected OpenSSH keys, which the SSH core cannot load yet. */
  encryptedOpenSsh?: boolean;
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

export interface RoutingProxyList {
  enabled: boolean;
  sourceUrl: string;
  domains: string[];
  updatedAt?: string;
}

export interface RoutingDirectList {
  enabled: boolean;
  sourceUrl: string;
  domains: string[];
  updatedAt?: string;
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
  releaseRendererInTrayEnabled: boolean;
  startWithWindowsInTray: boolean;
  autoConnectOnStartup: boolean;
  sidebarCollapsed: boolean;
  activeGlobalTab: GlobalTab;
  lastConnectedTransport: GlobalTab;
  xrayConsentAccepted: boolean;
  showXrayWarningOnEnter: boolean;
  xrayRiskBannerExpanded: boolean;
  /**
   * Routes traffic through a TUN adapter instead of the Windows user proxy.
   *
   * The proxy setting is advisory and TCP-only, so an application that ignores
   * it - Telegram, Discord voice, anything speaking QUIC - leaves directly no
   * matter what a `process.name` rule says. The adapter owns the routes, so the
   * OS hands the packets over regardless. It needs administrator rights, which
   * a portable build only has if the user started it that way, so this stays
   * opt-in and falls back to the proxy path when it cannot come up.
   */
  tunDataplaneEnabled: boolean;
  /** Desktop (OS) notification when the tunnel drops, comes back or stops reconnecting. */
  notifyTunnelChanges: boolean;
  /** Desktop notification when an update finished downloading. */
  notifyUpdateDownloaded: boolean;
  /** One-time desktop notification the first time the window closes to the tray. */
  notifyStillRunningInTray: boolean;
  /** Only show desktop notifications while the window is hidden or minimized. */
  notifyOnlyWhenHidden: boolean;
  /** Set once the "still running in the tray" notification has been shown. */
  stillRunningNoticeShown: boolean;
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
  routingProxyList: RoutingProxyList;
  routingDirectList: RoutingDirectList;
  /** Last successful download of the public Xray list. */
  publicProxyRefresh?: PublicProxyRefresh;
}

export interface PublicProxyRefresh {
  at: string;
  /** Distinct profiles the list held at that refresh. */
  listed: number;
}

export interface ProxyProfile {
  id: string;
  name: string;
  protocol: ProxyProtocol;
  host: string;
  /**
   * The server port. For a Hysteria 2 port-hopping link it is the first port
   * written in the link, shown and protected, but Xray starts on a random
   * port of hopPorts and never dials this one.
   */
  port: number;
  /** Hysteria 2 port hopping: every server port the link hops across ("443,20000-30000"). */
  hopPorts?: string;
  /**
   * The Hysteria 2 link asks to skip certificate checks (insecure=1,
   * allowInsecure or allow_insecure) without a pinSHA256. Xray verifies the
   * certificate anyway, so a server with a self-signed one fails. Only `true`
   * is stored; the key is left out otherwise.
   */
  insecureWithoutPin?: boolean;
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
  hopPorts?: string;
  /** See `ProxyProfile.insecureWithoutPin`: present (true) only for such Hysteria 2 links. */
  insecureWithoutPin?: boolean;
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

export type DiagnosticsSource = "ssh" | "xray" | "routing" | "update" | "app";

export interface DiagnosticsEntry {
  id: string;
  at: string;
  level: "info" | "warning" | "error";
  message: string;
  /** Which part of the app produced the entry; renderers fall back to message heuristics when absent. */
  source?: DiagnosticsSource;
}

/**
 * Events that change how traffic flows and that the user must see even if the
 * live diagnostics are cleared on the next connect. They stay until dismissed.
 */
export type AttentionKind =
  | "split-tunnel-no-targets"
  | "tun-unavailable"
  | "reconnect-stopped"
  | "auto-connect-failed"
  | "auto-connect-skipped"
  | "system-proxy-restore-failed"
  | "system-proxy-recovered"
  | "storage-unreadable"
  | "other";

export interface AttentionEvent {
  id: string;
  at: string;
  kind: AttentionKind;
  level: "info" | "warning" | "error";
  source: DiagnosticsSource;
  title: string;
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

export interface LocalProxyEndpoint {
  host: string;
  /** HTTP proxy port. For SSH the same port also speaks SOCKS5. */
  httpPort: number;
  /** SOCKS5 port when it differs from the HTTP port (Xray). */
  socksPort?: number;
}

export interface RuntimeStatus {
  state: ConnectionState;
  activeConfigId?: string;
  /** Display name of the server or profile the session was started with (survives renames/deletes). */
  activeConfigName?: string;
  /** host:port the session targets. */
  activeTarget?: string;
  message: string;
  connectedAt?: string;
  reconnectAttempt: number;
  transport: ServiceTransport;
  platformTarget: PlatformTarget;
  realTunnelAvailable: boolean;
  /** Local proxy the session exposes, once it is listening. */
  localProxy?: LocalProxyEndpoint;
  /** OpenSSH-style SHA256 fingerprint of the server host key verified in this session (SSH only). */
  observedHostKeyFingerprint?: string;
  /** Whether the TUN adapter actually carries traffic for this session (Windows only). */
  tunActive?: boolean;
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
  /** Round-trip time of a passed check. */
  latencyMs?: number;
  /** A pass with a caveat (the endpoint stayed silent on a port that does not need to speak first). */
  note?: boolean;
  /** Which tunnel was checked. */
  transport?: GlobalTab;
  /** Name of the server or profile that was checked. */
  targetName?: string;
}

export interface ConnectRequest {
  config: SshConfig;
  routingMode: RoutingMode;
  routingRules: RoutingRule[];
  routingProxyDomains: string[];
  routingDirectDomains: string[];
  checkEndpoint: string;
  /** Mirrors `AppSettings.tunDataplaneEnabled` for this connection. */
  tunDataplaneEnabled?: boolean;
  secrets?: SshServiceSecrets;
}

export interface ProxyConnectRequest {
  profile: ProxyProfile;
  routingMode: RoutingMode;
  routingRules: RoutingRule[];
  /** Mirrors `AppSettings.tunDataplaneEnabled` for this connection. */
  tunDataplaneEnabled?: boolean;
  routingProxyDomains: string[];
  routingDirectDomains: string[];
  checkEndpoint: string;
  secrets: ProxyServiceSecrets;
}

export interface RoutingUpdateRequest {
  routingMode: RoutingMode;
  routingRules: RoutingRule[];
  routingProxyDomains: string[];
  routingDirectDomains: string[];
  checkEndpoint: string;
  tunDataplaneEnabled?: boolean;
}

export interface ProxyServiceSecrets {
  rawUri: string;
}

export interface SshServiceSecrets {
  password?: string;
  privateKey?: string;
  privateKeyPassphrase?: string;
}

export type StorageHealth =
  | { state: "ok" }
  | {
      state: "unreadable";
      /** Plain reason, e.g. a JSON parse error or a size limit. */
      message: string;
      /** The file that couldn't be read. */
      storePath: string;
      dataDirectory: string;
      /** Only the secret file is unreadable: Start fresh keeps servers, rules and settings. */
      secretsOnly?: boolean;
    };

export interface TunStatus {
  /** TUN capture exists on this platform (Windows only today). */
  supported: boolean;
  /** The user setting. */
  enabled: boolean;
  /** The process runs with administrator rights. */
  elevated: boolean;
  /** wintun.dll was found next to the app or in the data folder. */
  wintunFound: boolean;
  /** Folders searched for wintun.dll, in order. */
  searchedPaths: string[];
  /** TUN carries traffic for the current session. */
  active: boolean;
  /** The setting changed while connected, so it takes effect on the next connect. */
  appliesOnNextConnect: boolean;
  /** Why TUN was not used for the current session, when it was wanted. */
  lastFailure?: string;
}

export interface AppEnvironment {
  version: string;
  platform: DesktopPlatform;
  arch: RuntimeArch;
  dataDirectory: string;
  logDirectory: string;
  /** Where secrets are encrypted: "Windows DPAPI", "macOS Keychain", "Linux keyring" or "unavailable". */
  secretsBackend: string;
  isDevBuild: boolean;
}

/** The connect auto-connect started at app start, for the "Connecting automatically" notice. */
export interface AutoConnectNotice {
  at: string;
  transport: GlobalTab;
  targetName: string;
}

/** One log file on disk: main.log or one of its rotation archives. */
export interface LogFileInfo {
  path: string;
  /** Size in bytes (0 when the file does not exist). */
  size: number;
  exists: boolean;
}

export interface AppSnapshot {
  store: AppStore;
  runtime: RuntimeStatus;
  /** Which transport owns `runtime`. */
  activeTransport: GlobalTab;
  diagnostics: DiagnosticsEntry[];
  attention: AttentionEvent[];
  terminal: TerminalLine[];
  logFilePaths: string[];
  lastTunnelCheck?: TunnelCheckResult;
  /** A tunnel check is running (started from any window, the tray or right after a connect). */
  tunnelCheckRunning: boolean;
  /**
   * Why the connection core didn't start, when Connect fell back to the
   * simulator ("Preview only"). Stays for the whole app run.
   */
  startupFailure?: string;
  /** Set when auto-connect started a connect at app start. */
  autoConnect?: AutoConnectNotice;
  updateInfo?: AppUpdateInfo;
  updateDownload?: AppUpdateDownload;
  storageHealth: StorageHealth;
  tunStatus: TunStatus;
  environment: AppEnvironment;
}

/**
 * Result of a routing mutation. The change is always saved before it is
 * applied; `applyError` reports a save that could not be applied to the
 * running tunnel (for example a failed system proxy write).
 */
export interface RoutingMutationResult {
  snapshot: AppSnapshot;
  applyError?: string;
}
