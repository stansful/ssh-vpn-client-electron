import { createDefaultStore, DEFAULT_SETTINGS } from "../shared/defaults.js";
import { normalizeProxyDomain } from "../core/routing/domain-proxy-list.js";
import type { RendererEvent, ShadowSshApi } from "../shared/ipc.js";
import { appendBoundedDiagnosticEntries } from "../shared/diagnostics-history.js";
import { proxyProtocolLabel } from "../shared/proxy-protocols.js";
import { appendBoundedTerminalLine } from "../shared/terminal-history.js";
import type {
  AppEnvironment,
  AppSettings,
  AppSnapshot,
  AppStore,
  AppUpdateDownload,
  AppUpdateInfo,
  AttentionEvent,
  AutoConnectNotice,
  DesktopPlatform,
  DiagnosticsEntry,
  DiagnosticsSource,
  GlobalTab,
  ImportProxyProfilesInput,
  ImportProxyProfilesResult,
  LogFileInfo,
  ProxyProfile,
  ProxyProtocol,
  ProxySecurity,
  ProxyTransport,
  RoutingMode,
  RoutingMutationResult,
  RoutingRule,
  RuntimeStatus,
  SshConfig,
  SshKeyMetadata,
  StorageHealth,
  TerminalLine,
  TunnelCheckResult,
  TunStatus,
  UpsertProxyProfileInput,
  UpsertSshConfigInput,
  UpsertSshKeyInput
} from "../shared/types.js";
import { validateRoutingRuleValue } from "../shared/validation.js";
import { linkFingerprint, parseShareLink, type LinkPreview } from "./components/pages/profiles/link-preview.js";

/**
 * In-memory stand-in for the preload API when the renderer runs in a plain
 * browser (`vite`). It seeds the canon sample data from the design brief and
 * simulates connect, disconnect, tunnel checks, reconnects and attention events.
 *
 * URL parameters pick a starting point:
 *   ?scenario=off | connected (default) | xray | reconnecting | error | blocked |
 *             empty | startup-failed | storage-unreadable | load-error | slow | auto-connect
 *   ?platform=windows (default) | macos | linux
 *   ?logging=off
 * In the console, `shadowSshPreview` triggers events on demand:
 *   shadowSshPreview.reconnect("network")  // drop and restore the session
 *   shadowSshPreview.fail("SSH authentication failed: …")
 *   shadowSshPreview.attention()            // add an attention event
 */
export function createBrowserPreviewApi(): ShadowSshApi {
  const params = new URLSearchParams(typeof window !== "undefined" ? window.location.search : "");
  const scenario = params.get("scenario") ?? "connected";
  const platform = parsePlatform(params.get("platform"));
  return new BrowserPreview(scenario, platform, params.get("logging") !== "off").api;
}

type Listener = (event: RendererEvent) => void;

const PREVIEW_VERSION = "2.2.0";
const HOUR = 3600_000;
/** main.log rotates at 5 MB; the seeded archives are full ones. */
const LOG_ARCHIVE_BYTES = 5 * 1024 * 1024;
const PUBLIC_LIST_URL = "https://hub.mos.ru/zieng2/wl/raw/main/list_universal.txt";

class BrowserPreview {
  readonly api: ShadowSshApi;
  private readonly listeners = new Set<Listener>();
  private store: AppStore;
  private sshRuntime: RuntimeStatus;
  private xrayRuntime: RuntimeStatus;
  private activeTransport: GlobalTab = "ssh";
  private diagnostics: DiagnosticsEntry[];
  private attention: AttentionEvent[];
  private terminal: TerminalLine[] = [];
  private lastTunnelCheck: TunnelCheckResult | undefined;
  private updateInfo: AppUpdateInfo | undefined;
  private updateDownload: AppUpdateDownload = { state: "idle", downloadedBytes: 0 };
  private storageHealth: StorageHealth = { state: "ok" };
  private readonly environment: AppEnvironment;
  private fileLog: string;
  private logArchives = 2;
  private timers = new Set<ReturnType<typeof setTimeout>>();
  private shellOpen = false;
  private checksRunning = 0;
  /** Seeded public profiles get their real fingerprints (WebCrypto is async), so a refresh updates them. */
  private readonly ready: Promise<void>;
  private startupFailure: string | undefined;
  private autoConnect: AutoConnectNotice | undefined;

  constructor(private readonly scenario: string, private readonly platform: DesktopPlatform, loggingEnabled: boolean) {
    const today = startOfToday();
    this.environment = {
      version: PREVIEW_VERSION,
      platform,
      arch: platform === "macos" ? "arm64" : "x64",
      dataDirectory: dataDirectoryFor(platform),
      logDirectory: `${dataDirectoryFor(platform)}${platform === "windows" ? "\\" : "/"}logs`,
      secretsBackend: platform === "windows" ? "Windows DPAPI" : platform === "macos" ? "macOS Keychain" : "Linux keyring",
      isDevBuild: true
    };
    this.store = scenario === "empty" ? emptyStore(loggingEnabled) : seedStore(today, loggingEnabled);
    if (scenario === "blocked") {
      this.store = { ...this.store, routingRules: this.store.routingRules.map((rule) => ({ ...rule, enabled: false })), routingProxyList: { ...this.store.routingProxyList, enabled: false } };
    }
    this.diagnostics = scenario === "empty" ? [] : seedDiagnostics(today);
    this.attention = scenario === "empty" ? [] : seedAttention(today);
    this.fileLog = seedLogFile(today);
    this.updateInfo = {
      available: true,
      currentVersion: PREVIEW_VERSION,
      latestVersion: "2.3.0",
      releaseUrl: "https://github.com/stansful/ssh-vpn-client-electron/releases/tag/v2.3.0",
      publishedAt: new Date(today.getTime() - 26 * HOUR).toISOString(),
      asset: {
        name: `shadow-ssh-2.3.0-${platform === "macos" ? "macos" : platform === "linux" ? "linux" : "windows"}-portable-x64.exe`,
        version: "2.3.0",
        arch: "x64",
        size: 92_000_000,
        downloadUrl: "https://github.com/stansful/ssh-vpn-client-electron/releases/download/v2.3.0/shadow-ssh-2.3.0-windows-portable-x64.exe"
      },
      checkedAt: new Date(today.getTime() + 12 * HOUR + 4 * 60_000).toISOString(),
      message: "Shadow SSH 2.3.0 is available."
    };
    const platformTarget = {
      platform,
      arch: this.environment.arch,
      serviceExecutableName: platform === "windows" ? "shadow-ssh-service.exe" : "shadow-ssh-service",
      serviceRelativePath: `native/${platform}/${this.environment.arch}/shadow-ssh-service`,
      supportsPrivilegedService: platform === "windows"
    };
    const idle: RuntimeStatus = {
      state: "Disconnected",
      message: "Disconnected.",
      reconnectAttempt: 0,
      transport: "live-ssh",
      platformTarget,
      realTunnelAvailable: true
    };
    this.sshRuntime = idle;
    this.xrayRuntime = { ...idle, transport: "xray" };
    this.applyScenario(today);
    this.ready = this.fingerprintSeededProfiles();
    this.api = this.createApi();
    this.exposeConsoleHelpers();
  }

  // ---------- scenario seeding ----------

  private applyScenario(today: Date): void {
    const frankfurt = this.store.sshConfigs[0];
    const profile = this.store.proxyProfiles.find((candidate) => candidate.id === this.store.selectedProxyProfileId);
    switch (this.scenario) {
      case "connected":
        if (frankfurt) {
          this.sshRuntime = this.connectedSsh(frankfurt, new Date(today.getTime() + 12 * HOUR + 3 * 60_000 + 53_000));
          this.lastTunnelCheck = {
            endpoint: this.store.settings.checkEndpoint,
            ok: true,
            at: new Date(today.getTime() + 12 * HOUR + 12 * 60_000 + 11_000).toISOString(),
            message: `${this.store.settings.checkEndpoint} answered the TLS handshake through the tunnel.`,
            latencyMs: 184,
            transport: "ssh",
            targetName: frankfurt.name
          };
          this.terminal = [];
        }
        break;
      case "xray":
        if (profile) {
          this.activeTransport = "xray";
          this.store = { ...this.store, settings: { ...this.store.settings, activeGlobalTab: "xray", lastConnectedTransport: "xray", xrayConsentAccepted: true } };
          this.xrayRuntime = this.connectedXray(profile, new Date());
        }
        break;
      case "reconnecting":
        if (frankfurt) {
          this.sshRuntime = {
            ...this.connectedSsh(frankfurt, new Date()),
            state: "Reconnecting",
            reconnectAttempt: 3,
            realTunnelAvailable: false,
            localProxy: undefined,
            message: "Reconnecting after SSH failure: network-changed: network interfaces changed (lost Wi-Fi 192.168.1.24; gained Ethernet 10.0.0.12)"
          };
        }
        break;
      case "error":
        if (frankfurt) {
          this.sshRuntime = {
            ...this.sshRuntime,
            state: "Error",
            activeConfigId: frankfurt.id,
            activeConfigName: frankfurt.name,
            activeTarget: `${frankfurt.host}:${frankfurt.port}`,
            message: `SSH authentication failed: ${frankfurt.host} rejected the password for ${frankfurt.username}.`
          };
        }
        break;
      case "auto-connect": {
        const selected = this.store.sshConfigs.find((config) => config.id === this.store.selectedConfigId);
        if (selected) {
          this.autoConnect = { at: new Date().toISOString(), transport: "ssh", targetName: selected.name };
          this.later(400, () => void this.connectSsh());
        }
        break;
      }
      case "startup-failed":
        this.startupFailure = STARTUP_FAILURE;
        this.sshRuntime = {
          ...this.sshRuntime,
          state: "Error",
          transport: "simulator",
          realTunnelAvailable: false,
          message: STARTUP_FAILURE
        };
        this.diagnostics = appendBoundedDiagnosticEntries(this.diagnostics, [diagnostic(new Date(), "error", STARTUP_FAILURE, "app")]);
        break;
      case "storage-unreadable":
        this.storageHealth = {
          state: "unreadable",
          message: "Unexpected token } in JSON at position 4182",
          storePath: `${this.environment.dataDirectory}${this.platform === "windows" ? "\\storage\\" : "/storage/"}app-store.v1.json`,
          dataDirectory: this.environment.dataDirectory
        };
        this.attention = [
          {
            id: "attention-storage",
            at: new Date().toISOString(),
            kind: "storage-unreadable",
            level: "error",
            source: "app",
            title: "Saved data couldn't be read",
            message: "Shadow SSH stopped before changing anything. Recover it on the startup screen."
          }
        ];
        break;
      default:
        break;
    }
  }

  private connectedSsh(config: SshConfig, connectedAt: Date): RuntimeStatus {
    return {
      ...this.sshRuntime,
      state: "Connected",
      activeConfigId: config.id,
      activeConfigName: config.name,
      activeTarget: `${config.host}:${config.port}`,
      connectedAt: connectedAt.toISOString(),
      reconnectAttempt: 0,
      transport: "live-ssh",
      realTunnelAvailable: true,
      message: `Connected to ${config.name}. HTTP/SOCKS proxy 127.0.0.1:50817, direct-tcpip, and shell channels are live.`,
      localProxy: { host: "127.0.0.1", httpPort: 50817 },
      observedHostKeyFingerprint: "SHA256:qB3tU1u9mBV7c0o4gk2Hn8oQfYxW5yPcD1zR3mE7aLs",
      tunActive: false
    };
  }

  private connectedXray(profile: ProxyProfile, connectedAt: Date): RuntimeStatus {
    return {
      ...this.xrayRuntime,
      state: "Connected",
      activeConfigId: profile.id,
      activeConfigName: profile.name,
      activeTarget: hostPort(profile.host, profile.port),
      connectedAt: connectedAt.toISOString(),
      reconnectAttempt: 0,
      transport: "xray",
      realTunnelAvailable: true,
      message: `Connected to ${profile.name}. Xray HTTP proxy 127.0.0.1:10809 and SOCKS proxy 127.0.0.1:10808 are live.`,
      localProxy: { host: "127.0.0.1", httpPort: 10809, socksPort: 10808 },
      tunActive: false
    };
  }

  private async fingerprintSeededProfiles(): Promise<void> {
    const proxyProfiles = await Promise.all(
      this.store.proxyProfiles.map(async (profile) => {
        const match = /^prof-public-(\d+)$/u.exec(profile.id);
        if (!match) {
          return profile;
        }
        const fingerprint = await linkFingerprint(parseShareLink(publicLink(Number(match[1])).rawUri));
        return fingerprint ? { ...profile, fingerprint } : profile;
      })
    );
    this.store = { ...this.store, proxyProfiles };
  }

  // ---------- state helpers ----------

  private get runtime(): RuntimeStatus {
    return this.activeTransport === "xray" ? this.xrayRuntime : this.sshRuntime;
  }

  private snapshot(): AppSnapshot {
    return structuredClone({
      store: this.store,
      runtime: this.runtime,
      activeTransport: this.activeTransport,
      diagnostics: this.diagnostics,
      attention: this.attention,
      terminal: this.terminal,
      logFilePaths: [this.logPath(0), this.logPath(1), this.logPath(2)],
      lastTunnelCheck: this.lastTunnelCheck,
      tunnelCheckRunning: this.checksRunning > 0,
      ...(this.startupFailure ? { startupFailure: this.startupFailure } : {}),
      ...(this.autoConnect ? { autoConnect: this.autoConnect } : {}),
      updateInfo: this.updateInfo,
      updateDownload: this.updateDownload,
      storageHealth: this.storageHealth,
      tunStatus: this.tunStatus(),
      environment: this.environment
    });
  }

  private logPath(index: number): string {
    const main = `${this.environment.logDirectory}${this.platform === "windows" ? "\\" : "/"}main.log`;
    return index === 0 ? main : `${main}.${index}`;
  }

  private logFileInfo(): LogFileInfo[] {
    const mainSize = new TextEncoder().encode(this.fileLog ? `${this.fileLog}\n` : "").length;
    return [0, 1, 2].map((index) => {
      if (index === 0) {
        return { path: this.logPath(0), size: mainSize, exists: true };
      }
      const exists = index <= this.logArchives;
      return { path: this.logPath(index), size: exists ? LOG_ARCHIVE_BYTES : 0, exists };
    });
  }

  private tunStatus(): TunStatus {
    const supported = this.platform === "windows";
    const enabled = this.store.settings.tunDataplaneEnabled;
    return {
      supported,
      enabled,
      elevated: false,
      wintunFound: supported,
      searchedPaths: supported ? ["C:\\Program Files\\Shadow SSH\\resources\\native\\windows\\x64", this.environment.dataDirectory] : [],
      active: false,
      appliesOnNextConnect: false,
      lastFailure: supported && enabled ? "Shadow SSH isn't running as administrator" : undefined
    };
  }

  private emit(event: RendererEvent): void {
    for (const listener of this.listeners) {
      listener(event);
    }
  }

  private later(ms: number, action: () => void): void {
    const timer = setTimeout(() => {
      this.timers.delete(timer);
      action();
    }, ms);
    this.timers.add(timer);
  }

  private log(level: DiagnosticsEntry["level"], message: string, source: DiagnosticsSource): void {
    const settings = this.store.settings;
    const at = new Date();
    if (settings.loggingEnabled && settings.fileLoggingEnabled) {
      this.fileLog += `\n[${at.toISOString()}] ${level === "warning" ? "WARNING" : level.toUpperCase()} ${message}`;
    }
    if (!settings.loggingEnabled || !settings.diagnosticsLoggingEnabled) {
      return;
    }
    const entry = diagnostic(at, level, message, source);
    this.diagnostics = appendBoundedDiagnosticEntries(this.diagnostics, [entry]);
    this.emit({ type: "diagnostics-appended", entry });
  }

  private setStatus(transport: GlobalTab, patch: Partial<RuntimeStatus>): void {
    if (transport === "xray") {
      this.xrayRuntime = { ...this.xrayRuntime, ...patch };
    } else {
      this.sshRuntime = { ...this.sshRuntime, ...patch };
    }
    if (transport === this.activeTransport) {
      this.emit({ type: "status-changed", status: this.runtime });
    }
  }

  private setActiveTransport(transport: GlobalTab): void {
    if (this.activeTransport === transport) {
      return;
    }
    this.activeTransport = transport;
    this.lastTunnelCheck = undefined;
    this.emit({ type: "active-transport-changed", transport, status: this.runtime });
  }

  private setAttention(next: AttentionEvent[]): void {
    this.attention = next.slice(0, 20);
    this.emit({ type: "attention-changed", attention: structuredClone(this.attention) });
  }

  private addAttention(event: Omit<AttentionEvent, "id" | "at">): void {
    const entry: AttentionEvent = { ...event, id: crypto.randomUUID(), at: new Date().toISOString() };
    this.setAttention([entry, ...this.attention.filter((candidate) => candidate.kind !== event.kind)]);
  }

  private appendTerminal(stream: TerminalLine["stream"], text: string): void {
    const line: TerminalLine = { id: crypto.randomUUID(), at: new Date().toISOString(), stream, text };
    this.terminal = appendBoundedTerminalLine(this.terminal, line);
    this.emit({ type: "terminal-output", line });
  }

  private routing(applyError?: string): RoutingMutationResult {
    return applyError ? { snapshot: this.snapshot(), applyError } : { snapshot: this.snapshot() };
  }

  // ---------- simulated connection flows ----------

  private async stopTransport(transport: GlobalTab): Promise<void> {
    const status = transport === "xray" ? this.xrayRuntime : this.sshRuntime;
    if (status.state === "Disconnected" || status.state === "Error") {
      return;
    }
    this.setStatus(transport, { state: "Disconnecting", message: "Disconnect requested." });
    await delay(700);
    this.setStatus(transport, {
      state: "Disconnected",
      message: "Disconnected.",
      connectedAt: undefined,
      localProxy: undefined,
      reconnectAttempt: 0,
      tunActive: false
    });
    this.shellOpen = false;
    this.lastTunnelCheck = undefined;
    this.log("info", `Disconnected from ${status.activeConfigName ?? "the server"}. Direct network settings restored.`, transport);
  }

  private async connectSsh(): Promise<AppSnapshot> {
    const config = this.store.sshConfigs.find((candidate) => candidate.id === this.store.selectedConfigId);
    if (!config) {
      this.log("error", "Select or create an SSH configuration before connecting.", "ssh");
      return this.snapshot();
    }
    if (!this.hasRoutingTargets()) {
      this.log("error", "Selected rules mode requires at least one enabled routing rule or enabled proxy-list domain.", "routing");
      return this.snapshot();
    }
    if (this.activeTransport === "xray") {
      await this.stopTransport("xray");
    }
    this.setActiveTransport("ssh");
    this.diagnostics = [];
    this.lastTunnelCheck = undefined;
    const target = `${config.host}:${config.port}`;
    this.setStatus("ssh", {
      state: "Connecting",
      activeConfigId: config.id,
      activeConfigName: config.name,
      activeTarget: target,
      reconnectAttempt: 0,
      transport: "live-ssh",
      realTunnelAvailable: false,
      message: `Connecting to ${target} over SSH.`
    });
    this.log("info", `Connect requested for ${config.username}@${target}, auth=${config.authType}, routing=${this.store.routingMode}.`, "ssh");
    await delay(1600);
    if (this.sshRuntime.state !== "Connecting") {
      return this.snapshot();
    }
    if (config.authType === "password" && !config.passwordSecretId) {
      this.setStatus("ssh", { state: "Error", message: `No password is saved for ${config.name}. Add it in SSH servers, then connect again.` });
      this.log("error", `SSH authentication failed: no saved password for ${config.username}@${target}.`, "ssh");
      return this.snapshot();
    }
    if (config.host.endsWith("example.net")) {
      this.setStatus("ssh", { state: "Error", message: `getaddrinfo ENOTFOUND ${config.host}` });
      this.log("error", `Connection to ${target} failed: getaddrinfo ENOTFOUND ${config.host}`, "ssh");
      return this.snapshot();
    }
    this.sshRuntime = this.connectedSsh(config, new Date());
    this.emit({ type: "status-changed", status: this.sshRuntime });
    this.log("info", `Connected to ${config.name}. Local proxy 127.0.0.1:50817.`, "ssh");
    if (this.platform === "windows" && this.store.settings.tunDataplaneEnabled) {
      this.log("warning", "TUN adapter skipped: the app is not running as administrator. Using the Windows system proxy instead.", "routing");
    }
    await this.rememberTransport("ssh");
    this.later(600, () => void this.runCheck(this.store.settings.checkEndpoint, false));
    return this.snapshot();
  }

  private async connectXray(): Promise<AppSnapshot> {
    const profile = this.store.proxyProfiles.find((candidate) => candidate.id === this.store.selectedProxyProfileId);
    if (!profile) {
      this.log("error", "Select or import an Xray profile before connecting.", "xray");
      return this.snapshot();
    }
    if (!this.hasRoutingTargets()) {
      this.log("error", "Selected rules mode requires at least one enabled routing rule or enabled proxy-list domain.", "routing");
      return this.snapshot();
    }
    if (this.activeTransport === "ssh") {
      await this.stopTransport("ssh");
    }
    this.setActiveTransport("xray");
    this.diagnostics = [];
    this.lastTunnelCheck = undefined;
    this.setStatus("xray", {
      state: "Connecting",
      activeConfigId: profile.id,
      activeConfigName: profile.name,
      activeTarget: hostPort(profile.host, profile.port),
      reconnectAttempt: 0,
      transport: "xray",
      realTunnelAvailable: false,
      message: `Starting ${proxyProtocolLabel(profile.protocol)} profile ${profile.name}.`
    });
    this.log("info", `Starting ${proxyProtocolLabel(profile.protocol)} profile ${profile.name}.`, "xray");
    await delay(1400);
    if (this.xrayRuntime.state !== "Connecting") {
      return this.snapshot();
    }
    if (profile.security === "unknown" || profile.transport === "unknown") {
      this.setStatus("xray", { state: "Error", message: "Xray runtime exited during startup with code 1." });
      this.log("error", "Xray: [Error] infra/conf: unknown security type", "xray");
      return this.snapshot();
    }
    this.xrayRuntime = this.connectedXray(profile, new Date());
    this.emit({ type: "status-changed", status: this.xrayRuntime });
    this.log("info", `Connected to ${profile.name}. Xray HTTP proxy 127.0.0.1:10809, SOCKS 127.0.0.1:10808.`, "xray");
    await this.rememberTransport("xray");
    this.later(600, () => void this.runCheck(this.store.settings.checkEndpoint, false));
    return this.snapshot();
  }

  private async rememberTransport(transport: GlobalTab): Promise<void> {
    this.store = { ...this.store, settings: { ...this.store.settings, lastConnectedTransport: transport } };
  }

  private async runCheck(endpoint: string, manual: boolean): Promise<TunnelCheckResult | undefined> {
    const runtime = this.runtime;
    if (runtime.state !== "Connected") {
      if (manual) {
        throw new Error("Connect first: the tunnel check needs a running tunnel.");
      }
      return undefined;
    }
    this.checksRunning += 1;
    if (this.checksRunning === 1) {
      this.emit({ type: "tunnel-check-changed", running: true });
    }
    try {
      await delay(manual ? 900 : 700);
    } finally {
      this.checksRunning -= 1;
      if (this.checksRunning === 0) {
        this.emit({ type: "tunnel-check-changed", running: false });
      }
    }
    if (this.runtime.state !== "Connected") {
      return undefined;
    }
    const latencyMs = 150 + Math.round(Math.random() * 80);
    const port = Number(endpoint.split(":").pop());
    const quietPort = port !== 443 && port !== 80 && port !== 8080 && port !== 8443;
    const result: TunnelCheckResult = {
      endpoint,
      ok: !endpoint.includes("blocked"),
      at: new Date().toISOString(),
      message: endpoint.includes("blocked")
        ? `${endpoint} didn't answer through the tunnel within 12 s.`
        : quietPort
          ? `${endpoint} stayed silent for 12 s. That's normal for ports that wait for the client, but the route isn't verified end to end.`
          : `${endpoint} answered the TLS handshake through the tunnel.`,
      latencyMs: endpoint.includes("blocked") ? undefined : latencyMs,
      note: quietPort && !endpoint.includes("blocked") ? true : undefined,
      transport: this.activeTransport,
      targetName: runtime.activeConfigName
    };
    this.lastTunnelCheck = result;
    this.emit({ type: "tunnel-check-result", result });
    this.log(result.ok ? "info" : "warning", result.ok ? `Tunnel check passed: ${endpoint} answered in ${latencyMs} ms.` : `Tunnel check failed: ${result.message}`, this.activeTransport);
    return result;
  }

  private simulateReconnect(reason: "network" | "wake" | "stuck" = "network"): void {
    const transport = this.activeTransport;
    const runtime = this.runtime;
    if (runtime.state !== "Connected") {
      return;
    }
    const target = runtime.activeTarget ?? "the server";
    const causes = {
      network: "network-changed: network interfaces changed (lost Wi-Fi 192.168.1.24; gained Ethernet 10.0.0.12)",
      wake: "system resume",
      stuck: `getaddrinfo ENOTFOUND ${target.split(":")[0]}`
    } as const;
    this.lastTunnelCheck = undefined;
    this.setStatus(transport, {
      state: "Reconnecting",
      reconnectAttempt: 1,
      realTunnelAvailable: false,
      localProxy: undefined,
      message: transport === "xray" ? `Restarting Xray transport after failure: ${causes[reason]}` : `Reconnecting after SSH failure: ${causes[reason]}`
    });
    this.log("warning", `Reconnect attempt 1 scheduled in 2 s: ${causes[reason]}`, transport);
    if (reason === "stuck") {
      let attempt = 1;
      const retry = (): void => {
        if (this.runtime.state !== "Reconnecting") {
          return;
        }
        attempt += 1;
        this.setStatus(transport, { reconnectAttempt: attempt, message: `Reconnect attempt ${attempt} failed: ${causes.stuck}` });
        this.later(4000, retry);
      };
      this.later(3000, retry);
      return;
    }
    this.later(3200, () => {
      if (this.runtime.state !== "Reconnecting") {
        return;
      }
      if (transport === "xray") {
        const profile = this.store.proxyProfiles.find((candidate) => candidate.id === this.xrayRuntime.activeConfigId);
        if (profile) {
          this.xrayRuntime = this.connectedXray(profile, new Date());
        }
      } else {
        const config = this.store.sshConfigs.find((candidate) => candidate.id === this.sshRuntime.activeConfigId);
        if (config) {
          this.sshRuntime = this.connectedSsh(config, new Date());
        }
      }
      this.emit({ type: "status-changed", status: this.runtime });
      this.log("info", `SSH session established for ${target} after 3.2 s without a tunnel.`, transport);
      this.later(400, () => void this.runCheck(this.store.settings.checkEndpoint, false));
    });
  }

  private hasRoutingTargets(): boolean {
    const store = this.store;
    if (store.routingMode !== "selected-rules") {
      return true;
    }
    return (
      store.routingRules.some((rule) => rule.enabled && validateRoutingRuleValue(rule.type, rule.value).ok) ||
      (store.routingProxyList.enabled && store.routingProxyList.domains.some((domain) => normalizeProxyDomain(domain) !== undefined))
    );
  }

  /** Mirrors the main process: a running split tunnel that loses its last target closes. */
  private async enforceRoutingTargets(): Promise<void> {
    if (this.hasRoutingTargets() || (this.runtime.state !== "Connected" && this.runtime.state !== "Reconnecting")) {
      return;
    }
    const name = this.runtime.activeConfigName ?? "The tunnel";
    this.log("error", "Selected-rules routing no longer has any enabled rules or list domains, so the tunnel was closed instead of routing everything direct.", "routing");
    await this.stopTransport(this.activeTransport);
    this.addAttention({
      kind: "split-tunnel-no-targets",
      level: "warning",
      source: "routing",
      title: "Blocked by routing",
      message: `Split tunnel has nothing left to route, so ${name} closed instead of sending everything direct. Turn on a rule or a domain list, then connect.`
    });
  }

  private exposeConsoleHelpers(): void {
    if (typeof window === "undefined") {
      return;
    }
    const helpers = {
      reconnect: (reason?: "network" | "wake" | "stuck") => this.simulateReconnect(reason),
      fail: (message = "SSH authentication failed: the server rejected the password for root.") => {
        const transport = this.activeTransport;
        this.setStatus(transport, { state: "Error", message, localProxy: undefined });
        this.log("error", message, transport);
        this.addAttention({ kind: "reconnect-stopped", level: "error", source: transport, title: "Reconnect stopped", message: "Only you can fix this one. Check the server, then connect again." });
      },
      attention: () =>
        this.addAttention({
          kind: "system-proxy-recovered",
          level: "info",
          source: "app",
          title: "Network settings repaired",
          message: "Shadow SSH didn't close cleanly last time, so Windows still pointed at its proxy. Direct settings are back."
        }),
      invalidate: () => this.emit({ type: "snapshot-invalidated", reason: "preview" })
    };
    (window as unknown as { shadowSshPreview?: typeof helpers }).shadowSshPreview = helpers;
  }

  // ---------- API ----------

  private createApi(): ShadowSshApi {
    return {
      loadSnapshot: async () => {
        await this.ready;
        if (this.scenario === "load-error") {
          await delay(600);
          throw new Error("Initial application state did not arrive within 10 seconds. Check main.log and retry.");
        }
        if (this.scenario === "slow") {
          await delay(1800);
        }
        return this.snapshot();
      },
      upsertConfig: async (input) => {
        this.assertWritable();
        this.upsertConfig(input);
        return this.snapshot();
      },
      deleteConfig: async (id) => {
        this.assertWritable();
        const remaining = this.store.sshConfigs.filter((config) => config.id !== id);
        this.store = {
          ...this.store,
          sshConfigs: remaining,
          selectedConfigId: this.store.selectedConfigId === id ? remaining[0]?.id : this.store.selectedConfigId
        };
        return this.snapshot();
      },
      selectConfig: async (id) => {
        this.assertWritable();
        this.store = { ...this.store, selectedConfigId: id };
        return this.snapshot();
      },
      upsertKey: async (input) => {
        this.assertWritable();
        this.upsertKey(input);
        return this.snapshot();
      },
      copyPrivateKey: async (id) => {
        if (!this.store.sshKeys.some((key) => key.id === id)) {
          throw new Error("SSH key does not exist.");
        }
        return true;
      },
      deleteKey: async (id) => {
        this.assertWritable();
        const users = this.store.sshConfigs.filter((config) => config.privateKeyId === id);
        if (users.length > 0) {
          throw new Error(`This private key is used by ${users.map((config) => config.name).join(" and ")}, so it can't be deleted.`);
        }
        this.store = { ...this.store, sshKeys: this.store.sshKeys.filter((key) => key.id !== id) };
        return this.snapshot();
      },
      upsertProxyProfile: async (input) => {
        this.assertWritable();
        await this.upsertProfile(input);
        return this.snapshot();
      },
      importProxyProfiles: async (input) => {
        this.assertWritable();
        await delay(500);
        const result = await this.importProfiles(input);
        return { snapshot: this.snapshot(), result };
      },
      refreshProxyProfiles: async () => {
        this.assertWritable();
        await delay(1200);
        const result = await this.importProfiles({ text: publicListText(), source: "remote", sourceUrl: PUBLIC_LIST_URL });
        return { snapshot: this.snapshot(), result };
      },
      selectProxyProfile: async (id) => {
        this.assertWritable();
        const profile = this.store.proxyProfiles.find((candidate) => candidate.id === id);
        if (!profile) {
          throw new Error("Xray profile does not exist.");
        }
        if (profile.security === "unknown" || profile.transport === "unknown") {
          throw new Error("This profile uses an unsupported security mode or transport, so it can't be selected.");
        }
        this.store = {
          ...this.store,
          selectedProxyProfileId: id,
          proxyProfiles: this.store.proxyProfiles.map((candidate) => ({ ...candidate, isSelected: candidate.id === id }))
        };
        return this.snapshot();
      },
      toggleProxyProfilePin: async (id) => {
        this.assertWritable();
        this.store = {
          ...this.store,
          proxyProfiles: this.store.proxyProfiles.map((profile) => (profile.id === id ? { ...profile, isPinned: !profile.isPinned } : profile))
        };
        return this.snapshot();
      },
      deleteProxyProfile: async (id) => {
        this.assertWritable();
        if (this.activeTransport === "xray" && this.xrayRuntime.activeConfigId === id) {
          await this.stopTransport("xray");
        }
        const remaining = this.store.proxyProfiles.filter((profile) => profile.id !== id);
        this.store = {
          ...this.store,
          proxyProfiles: remaining,
          selectedProxyProfileId: this.store.selectedProxyProfileId === id ? remaining[0]?.id : this.store.selectedProxyProfileId
        };
        return this.snapshot();
      },
      deleteUnpinnedProxyProfiles: async () => {
        this.assertWritable();
        if (this.activeTransport === "xray") {
          await this.stopTransport("xray");
        }
        const remaining = this.store.proxyProfiles.filter((profile) => profile.isPinned);
        this.store = {
          ...this.store,
          proxyProfiles: remaining,
          selectedProxyProfileId: remaining.some((profile) => profile.id === this.store.selectedProxyProfileId) ? this.store.selectedProxyProfileId : remaining[0]?.id
        };
        return this.snapshot();
      },
      updateSettings: async (patch: Partial<AppSettings>) => {
        this.assertWritable();
        this.store = {
          ...this.store,
          settings: {
            ...this.store.settings,
            ...patch,
            customTheme: patch.customTheme ? { ...this.store.settings.customTheme, ...patch.customTheme } : this.store.settings.customTheme
          }
        };
        return this.snapshot();
      },
      updateRoutingMode: async (mode: RoutingMode) => {
        this.assertWritable();
        this.store = { ...this.store, routingMode: mode };
        await this.enforceRoutingTargets();
        return this.routing(this.applyErrorForPreview());
      },
      updateRoutingRules: async (rules: RoutingRule[]) => {
        this.assertWritable();
        await delay(250);
        this.store = { ...this.store, routingRules: rules };
        await this.enforceRoutingTargets();
        return this.routing(this.applyErrorForPreview());
      },
      updateRoutingProxyListEnabled: async (enabled: boolean) => {
        this.assertWritable();
        this.store = { ...this.store, routingProxyList: { ...this.store.routingProxyList, enabled } };
        await this.enforceRoutingTargets();
        return this.routing();
      },
      refreshRoutingProxyList: async () => {
        this.assertWritable();
        await delay(1500);
        this.store = {
          ...this.store,
          routingProxyList: { ...this.store.routingProxyList, enabled: true, domains: generateDomains(1982, BLOCKED_SAMPLE), updatedAt: new Date().toISOString() }
        };
        this.log("info", "Blocked in Russia list refreshed: 1,982 domains.", "routing");
        return this.routing();
      },
      updateRoutingDirectListEnabled: async (enabled: boolean) => {
        this.assertWritable();
        this.store = { ...this.store, routingDirectList: { ...this.store.routingDirectList, enabled } };
        return this.routing();
      },
      refreshRoutingDirectList: async () => {
        this.assertWritable();
        await delay(1500);
        this.store = {
          ...this.store,
          routingDirectList: { ...this.store.routingDirectList, enabled: true, domains: generateDomains(312, RUSSIAN_SAMPLE, ".ru"), updatedAt: new Date().toISOString() }
        };
        this.log("info", "Russian services list refreshed: 312 domains.", "routing");
        return this.routing();
      },
      clearDiagnostics: async () => {
        this.diagnostics = [];
        // Like the main process: clearing Activity also clears what it was asked to keep.
        if (this.attention.length > 0) {
          this.setAttention([]);
        }
        return this.snapshot();
      },
      readLogFile: async () => {
        await delay(300);
        return this.fileLog ? `### ${this.logPath(0)}\n${this.fileLog}` : "";
      },
      getLogFileInfo: async () => this.logFileInfo(),
      clearLogFile: async () => {
        this.fileLog = "";
        this.logArchives = 0;
        return "";
      },
      listProcesses: async () => {
        await delay(700);
        return ["chrome.exe", "msedge.exe", "telegram.exe", "discord.exe", "code.exe", "spotify.exe", "steam.exe", "powershell.exe", "explorer.exe", "slack.exe"];
      },
      connect: () => this.connectSsh(),
      connectProxy: () => this.connectXray(),
      disconnect: async () => {
        await this.stopTransport(this.activeTransport);
        return this.snapshot();
      },
      checkTunnel: async (endpoint?: string) => {
        await this.runCheck(endpoint ?? this.store.settings.checkEndpoint, true);
        return this.snapshot();
      },
      openTerminal: async () => {
        if (this.activeTransport !== "ssh" || this.sshRuntime.state !== "Connected") {
          throw new Error("Terminal is available only while connected.");
        }
        await delay(300);
        this.shellOpen = true;
        this.appendTerminal("system", "SSH shell channel opened.\n");
        this.appendTerminal("stdout", "root@fra-01:~# ");
        return this.snapshot();
      },
      closeTerminal: async () => {
        if (this.shellOpen) {
          this.shellOpen = false;
          this.appendTerminal("system", "\nShell channel closed.\n");
        }
        return this.snapshot();
      },
      terminalInput: async (input: string) => {
        if (!this.shellOpen) {
          throw new Error("Terminal input ignored because SSH is not connected.");
        }
        const command = input.replace(/\r?\n$/u, "");
        this.appendTerminal("stdout", `${command}\n`);
        await delay(150);
        this.appendTerminal("stdout", `${fakeShellOutput(command)}root@fra-01:~# `);
      },
      checkForUpdates: async () => {
        await delay(900);
        const update = { ...this.updateInfo!, checkedAt: new Date().toISOString() };
        this.updateInfo = update;
        return { snapshot: this.snapshot(), update: structuredClone(update) };
      },
      downloadUpdate: async () => {
        const total = this.updateInfo?.asset?.size ?? 92_000_000;
        this.updateDownload = { state: "downloading", downloadedBytes: 0, totalBytes: total, percent: 0 };
        this.emit({ type: "update-download-changed", download: this.updateDownload });
        const step = (): void => {
          if (this.updateDownload.state !== "downloading") {
            return;
          }
          const downloadedBytes = Math.min(total, this.updateDownload.downloadedBytes + total / 12);
          const done = downloadedBytes >= total;
          this.updateDownload = done
            ? { state: "downloaded", downloadedBytes: total, totalBytes: total, percent: 100, filePath: `${this.environment.dataDirectory}\\updates\\${this.updateInfo?.asset?.name ?? "update.exe"}` }
            : { state: "downloading", downloadedBytes, totalBytes: total, percent: Math.round((downloadedBytes / total) * 100) };
          this.emit({ type: "update-download-changed", download: this.updateDownload });
          if (!done) {
            this.later(450, step);
          }
        };
        this.later(450, step);
        return this.snapshot();
      },
      revealDownloadedUpdate: async () => this.updateDownload.state === "downloaded",
      copyText: async (text: string) => {
        try {
          await navigator.clipboard.writeText(text);
          return true;
        } catch {
          return false;
        }
      },
      readClipboardText: async () => {
        try {
          return (await navigator.clipboard.readText()).slice(0, 2_097_152);
        } catch {
          return "";
        }
      },
      openExternal: async (url: string) => {
        window.open(url, "_blank", "noopener,noreferrer");
        return true;
      },
      dismissConnectionError: async () => {
        if (this.runtime.state === "Error") {
          this.setStatus(this.activeTransport, { state: "Disconnected", message: "Disconnected." });
        }
        return this.snapshot();
      },
      dismissAttention: async (id?: string) => {
        this.setAttention(id ? this.attention.filter((event) => event.id !== id) : []);
        return this.snapshot();
      },
      openLogFolder: async () => true,
      openDataFolder: async () => true,
      recoverStorage: async () => {
        await delay(900);
        this.storageHealth = { state: "ok" };
        this.store = emptyStore(true);
        this.diagnostics = [];
        this.attention = [];
        return this.snapshot();
      },
      quitApp: async () => {
        window.close();
      },
      onServiceEvent: (callback) => {
        this.listeners.add(callback);
        return () => {
          this.listeners.delete(callback);
        };
      }
    };
  }

  private assertWritable(): void {
    if (this.storageHealth.state === "unreadable") {
      throw new Error("Saved data couldn't be read, so changes are blocked. Recover it on the startup screen first.");
    }
  }

  /** `?applyError=1` makes routing saves report an apply failure, for the "Saved · not applied" state. */
  private applyErrorForPreview(): string | undefined {
    const params = new URLSearchParams(typeof window !== "undefined" ? window.location.search : "");
    return params.get("applyError") ? "Windows refused the system proxy change (access denied)." : undefined;
  }

  private upsertConfig(input: UpsertSshConfigInput): void {
    const now = new Date().toISOString();
    const existing = input.id ? this.store.sshConfigs.find((config) => config.id === input.id) : undefined;
    const config: SshConfig = {
      id: existing?.id ?? crypto.randomUUID(),
      name: input.name.trim(),
      host: input.host.trim(),
      port: Number(input.port),
      username: input.username.trim(),
      authType: input.authType,
      passwordSecretId:
        input.authType === "password" ? (input.password ? `preview-password-${crypto.randomUUID()}` : existing?.passwordSecretId) : undefined,
      privateKeyId: input.authType === "private-key" ? input.privateKeyId : undefined,
      expectedServerFingerprint: input.expectedServerFingerprint.trim(),
      keepaliveIntervalSec: Number(input.keepaliveIntervalSec),
      note: input.note.trim(),
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    };
    this.store = {
      ...this.store,
      sshConfigs: existing ? this.store.sshConfigs.map((candidate) => (candidate.id === config.id ? config : candidate)) : [...this.store.sshConfigs, config],
      selectedConfigId: this.store.selectedConfigId ?? config.id
    };
  }

  private upsertKey(input: UpsertSshKeyInput): void {
    const now = new Date().toISOString();
    const existing = input.id ? this.store.sshKeys.find((key) => key.id === input.id) : undefined;
    const text = input.privateKey ?? "";
    const keyType = /OPENSSH PRIVATE KEY/u.test(text) ? "ed25519" : /RSA PRIVATE KEY|PRIVATE KEY/u.test(text) ? "rsa" : existing?.keyType ?? "unknown";
    const key: SshKeyMetadata = {
      id: existing?.id ?? crypto.randomUUID(),
      name: input.name.trim(),
      privateKeySecretId: text ? `preview-key-${crypto.randomUUID()}` : existing?.privateKeySecretId ?? `preview-key-${crypto.randomUUID()}`,
      privateKeyPassphraseSecretId: input.privateKeyPassphrase ? `preview-passphrase-${crypto.randomUUID()}` : existing?.privateKeyPassphraseSecretId,
      fingerprint: text ? `sha256:${randomHex(64)}` : existing?.fingerprint ?? `sha256:${randomHex(64)}`,
      keyType,
      keyFormat: /OPENSSH/u.test(text) ? "openssh" : /BEGIN PRIVATE KEY|ENCRYPTED PRIVATE KEY/u.test(text) ? "pkcs8" : text ? "pem" : existing?.keyFormat,
      encryptedOpenSsh: /OPENSSH/u.test(text) ? Boolean(input.privateKeyPassphrase) : existing?.encryptedOpenSsh,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    };
    this.store = {
      ...this.store,
      sshKeys: existing ? this.store.sshKeys.map((candidate) => (candidate.id === key.id ? key : candidate)) : [...this.store.sshKeys, key]
    };
  }

  /** Parses like the main process (same messages) and matches saved profiles by fingerprint. */
  private async parseLink(rawUri: string): Promise<{ link: LinkPreview; fingerprint: string }> {
    const link = parseShareLink(rawUri);
    return { link, fingerprint: (await linkFingerprint(link)) ?? `sha256:${randomHex(64)}` };
  }

  private async upsertProfile(input: UpsertProxyProfileInput): Promise<void> {
    const rawUri = input.rawUri.trim();
    const { link, fingerprint } = await this.parseLink(rawUri);
    const existing =
      (input.id ? this.store.proxyProfiles.find((profile) => profile.id === input.id) : undefined) ??
      this.store.proxyProfiles.find((profile) => profile.fingerprint === fingerprint);
    const profile = makeProfile(
      { ...link, flow: "", rawUri, fingerprint, name: input.name.trim() || link.name },
      input.source ?? existing?.source ?? "manual",
      existing
    );
    this.store = {
      ...this.store,
      proxyProfiles: existing ? this.store.proxyProfiles.map((candidate) => (candidate.id === profile.id ? profile : candidate)) : [...this.store.proxyProfiles, profile],
      selectedProxyProfileId: this.store.selectedProxyProfileId ?? profile.id
    };
  }

  private async importProfiles(input: ImportProxyProfilesInput): Promise<ImportProxyProfilesResult> {
    const result: ImportProxyProfilesResult = { imported: 0, updated: 0, skipped: 0, failed: 0, errors: [] };
    const profiles = [...this.store.proxyProfiles];
    const byFingerprint = new Map(profiles.map((profile, index) => [profile.fingerprint, index]));
    const seen = new Set<string>();
    const lines = input.text.split(/\r?\n/u);
    for (const [index, rawLine] of lines.entries()) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) {
        result.skipped += 1;
        continue;
      }
      let parsed: { link: LinkPreview; fingerprint: string };
      try {
        parsed = await this.parseLink(line);
      } catch (error) {
        result.failed += 1;
        if (result.errors.length < 500) {
          result.errors.push(`Line ${index + 1}: ${error instanceof Error ? error.message : String(error)}`);
        }
        continue;
      }
      const { link, fingerprint } = parsed;
      seen.add(fingerprint);
      const existingIndex = byFingerprint.get(fingerprint);
      if (existingIndex !== undefined) {
        const existing = profiles[existingIndex];
        profiles[existingIndex] = makeProfile({ ...link, flow: "", rawUri: line, fingerprint, name: existing.name || link.name }, input.source, existing, {
          sourceUrl: input.sourceUrl
        });
        result.updated += 1;
        continue;
      }
      byFingerprint.set(fingerprint, profiles.length);
      profiles.push(makeProfile({ ...link, flow: "", rawUri: line, fingerprint }, input.source, undefined, { sourceUrl: input.sourceUrl }));
      result.imported += 1;
    }
    const now = new Date().toISOString();
    const next =
      input.source === "remote" && input.sourceUrl
        ? profiles.map((profile) =>
            profile.source === "remote" && profile.sourceUrl === input.sourceUrl && !seen.has(profile.fingerprint) ? { ...profile, isStale: true, updatedAt: now } : profile
          )
        : profiles;
    this.store = {
      ...this.store,
      proxyProfiles: next,
      selectedProxyProfileId: this.store.selectedProxyProfileId ?? next[0]?.id,
      ...(input.source === "remote" && input.sourceUrl ? { publicProxyRefresh: { at: now, listed: seen.size } } : {})
    };
    return result;
  }
}

// ---------- sample data ----------

const STARTUP_FAILURE = [
  "Startup failed: Error: listen EADDRINUSE: address already in use 127.0.0.1:50817",
  "    at Server.setupListenHandle [as _listen2] (node:net:1872:16)",
  "    at listenInCluster (node:net:1920:12)",
  "    at Server.listen (node:net:2009:7)",
  "    at createLocalProxy (main/proxy/local-proxy.js:214:18)",
  "    at startServices (main/services/index.js:88:11)",
  "    at async bootstrap (main/index.js:57:5)",
  "    at async Object.start (main/index.js:131:3)"
].join("\n");

const BLOCKED_SAMPLE = [
  "cdninstagram.com", "googlevideo.com", "ytimg.com", "4pda.to", "adguard.com", "amnezia.org", "anthropic.com", "bbc.com",
  "chatgpt.com", "claude.ai", "discord.com", "discord.gg", "discordapp.net", "facebook.com", "ggpht.com", "instagram.com",
  "linkedin.com", "medium.com", "netflix.com", "openai.com", "patreon.com", "proton.me", "rutracker.org", "signal.org",
  "soundcloud.com", "spotify.com", "telegram.org", "twitch.tv", "x.com", "youtube.com"
];
const RUSSIAN_SAMPLE = ["gosuslugi.ru", "mail.ru", "yandex.ru", "vk.com", "ozon.ru", "wildberries.ru", "sberbank.ru", "tinkoff.ru", "avito.ru", "kinopoisk.ru"];

function startOfToday(): Date {
  const date = new Date();
  date.setHours(0, 0, 0, 0);
  return date;
}

function at(day: Date, hours: number, minutes: number, seconds = 0): string {
  return new Date(day.getTime() + hours * HOUR + minutes * 60_000 + seconds * 1000).toISOString();
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function randomHex(length: number): string {
  return Array.from({ length }, () => Math.floor(Math.random() * 16).toString(16)).join("");
}

function hostPort(host: string, port: number): string {
  return host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;
}

function parsePlatform(value: string | null): DesktopPlatform {
  return value === "macos" || value === "linux" || value === "windows" ? value : "windows";
}

function dataDirectoryFor(platform: DesktopPlatform): string {
  if (platform === "macos") {
    return "/Users/alex/Library/Application Support/Shadow SSH";
  }
  if (platform === "linux") {
    return "/home/alex/.config/Shadow SSH";
  }
  return "C:\\Users\\alex\\AppData\\Roaming\\Shadow SSH";
}

function diagnostic(date: Date, level: DiagnosticsEntry["level"], message: string, source: DiagnosticsSource): DiagnosticsEntry {
  return { id: crypto.randomUUID(), at: date.toISOString(), level, message, source };
}

function generateDomains(count: number, seed: string[], suffix = ".com"): string[] {
  const domains = [...seed];
  for (let index = domains.length; index < count; index += 1) {
    domains.push(`site-${String(index).padStart(4, "0")}${suffix}`);
  }
  return domains.slice(0, count);
}

function emptyStore(loggingEnabled: boolean): AppStore {
  const store = createDefaultStore();
  return { ...store, settings: { ...DEFAULT_SETTINGS, loggingEnabled } };
}

function seedStore(today: Date, loggingEnabled: boolean): AppStore {
  const created = at(today, -24 * 30, 0);
  const keys: SshKeyMetadata[] = [
    { id: "key-work", name: "work-ed25519", privateKeySecretId: "secret-key-work", fingerprint: "sha256:4f1c9e0b7d2a51c8e3f6a0b94d17c2e85a6f3b10d9c4e27f81a5b3c6d0e9a92e", keyType: "ed25519", keyFormat: "openssh", encryptedOpenSsh: false, createdAt: created, updatedAt: created },
    { id: "key-home", name: "home-rsa", privateKeySecretId: "secret-key-home", privateKeyPassphraseSecretId: "secret-pass-home", fingerprint: "sha256:b7d2031c5e8f4a6b9d0c2e1f3a5b7c9d8e0f1a2b3c4d5e6f7a8b9c0d1e2f19f4", keyType: "rsa", keyFormat: "pem", encryptedOpenSsh: false, createdAt: created, updatedAt: created },
    { id: "key-old", name: "old-laptop", privateKeySecretId: "secret-key-old", fingerprint: "sha256:e05a7c3d9b1f2e4a6c8d0b2f4e6a8c0d2f4b6d8f0a2c4e6b8d0f2a4c6e8b6b1d", keyType: "rsa", keyFormat: "pem", encryptedOpenSsh: false, createdAt: created, updatedAt: created }
  ];
  const servers: SshConfig[] = [
    { id: "srv-fra", name: "Frankfurt-01", host: "203.0.113.10", port: 22, username: "root", authType: "password", passwordSecretId: "secret-pw-fra", expectedServerFingerprint: "SHA256:qB3tU1u9mBV7c0o4gk2Hn8oQfYxW5yPcD1zR3mE7aLs", keepaliveIntervalSec: 120, note: "VPS plan renews on the 14th. Panel: vps.example.net", createdAt: created, updatedAt: created },
    { id: "srv-ams", name: "Amsterdam-edge", host: "198.51.100.24", port: 2222, username: "deploy", authType: "private-key", privateKeyId: "key-work", expectedServerFingerprint: "", keepaliveIntervalSec: 120, note: "", createdAt: created, updatedAt: created },
    { id: "srv-hel", name: "Helsinki-backup", host: "helsinki.example.net", port: 22, username: "admin", authType: "private-key", privateKeyId: "key-home", expectedServerFingerprint: "SHA256:Zt8Kp2xQe5rW9mL3vB7nC1aY4uF6hD0sG2jE8kR5tPo", keepaliveIntervalSec: 300, note: "", createdAt: created, updatedAt: created },
    { id: "srv-lab", name: "Lab Raspberry", host: "192.0.2.55", port: 22, username: "pi", authType: "password", expectedServerFingerprint: "", keepaliveIntervalSec: 120, note: "", createdAt: created, updatedAt: created }
  ];

  const named: Array<[string, ProxyProtocol, string, number, ProxyTransport, ProxySecurity, ProxyProfile["source"], boolean, boolean]> = [
    ["de-fra-reality", "vless", "185.244.30.9", 443, "tcp", "reality", "manual", true, false],
    ["nl-ams-ws", "vmess", "ams.example.org", 443, "ws", "tls", "clipboard", false, false],
    ["trojan-tokyo", "trojan", "203.0.113.77", 443, "tcp", "tls", "clipboard", true, false],
    ["public-23", "vless", "45.12.33.1", 8443, "grpc", "tls", "remote", false, true],
    ["lab-unknown", "vless", "192.0.2.9", 443, "tcp", "unknown", "manual", false, false],
    ["Frankfurt am Main · Hetzner CX22 · reality over xhttp · backup node 02", "vless", "fra2.example.net", 443, "xhttp", "reality", "manual", false, false],
    ["warsaw-v6", "vless", "2001:db8::1", 443, "ws", "tls", "clipboard", false, false],
    ["public-58", "trojan", "198.51.100.140", 443, "tcp", "tls", "remote", false, false],
    ["public-07", "vmess", "203.0.113.201", 2053, "httpupgrade", "tls", "remote", true, true]
  ];
  const profiles: ProxyProfile[] = named.map(([name, protocol, host, port, transport, security, source, pinned, gone], index) =>
    makeProfile({ name, protocol, host, port, transport, security, flow: "", rawUri: `${protocol}://preview@${hostPort(host, port)}#${encodeURIComponent(name)}`, fingerprint: `sha256:${index.toString(16).padStart(64, "0")}` }, source, undefined, {
      id: `prof-${index + 1}`,
      isPinned: pinned,
      isStale: gone,
      isSelected: index === 0,
      sourceUrl: source === "remote" ? PUBLIC_LIST_URL : undefined
    })
  );
  for (let index = 1; profiles.length < 128; index += 1) {
    if (NAMED_PUBLIC_INDEXES.has(index)) {
      continue;
    }
    const { name, rawUri } = publicLink(index);
    const link = parseShareLink(rawUri);
    profiles.push(
      makeProfile({ ...link, flow: "", rawUri, fingerprint: `sha256:${(1000 + index).toString(16).padStart(64, "0")}` }, "remote", undefined, {
        id: `prof-public-${index}`,
        name,
        isPinned: index % 13 === 0 && profiles.filter((profile) => profile.isPinned).length < 12,
        isStale: index % 23 === 0,
        isSelected: false,
        sourceUrl: PUBLIC_LIST_URL
      })
    );
  }

  const rule = (id: string, type: RoutingRule["type"], value: string, enabled = true): RoutingRule => ({ id, type, value, enabled, createdAt: created, updatedAt: created });
  return {
    ...createDefaultStore(),
    sshConfigs: servers,
    sshKeys: keys,
    proxyProfiles: profiles,
    selectedConfigId: "srv-fra",
    selectedProxyProfileId: "prof-1",
    settings: { ...DEFAULT_SETTINGS, loggingEnabled, activeGlobalTab: "ssh", lastConnectedTransport: "ssh" },
    routingMode: "selected-rules",
    routingRules: [
      rule("r1", "domain", "youtube.com"),
      rule("r2", "domain", "*.googlevideo.com"),
      rule("r3", "domain", "instagram.com"),
      rule("r4", "domain", "x.com"),
      rule("r5", "domain", "discord.com"),
      rule("r6", "domain", "*.discord.gg", false),
      rule("r7", "domain", "chatgpt.com"),
      rule("r8", "domain", "linkedin.com"),
      rule("r9", "domain", "medium.com"),
      rule("r10", "ip", "8.8.8.8"),
      rule("r11", "ip", "1.1.1.1/32"),
      rule("r12", "ip", "2a00:1450::/32"),
      rule("r13", "process.name", "telegram.exe"),
      rule("r14", "process.name", "discord.exe")
    ],
    routingProxyList: {
      enabled: true,
      sourceUrl: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst",
      domains: generateDomains(1982, BLOCKED_SAMPLE),
      updatedAt: at(today, 11, 40)
    },
    routingDirectList: {
      enabled: false,
      sourceUrl: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/outside-raw.lst",
      domains: generateDomains(312, RUSSIAN_SAMPLE, ".ru"),
      updatedAt: at(today, -24 * 3 + 9, 15)
    }
  };
}

function makeProfile(
  parsed: {
    name: string;
    protocol: ProxyProtocol;
    host: string;
    port: number;
    hopPorts?: string;
    insecureWithoutPin?: boolean;
    transport: ProxyTransport;
    security: ProxySecurity;
    flow: string;
    rawUri: string;
    fingerprint: string;
  },
  source: ProxyProfile["source"],
  existing?: ProxyProfile,
  overrides: Partial<ProxyProfile> = {}
): ProxyProfile {
  const now = new Date().toISOString();
  return {
    id: existing?.id ?? crypto.randomUUID(),
    name: parsed.name,
    protocol: parsed.protocol,
    host: parsed.host,
    port: parsed.port,
    ...(parsed.hopPorts ? { hopPorts: parsed.hopPorts } : {}),
    ...(parsed.insecureWithoutPin ? { insecureWithoutPin: true } : {}),
    transport: parsed.transport,
    security: parsed.security,
    flow: parsed.flow,
    source,
    rawUriSecretId: existing?.rawUriSecretId ?? `preview-proxy-${crypto.randomUUID()}`,
    fingerprint: parsed.fingerprint,
    isSelected: existing?.isSelected ?? false,
    isPinned: existing?.isPinned ?? false,
    isStale: false,
    lastTestStatus: "unknown",
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
    lastSeenAt: now,
    ...overrides
  };
}

/** Seeded profiles named like public list entries ("public-07"); the generated list skips these numbers. */
const NAMED_PUBLIC_INDEXES = new Set([7, 23, 58]);
/** The stand-in public list currently holds entries 1–124, minus the named ones and every 23rd (gone). */
const PUBLIC_LIST_SIZE = 124;

/**
 * Entry `index` of the stand-in public list (the same link on every refresh).
 * Every tenth one, from public-04, is Hysteria 2; every other of those hops
 * ports and uses the hy2:// spelling. public-14 asks for insecure=1 without a
 * pinSHA256, so its card shows the insecure=1 tag.
 */
function publicLink(index: number): { name: string; rawUri: string } {
  const name = `public-${String(index).padStart(2, "0")}`;
  const host = `198.51.${100 + (index % 40)}.${(index * 7) % 250}`;
  const port = index % 6 === 0 ? 8443 : 443;
  const id = `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
  if (index % 10 === 4) {
    const hops = index % 20 === 4;
    const insecure = index === 14 ? "&insecure=1" : "";
    return {
      name,
      rawUri: `${hops ? "hy2" : "hysteria2"}://${id}@${host}:${hops ? `${port},20000-30000` : port}?sni=preview.example.net&obfs=salamander&obfs-password=preview${insecure}#${name}`
    };
  }
  const transport = (["tcp", "ws", "grpc", "xhttp"] as const)[index % 4];
  const protocol = (["vless", "vmess", "trojan"] as const)[index % 3];
  if (protocol === "vmess") {
    return { name, rawUri: `vmess://${btoa(JSON.stringify({ v: "2", ps: name, add: host, port, id, net: transport, tls: "tls" }))}` };
  }
  const security = protocol === "vless" && index % 5 === 0 ? "reality" : "tls";
  const query = protocol === "vless" ? `security=${security}&type=${transport}&sni=${host}` : `security=tls&sni=${host}`;
  return { name, rawUri: `${protocol}://${id}@${host}:${port}?${query}#${name}` };
}

function publicListText(): string {
  const lines: string[] = [];
  for (let index = 1; index <= PUBLIC_LIST_SIZE; index += 1) {
    if (!NAMED_PUBLIC_INDEXES.has(index) && index % 23 !== 0) {
      lines.push(publicLink(index).rawUri);
    }
  }
  return lines.join("\n");
}

function seedDiagnostics(today: Date): DiagnosticsEntry[] {
  const rows: Array<[number, number, number, DiagnosticsEntry["level"], DiagnosticsSource, string]> = [
    [12, 3, 51, "info", "ssh", "Connecting to 203.0.113.10:22 over SSH."],
    [12, 3, 52, "warning", "routing", "TUN adapter skipped: the app is not running as administrator. Using the Windows system proxy instead."],
    [12, 3, 53, "info", "ssh", "Connected to Frankfurt-01. Local proxy 127.0.0.1:50817."],
    [12, 3, 55, "info", "ssh", "Tunnel check passed: youtube.com:443 answered in 197 ms."],
    [12, 5, 49, "info", "ssh", "HTTP tunnel opened for www.youtube.com:443."],
    [12, 5, 56, "info", "ssh", "Local proxy activity: active=12, down=18.4 MB, up=1.3 MB since last check."],
    [12, 6, 1, "info", "ssh", "SOCKS5 tunnel opened for rr3---sn-4g5e6nzl.googlevideo.com:443."],
    [12, 6, 2, "info", "ssh", "Further proxy connection diagnostics are suppressed for this session."],
    [12, 6, 40, "info", "update", "Update 2.3.0 is available for Windows x64."],
    [12, 7, 2, "info", "routing", "Routing changed while connected: Split tunnel, 14 targets (8 domains, 3 IPs, 2 apps, 1 list). Applied without reconnecting SSH."],
    [12, 7, 18, "warning", "ssh", "SOCKS5 tunnel failed for x.com:443: Timed out waiting for SSH channel 41."],
    [12, 8, 30, "info", "app", "Window hidden to tray. The tunnel stays connected."],
    [12, 12, 2, "warning", "ssh", "Reconnect attempt 1 scheduled in 8 s: SSH keepalive timed out."],
    [12, 12, 3, "info", "ssh", "Wake (resume from sleep): reconnecting now instead of waiting out the backoff."],
    [12, 12, 3, "error", "ssh", "Reconnect attempt could not be started: connect ENETUNREACH 203.0.113.10:22"],
    [12, 12, 9, "info", "ssh", "Connected to Frankfurt-01. Local proxy 127.0.0.1:50817."],
    [12, 12, 11, "info", "ssh", "Tunnel check passed: youtube.com:443 answered in 184 ms."],
    [12, 14, 21, "info", "ssh", "Local proxy activity: active=9, down=41.8 MB, up=2.6 MB since last check."]
  ];
  return rows.map(([hours, minutes, seconds, level, source, message], index) => ({ id: `diag-${index}`, at: at(today, hours, minutes, seconds), level, message, source }));
}

function seedAttention(today: Date): AttentionEvent[] {
  return [
    {
      id: "attention-tun",
      at: at(today, 12, 3, 52),
      kind: "tun-unavailable",
      level: "warning",
      source: "routing",
      title: "TUN adapter not used: not running as administrator",
      message: "Apps that ignore the Windows proxy setting, like telegram.exe and discord.exe on your list, can connect directly instead of through the tunnel."
    },
    {
      id: "attention-split",
      at: at(today, 12, 1, 44),
      kind: "split-tunnel-no-targets",
      level: "error",
      source: "routing",
      title: "Split tunnel lost its last target, so the tunnel was closed to avoid routing everything direct",
      message: "A routing change left nothing to send through the tunnel. You have reconnected since, so this reason is kept here until you dismiss it."
    }
  ];
}

function seedLogFile(today: Date): string {
  const rows: Array<[number, number, number, string, string]> = [
    [8, 40, 12.418, "INFO", "Shadow SSH 2.2.0 started on Windows x64."],
    [8, 41, 3.902, "INFO", "Connecting to helsinki.example.net:22 over SSH."],
    [8, 41, 4.311, "WARNING", "DNS lookup for helsinki.example.net failed (getaddrinfo EAI_AGAIN helsinki.example.net); retrying with the last known address 198.51.100.61."],
    [8, 41, 5.027, "INFO", "Connected to Helsinki-backup. Local proxy 127.0.0.1:50817."],
    [8, 49, 58.66, "INFO", "Disconnected from Helsinki-backup. Direct network settings restored."],
    [8, 52, 6.118, "INFO", "Starting VLESS profile de-fra-reality."],
    [8, 52, 6.402, "WARNING", "Xray: [Warning] core: Xray 25.9.11 started"],
    [8, 57, 40.093, "ERROR", "Xray: [Error] proxy/vless/outbound: failed to find an available destination > common/retry: all retry attempts failed > dial tcp 185.244.30.9:443: i/o timeout"],
    [9, 1, 44.519, "INFO", "Disconnected from de-fra-reality. Direct network settings restored."],
    [9, 3, 51.104, "INFO", "Connecting to 203.0.113.10:22 over SSH."],
    [9, 3, 52.88, "WARNING", "TUN routing is unavailable, continuing on the Windows proxy path: The native helper cannot create a tunnel adapter. It needs wintun.dll beside the service binary and an elevated process."],
    [9, 3, 53.415, "INFO", "Connected to Frankfurt-01. Local proxy 127.0.0.1:50817."],
    [9, 3, 55.602, "INFO", "Tunnel check succeeded for youtube.com:443 in 197 ms: youtube.com:443 answered the TLS handshake."],
    [9, 12, 2.771, "WARNING", "Reconnect attempt 1 scheduled in 8 s: SSH keepalive timed out."],
    [9, 12, 3.14, "ERROR", "Reconnect attempt could not be started: connect ENETUNREACH 203.0.113.10:22"],
    [9, 12, 9.552, "INFO", "Connected to Frankfurt-01. Local proxy 127.0.0.1:50817."],
    [9, 14, 21.007, "INFO", "Local proxy activity: active=9, down=41.8 MB, up=2.6 MB since last check."]
  ];
  const utcDay = Date.UTC(today.getFullYear(), today.getMonth(), today.getDate());
  return rows
    .map(([hours, minutes, seconds, level, message]) => `[${new Date(utcDay + hours * HOUR + minutes * 60_000 + seconds * 1000).toISOString()}] ${level} ${message}`)
    .join("\n");
}

function fakeShellOutput(command: string): string {
  if (command === "uptime") {
    return " 12:04:31 up 41 days,  3:12,  1 user,  load average: 0.08, 0.05, 0.01\n";
  }
  if (command.startsWith("df")) {
    return "Filesystem      Size  Used Avail Use% Mounted on\n/dev/vda1        40G   11G   27G  29% /\n";
  }
  if (command === "") {
    return "";
  }
  return `${command.split(/\s+/u)[0]}: preview shell — nothing was sent to a server\n`;
}
