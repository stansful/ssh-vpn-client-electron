import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import net from "node:net";
import path from "node:path";
import os from "node:os";
import { RoutingMatcher, type RoutingMatcherSummary } from "../core/routing/routing-matcher.js";
import { Socks5Proxy } from "../core/network/socks5-proxy.js";
import { ProxyActivityHeartbeat, PROXY_HEARTBEAT_INTERVAL_MS } from "../core/network/proxy-activity-heartbeat.js";
import { WindowsSystemProxyManager, type SystemProxyApplyResult } from "../core/network/windows-system-proxy.js";
import {
  isAutoLearnableRemoteAddress,
  listWindowsProcessConnections,
  normalizeWindowsProcessName,
  type WindowsProcessConnection
} from "../core/network/windows-process-connections.js";
import { listWindowsDnsCacheEntries, type WindowsDnsCacheEntry } from "../core/network/windows-dns-cache.js";
import {
  isDomainCoveredByDirectDomainSuffixes,
  isDomainCoveredByRoutePatterns,
  MAX_PROCESS_ROUTE_SESSION_LEASES,
  normalizeProcessRouteDirectDomains,
  processRouteDomainHints,
  type ProcessRouteSessionEvidence
} from "../core/routing/process-route-domains.js";
import type { DirectTcpIpChannel, DirectTcpIpTarget } from "../core/network/local-tcp-proxy.js";
import { parseEndpoint } from "../core/network/socks5-check.js";
import { passedTunnelCheck, probeTunnelEndpoint } from "../core/network/tunnel-probe.js";
import { LocalRoutingEnforcer, RoutingDecisionLog, type LocalRoutingContext } from "./local-routing-enforcement.js";
import { preferredLocalProxyPort, rememberLocalProxyPort } from "./local-proxy-port.js";
import { NativeProcessAttribution, type ProcessAttribution } from "./process-attribution.js";
import { NativeDataplaneController, type DataplaneController } from "./native-dataplane.js";
import { errorText, resolveProtectedAddresses, startDataplaneWithRetry, TUN_ADAPTER_NAME, TUN_ROUTING_JOURNAL_FILE } from "./tun-routing.js";
import { LIVENESS_PROBE_TIMEOUT_MS, SshAuthenticationError, SshLiveClient, type SshLiveClientEvent } from "../core/ssh/live-client.js";
import { SystemWakeDetector, type SystemWakeDetectorOptions, type SystemWakeEvent } from "./system-wake-detector.js";
import type { ServiceEvent } from "../shared/ipc.js";
import type {
  ConnectRequest,
  DiagnosticsEntry,
  LocalProxyEndpoint,
  RoutingRule,
  RoutingUpdateRequest,
  RuntimeStatus,
  SshConfig,
  TerminalLine,
  TunnelCheckResult
} from "../shared/types.js";
import { normalizeRuleValue, validateRoutingRuleValue } from "../shared/validation.js";
import type { ServiceBridge } from "./service-bridge.js";

export interface LiveSshServiceBridgeOptions {
  pacDirectory?: string;
  systemProxy?: WindowsSystemProxyManager;
  processRoutingRefreshIntervalMs?: () => number;
  processConnectionsProvider?: (processNames: Iterable<string>) => Promise<WindowsProcessConnection[]>;
  processDnsEntriesProvider?: (addresses: Iterable<string>) => Promise<WindowsDnsCacheEntry[]>;
  /** Path to the native helper used for per-connection process attribution. */
  nativeServiceExecutablePath?: string;
  /**
   * The application's data folder. It is where the TUN routing journal lives,
   * and one of the places the helper is told to look for `wintun.dll` - a
   * portable build's own resources folder is recreated in `%TEMP%` at every
   * launch, so nothing a user puts there survives.
   */
  userDataDirectory?: string;
  /** Injection seam for tests; defaults to the native helper when a path is set. */
  processAttribution?: ProcessAttribution;
  /** Injection seam for tests; defaults to the native helper when a path is set. */
  dataplane?: DataplaneController;
  /** Injection seam for tests; defaults to a DNS lookup of the config host. */
  protectedAddressResolver?: (host: string) => Promise<string[]>;
  /**
   * Watches for clock jumps and interface changes while a connection is
   * wanted and turns them into {@link LiveSshServiceBridge.wake} calls.
   * Defaults to on; tests pass `false`, or detector options with fake clocks.
   */
  systemWakeDetection?: boolean | SystemWakeDetectorOptions;
}

/**
 * Upper bound for the reconnect backoff. See `scheduleReconnect`: while the
 * tunnel is down every proxied application fails, so the retry cadence stays
 * responsive instead of growing into minutes.
 */
const MAXIMUM_RECONNECT_DELAY_MS = 30_000;
/**
 * Floor between two connection attempts, whatever asked for the second one. A
 * resume, a network change and the watchdog can all arrive within the same
 * second, and the server must never see a burst of half-finished sessions.
 */
const MINIMUM_RECONNECT_SPACING_MS = 1_000;
/**
 * The credentials worked the last time, so one rejection during an automatic
 * reconnect is more likely a server that is still coming up than a changed
 * password. Two in a row is the limit: it stays well under any lockout policy
 * (fail2ban's default is five), and a real credential problem needs the user.
 */
const MAXIMUM_AUTOMATIC_AUTH_FAILURES = 2;
/**
 * How often the supervisor checks its invariant: while a connection is wanted
 * there is a live client, an attempt in progress, or a timer that will start
 * one. Every wait in the connect path has its own deadline, so ten seconds is
 * for the case none of them fired - a bug, not a slow network.
 */
const SUPERVISOR_WATCHDOG_INTERVAL_MS = 10_000;
/**
 * An attempt that has been running this long has outlived every timeout it
 * is built from. The watchdog cannot safely abandon it (the routing state it
 * owns would leak) but it must at least be visible in the log.
 */
const SUPERVISOR_STUCK_ATTEMPT_MS = 5 * 60 * 1000;
/**
 * Wakes closer together than this do not restart the backoff again. One wake
 * per resume or network change is the design; an interface whose address
 * flaps every few seconds would otherwise turn the 1-30 s ladder into an
 * attempt every tick.
 */
const WAKE_BACKOFF_RESET_INTERVAL_MS = 30_000;
/**
 * How long a connection accepted by the local listener waits for the tunnel
 * to come back before it is answered with a failure. The listener stays up
 * across a reconnect so that applications never see "connection refused";
 * within this window they only see a pause - a WebSocket reconnect, a poll or
 * a page load completes as soon as the new session is up. Browsers give a
 * proxy CONNECT well over half a minute, so the window is generous enough for
 * one failed attempt and its retry.
 */
const TUNNEL_RECOVERY_PARK_TIMEOUT_MS = 25_000;
/**
 * How long system routing (Windows proxy setting, PAC, TUN capture) is left
 * in place after the transport fails. A reconnect normally lands well inside
 * it, and then nothing about the machine's network changed from the
 * applications' point of view. Past it the machine is returned to direct
 * routing, exactly as before, so a long outage does not leave it offline.
 */
const ROUTING_HOLD_TIMEOUT_MS = 30_000;
/**
 * Backoff between automatic attempts. The first retry is immediate: a
 * transport that just died was healthy a moment ago, and the common causes -
 * a NAT mapping that expired, a server restart, a network blip - are best
 * answered by trying again at once. Only repeated failures slow down.
 */
const RECONNECT_BACKOFF_STEPS_MS = [0, 1_000, 2_000, 4_000, 8_000, 16_000, MAXIMUM_RECONNECT_DELAY_MS] as const;
const PROCESS_ROUTE_TTL_MS = 5 * 60 * 1000;
const PROCESS_ROUTE_REFRESH_INTERVAL_MS = 10 * 1000;
const PROCESS_ROUTE_DISCOVERY_DELAYS_MS = [1_000, 2_000, 4_000, 8_000] as const;
const PROCESS_ROUTE_DNS_REFRESH_MS = 5 * 60 * 1000;
const PROCESS_ROUTE_DNS_MIN_REFRESH_MS = 1_000;
const PROCESS_ROUTE_DNS_RETRY_BASE_MS = 10_000;

export class LiveSshServiceBridge implements ServiceBridge {
  private readonly events = new EventEmitter();
  private status: RuntimeStatus;
  private client: SshLiveClient | undefined;
  private shellOpen = false;
  private disconnectRequested = false;
  private reconnectTimer: NodeJS.Timeout | undefined;
  /**
   * Set when reconnecting cannot help - the host key does not match, or the
   * credentials were rejected - and cleared by the next user Connect. Nothing
   * automatic (a resume, a network change, the watchdog) restarts a halted
   * session; it needs the user, and the status says so.
   */
  private reconnectHalted = false;
  /** Drives the backoff; unlike `reconnectAttempt` it resets when the world changes. */
  private reconnectBackoffStep = 0;
  private lastConnectAttemptAt = 0;
  private lastWakeResetAt = 0;
  /** A wake that arrived while an attempt was running; consumed by the next schedule. */
  private pendingWakeReason: string | undefined;
  private consecutiveAuthFailures = 0;
  /** Whether the current request has ever produced a session; gates the auth retry. */
  private sessionEstablished = false;
  /** The address the last successful session used, keyed by the config host it stood for. */
  private lastServerAddress: { host: string; address: string } | undefined;
  private mutationsInFlight = 0;
  private mutationInFlightSince = 0;
  private supervisorWatchdog: NodeJS.Timeout | undefined;
  private supervisorStallReported = false;
  private readonly wakeDetector: SystemWakeDetector | undefined;
  private lastRequest: ConnectRequest | undefined;
  private routingRules: RoutingRule[] = [];
  private socksProxy: Socks5Proxy | undefined;
  private socksProxyHeartbeat: NodeJS.Timeout | undefined;
  private socksEndpoint: { host: string; port: number } | undefined;
  /**
   * Proxy connections accepted while no session is up. They wait for the
   * reconnect, then open their channel in the new session as if nothing
   * happened; see {@link waitForTunnel}.
   */
  private readonly tunnelWaiters = new Set<TunnelWaiter>();
  /** True while system routing is applied and points at `socksEndpoint`. */
  private systemRoutingApplied = false;
  private routingHoldTimer: NodeJS.Timeout | undefined;
  private routingHoldGeneration = 0;
  /** Rules or mode changed while the session was down; held TUN routing must be rebuilt. */
  private routingChangedWhileDown = false;
  private tunnelInterruptedAt: number | undefined;
  private readonly systemProxy: WindowsSystemProxyManager;
  private readonly processRoutingRefreshIntervalMs: () => number;
  private readonly processConnectionsProvider: (processNames: Iterable<string>) => Promise<WindowsProcessConnection[]>;
  private readonly processDnsEntriesProvider: (addresses: Iterable<string>) => Promise<WindowsDnsCacheEntry[]>;
  private proxyInfoDiagnostics = 0;
  private proxyWarningDiagnostics = 0;
  /**
   * Both directions of every routing decision, so the log can tell "no rule
   * matched" apart from "the rules matched and the tunnel behind them is
   * dead". See {@link RoutingDecisionLog}.
   */
  private readonly routingDecisions = new RoutingDecisionLog((message) => this.appendDiagnostic("info", message));
  private processRoutingMonitor: NodeJS.Timeout | undefined;
  private processRoutingGeneration = 0;
  private processRoutingIps = new Map<string, number>();
  private processRoutingHintDomains = new Set<string>();
  private processRoutingDomains = new Map<string, number>();
  private processRoutingDnsLookupAt = new Map<string, number>();
  private processRoutingDnsLookupFailures = new Map<string, number>();
  private processRoutingProfileCoveredAddresses = new Map<string, number>();
  private processRoutingSessionLeases = new Map<string, ProcessRouteSessionEvidence>();
  private processRoutingLastSignature = "";
  private processRoutingAppliedSignature = "";
  private processRoutingTargetSignature = "";
  private processRoutingApplyPending = false;
  private processRoutingLastMatchedConnections = 0;
  private processRoutingWarningEmitted = false;
  private processRoutingDnsWarningEmitted = false;
  private processRoutingDiscoveryStep = 0;
  private readonly processAttribution: ProcessAttribution | undefined;
  private readonly dataplane: DataplaneController | undefined;
  private readonly dataplaneJournalPath: string;
  private readonly protectedAddressResolver: (host: string) => Promise<string[]>;
  private tunRoutingActive = false;
  private readonly localRoutingEnforcer: LocalRoutingEnforcer;
  private localProcessEnforcement = false;
  private localRoutingContext: LocalRoutingContext | undefined;
  private mutationTail: Promise<void> = Promise.resolve();
  private terminalMutationTail: Promise<void> = Promise.resolve();
  private lifecycleGeneration = 0;
  private routingGeneration = 0;
  private disposed = false;

  constructor(initialStatus: RuntimeStatus, options: LiveSshServiceBridgeOptions = {}) {
    this.systemProxy = options.systemProxy ?? new WindowsSystemProxyManager({ pacDirectory: options.pacDirectory });
    this.processRoutingRefreshIntervalMs = options.processRoutingRefreshIntervalMs ?? (() => PROCESS_ROUTE_REFRESH_INTERVAL_MS);
    this.processConnectionsProvider = options.processConnectionsProvider ?? listWindowsProcessConnections;
    this.processDnsEntriesProvider = options.processDnsEntriesProvider ??
      (options.processConnectionsProvider ? async () => [] : listWindowsDnsCacheEntries);
    this.processAttribution = options.processAttribution ?? (options.nativeServiceExecutablePath
      ? new NativeProcessAttribution({
          executablePath: options.nativeServiceExecutablePath,
          onDiagnostic: (level, message) => this.appendDiagnostic(level, message)
        })
      : undefined);
    this.dataplane = options.dataplane ?? (options.nativeServiceExecutablePath
      ? new NativeDataplaneController({
          executablePath: options.nativeServiceExecutablePath,
          // The PAC directory lives inside the application's data folder, which
          // is a place the user can actually put wintun.dll - unlike the
          // packaged resources of a portable build.
          userDataDirectory: options.userDataDirectory,
          onDiagnostic: (level, message) => this.appendDiagnostic(level === "error" ? "error" : level, message),
          onActiveChange: () => this.syncDerivedStatus()
        })
      : undefined);
    this.dataplaneJournalPath = path.join(options.userDataDirectory ?? options.pacDirectory ?? os.tmpdir(), TUN_ROUTING_JOURNAL_FILE);
    this.protectedAddressResolver = options.protectedAddressResolver ?? resolveProtectedAddresses;
    this.localRoutingEnforcer = new LocalRoutingEnforcer(this.processAttribution);
    const wakeDetection = options.systemWakeDetection ?? true;
    this.wakeDetector = wakeDetection === false
      ? undefined
      : new SystemWakeDetector((event) => this.handleSystemWake(event), {
          ignoredInterfaceNames: [TUN_ADAPTER_NAME],
          ...(wakeDetection === true ? {} : wakeDetection)
        });
    this.status = {
      ...initialStatus,
      state: "Disconnected",
      transport: "live-ssh",
      realTunnelAvailable: false,
      message: "Live SSH service is ready.",
      ...this.derivedStatus()
    };
  }

  onEvent(listener: (event: ServiceEvent) => void): () => void {
    this.events.on("event", listener);
    return () => this.events.off("event", listener);
  }

  getStatus(): RuntimeStatus {
    return structuredClone(this.status);
  }

  async updateConfig(config: SshConfig): Promise<void> {
    void config;
    // The selected config is resolved at connect time with fresh secrets.
  }

  updateRoutingRules(rules: RoutingRule[]): Promise<void> {
    if (this.disposed) {
      return Promise.resolve();
    }
    this.routingRules = rules;
    if (this.lastRequest) {
      this.lastRequest = { ...this.lastRequest, routingRules: rules };
    }
    const routingGeneration = ++this.routingGeneration;
    const lifecycleGeneration = this.lifecycleGeneration;
    return this.enqueueMutation(async () => {
      if (!this.isCurrentMutation(lifecycleGeneration, routingGeneration)) {
        return;
      }
      const summary = new RoutingMatcher("selected-rules", rules).summary();
      const request = this.lastRequest;
      const socksEndpoint = this.socksEndpoint;
      if (this.status.state === "Connected" && request && socksEndpoint) {
        this.appendDiagnostic(
          "info",
          `Routing rules changed while connected: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}. Re-applying routing.`
        );
        await this.applySystemRouting(request, socksEndpoint);
        return;
      }
      this.noteRoutingChangedWhileDown();
      this.appendDiagnostic(
        "info",
        `Routing rules prepared for live SSH service: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`
      );
    });
  }

  updateRouting(update: RoutingUpdateRequest): Promise<void> {
    if (this.disposed) {
      return Promise.resolve();
    }
    this.routingRules = update.routingRules;
    if (this.lastRequest) {
      this.lastRequest = {
        ...this.lastRequest,
        routingMode: update.routingMode,
        routingRules: update.routingRules,
        routingProxyDomains: update.routingProxyDomains,
        routingDirectDomains: update.routingDirectDomains,
        checkEndpoint: update.checkEndpoint
      };
    }
    const routingGeneration = ++this.routingGeneration;
    const lifecycleGeneration = this.lifecycleGeneration;
    return this.enqueueMutation(async () => {
      if (!this.isCurrentMutation(lifecycleGeneration, routingGeneration)) {
        return;
      }
      const summary = new RoutingMatcher(update.routingMode, update.routingRules).summary();
      const request = this.lastRequest;
      const socksEndpoint = this.socksEndpoint;
      if (this.status.state === "Connected" && request && socksEndpoint) {
        const unsupportedRouting = describeUnsupportedSelectedRouting(request);
        if (unsupportedRouting) {
          this.setStatus({
            state: "Error",
            activeConfigId: request.config.id,
            realTunnelAvailable: false,
            message: unsupportedRouting
          });
          this.appendDiagnostic("error", unsupportedRouting);
          return;
        }
        this.appendDiagnostic(
          "info",
          `Routing mode changed while connected: mode=${update.routingMode}, enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}. Re-applying routing without SSH reconnect.`
        );
        await this.applySystemRouting(request, socksEndpoint);
        return;
      }
      this.noteRoutingChangedWhileDown();
      this.appendDiagnostic(
        "info",
        `Routing prepared for live SSH service: mode=${update.routingMode}, enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`
      );
    });
  }

  private noteRoutingChangedWhileDown(): void {
    if (this.systemRoutingApplied && this.lastRequest && !this.disconnectRequested) {
      this.routingChangedWhileDown = true;
    }
  }

  connect(request: ConnectRequest): Promise<void> {
    if (this.disposed) {
      return Promise.reject(new Error("Live SSH service has been disposed."));
    }
    // A user Connect is a fresh mandate: whatever stopped the previous
    // session, including a credential problem, is theirs to have fixed.
    this.reconnectHalted = false;
    this.reconnectBackoffStep = 0;
    this.consecutiveAuthFailures = 0;
    this.sessionEstablished = false;
    this.pendingWakeReason = undefined;
    if (this.lastServerAddress && this.lastServerAddress.host !== request.config.host) {
      this.lastServerAddress = undefined;
    }
    return this.startConnect(request, "user");
  }

  /**
   * Wakes the connection supervisor because something outside the session
   * changed: the machine resumed from sleep, its network changed, or the
   * process was frozen for a while. Silence from the socket proves nothing
   * after any of those, so a live session is probed immediately and a waiting
   * reconnect runs now instead of at the end of its backoff.
   *
   * Safe to call at any time; it does nothing unless a connection is wanted.
   */
  wake(reason: string): void {
    if (this.disposed || this.disconnectRequested || !this.lastRequest || this.reconnectHalted) {
      return;
    }
    if (this.reconnectTimer) {
      if (!this.mayResetBackoffOnWake()) {
        this.appendDiagnostic("info", `Wake (${reason}): a wake already restarted the backoff recently; keeping the scheduled attempt.`);
        return;
      }
      this.appendDiagnostic("info", `Wake (${reason}): reconnecting now instead of waiting out the backoff.`);
      this.clearReconnectTimer();
      this.reconnectBackoffStep = 0;
      this.scheduleReconnect(reason, this.lifecycleGeneration, { immediate: true });
      return;
    }
    const client = this.client;
    if (client && this.status.state === "Connected") {
      this.appendDiagnostic("info", `Wake (${reason}): probing the SSH session.`);
      // A failed probe surfaces through the client's error event, which is
      // the same path a regular keepalive timeout takes.
      void client.probeLiveness(LIVENESS_PROBE_TIMEOUT_MS).catch(() => undefined);
      return;
    }
    if (this.mutationsInFlight > 0) {
      // An attempt (or the teardown before one) is running. It may well be
      // failing against the network as it was before this wake; remember the
      // wake so the schedule that follows a failure runs at once instead of
      // applying a backoff sized for a world that has since changed.
      this.pendingWakeReason = reason;
      return;
    }
    if (!client) {
      // Nothing is connected, nothing is trying, and no timer is armed: the
      // supervisor has stalled. This is the watchdog's case, brought forward.
      this.appendDiagnostic("warning", `Wake (${reason}): no connection attempt was pending; starting one.`);
      this.scheduleReconnect(reason, this.lifecycleGeneration, { immediate: true });
    }
  }

  private mayResetBackoffOnWake(): boolean {
    const now = Date.now();
    if (this.lastWakeResetAt !== 0 && now - this.lastWakeResetAt >= 0 && now - this.lastWakeResetAt < WAKE_BACKOFF_RESET_INTERVAL_MS) {
      return false;
    }
    this.lastWakeResetAt = now;
    return true;
  }

  private startConnect(request: ConnectRequest, trigger: ConnectTrigger): Promise<void> {
    this.clearReconnectTimer();
    this.lastRequest = request;
    this.disconnectRequested = false;
    this.routingRules = request.routingRules;
    this.routingGeneration += 1;
    const generation = ++this.lifecycleGeneration;
    this.setStatus({
      state: trigger === "user" ? "Connecting" : "Reconnecting",
      activeConfigId: request.config.id,
      activeConfigName: request.config.name,
      activeTarget: formatServiceTarget(request.config.host, request.config.port),
      // A user Connect may reach a different server; the key this session
      // verifies is reported once it is up.
      ...(trigger === "user" ? { observedHostKeyFingerprint: undefined } : {}),
      message: trigger === "user"
        ? `Connecting to ${request.config.host}:${request.config.port} over live SSH.`
        : `Reconnecting to ${request.config.host}:${request.config.port} (attempt ${this.status.reconnectAttempt}).`,
      connectedAt: undefined,
      realTunnelAvailable: false
    });
    this.startSupervisor();
    return this.enqueueMutation(() => this.connectInternal(request, generation, trigger));
  }

  private async connectInternal(request: ConnectRequest, generation: number, trigger: ConnectTrigger): Promise<void> {
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    this.lastConnectAttemptAt = Date.now();
    this.proxyInfoDiagnostics = 0;
    this.proxyWarningDiagnostics = 0;
    this.routingDecisions.reset();
    this.shellOpen = false;

    let acquiredClient: SshLiveClient | undefined;
    // Routing and the listener survive an automatic reconnect: applications
    // keep their proxy endpoint and the machine keeps its routes while the
    // session is rebuilt underneath them. A user Connect starts from scratch,
    // because the configuration may have changed.
    const holdRouting = trigger !== "user" && this.systemRoutingApplied && this.socksProxy !== undefined;
    // Held TUN capture keeps the rules it was started with; a change made
    // while the session was down means the adapter has to be rebuilt.
    const holdTunRouting = holdRouting && this.tunRoutingActive && !this.routingChangedWhileDown;
    try {
      // Everything below sits inside one try: a failure while tearing the
      // previous session down is still a failed attempt, and a failed attempt
      // always ends in either a scheduled retry or an explicit halt. Nothing
      // may leave the status at Connecting/Reconnecting with no one working.
      if (!holdRouting) {
        await this.stopSystemRouting();
        this.processRoutingWarningEmitted = false;
        if (!this.isCurrentLifecycle(generation)) {
          return;
        }
      }
      const existingClient = this.client;
      this.client = undefined;
      if (existingClient) {
        await this.disconnectClient(existingClient, "Replacing SSH session.");
        if (!this.isCurrentLifecycle(generation)) {
          return;
        }
      }

      this.appendDiagnostic(
        "info",
        `${trigger === "user" ? "Connect requested" : `Reconnect attempt ${this.status.reconnectAttempt} (${trigger})`} for ${request.config.username}@${request.config.host}:${request.config.port}, auth=${request.config.authType}, routing=${request.routingMode}, privateKey=${Boolean(request.secrets?.privateKey)}, passphraseProvided=${Boolean(request.secrets?.privateKeyPassphrase)}${holdRouting ? ", routing held" : ""}.`
      );

      const unsupportedRouting = describeUnsupportedSelectedRouting(request);
      if (unsupportedRouting) {
        this.setStatus({
          state: "Error",
          activeConfigId: request.config.id,
          realTunnelAvailable: false,
          message: unsupportedRouting
        });
        this.appendDiagnostic("error", unsupportedRouting);
        this.haltReconnect("Reconnect stopped. Update the routing configuration, then connect again.");
        return;
      }

      // While the TUN adapter captures the machine's traffic, the only way
      // out is the server address it was told to leave alone; a fresh lookup
      // could answer with another address and route the transport into its
      // own tunnel. Reuse the protected address, and if that fails fall back
      // to the ordinary path with the adapter down (see the catch below).
      const protectedAddress = holdTunRouting && this.lastServerAddress?.host === request.config.host
        ? this.lastServerAddress.address
        : undefined;
      const client = await this.connectClient(request, protectedAddress);
      acquiredClient = client;
      if (!this.isCurrentLifecycle(generation)) {
        await this.disconnectClient(client, "SSH connection was superseded.");
        return;
      }
      this.client = client;
      this.consecutiveAuthFailures = 0;
      if (client.serverAddress) {
        this.lastServerAddress = { host: request.config.host, address: client.serverAddress };
      }
      client.onEvent((event) => this.handleClientEvent(client, generation, event));
      const socksEndpoint = await this.ensureLocalListener();
      if (!this.isCurrentLifecycle(generation) || this.client !== client) {
        await this.disconnectClient(client, "SSH connection was superseded.");
        return;
      }
      const effectiveRequest = this.lastRequest ?? request;
      if (holdTunRouting) {
        this.appendDiagnostic("info", `TUN routing was kept across the reconnect; the session reused the protected address ${client.serverAddress ?? protectedAddress ?? "?"}.`);
      } else {
        if (holdRouting && this.tunRoutingActive) {
          // Rules changed while the adapter was up: rebuild it from scratch
          // rather than restart it underneath the live session.
          await this.stopSystemRouting();
        }
        // Applying is a side effect on the machine; whoever supersedes this
        // attempt must find the flag set so the routing is taken down again.
        this.systemRoutingApplied = true;
        await this.applySystemRouting(effectiveRequest, socksEndpoint, true);
        if (!this.isCurrentLifecycle(generation) || this.client !== client) {
          await this.disconnectClient(client, "SSH connection was superseded.");
          return;
        }
      }
      this.systemRoutingApplied = true;
      this.routingChangedWhileDown = false;
      this.clearRoutingHold();
      this.reconnectBackoffStep = 0;
      this.sessionEstablished = true;
      this.pendingWakeReason = undefined;
      const interruptedForMs = this.tunnelInterruptedAt !== undefined ? Date.now() - this.tunnelInterruptedAt : undefined;
      this.tunnelInterruptedAt = undefined;
      this.setStatus({
        state: "Connected",
        activeConfigId: effectiveRequest.config.id,
        activeConfigName: effectiveRequest.config.name,
        activeTarget: formatServiceTarget(effectiveRequest.config.host, effectiveRequest.config.port),
        observedHostKeyFingerprint: client.hostKeyFingerprint,
        connectedAt: new Date().toISOString(),
        reconnectAttempt: 0,
        realTunnelAvailable: true,
        message: `Connected to ${effectiveRequest.config.name}. HTTP/SOCKS proxy ${socksEndpoint.host}:${socksEndpoint.port}, direct-tcpip, and shell channels are live.`
      });
      const parked = this.releaseTunnelWaiters(client);
      this.appendDiagnostic(
        "info",
        `SSH session established for ${effectiveRequest.config.username}@${effectiveRequest.config.host}:${effectiveRequest.config.port}${client.serverAddress ? ` (${client.serverAddress})` : ""}${interruptedForMs !== undefined ? ` after ${(interruptedForMs / 1000).toFixed(1)} s without a tunnel` : ""}${parked > 0 ? `; ${parked} waiting proxy connection${parked === 1 ? "" : "s"} resumed` : ""}.`
      );
    } catch (error) {
      try {
        if (acquiredClient) {
          if (this.client === acquiredClient) {
            this.client = undefined;
          }
          await this.disconnectClient(acquiredClient, "SSH connection setup failed.");
        }
        if (holdTunRouting && this.isCurrentLifecycle(generation)) {
          // The protected-address shortcut did not work; take the adapter
          // down so the next attempt can resolve and reach the server the
          // ordinary way, and the machine is not left captured meanwhile.
          this.appendDiagnostic("warning", "Reconnect through the protected address failed; releasing TUN routing until the session is back.");
          await this.stopSystemRouting();
        }
      } catch (cleanupError) {
        this.appendDiagnostic("warning", `Cleanup after a failed SSH connection attempt failed: ${errorMessage(cleanupError)}`);
      }
      if (!this.isCurrentLifecycle(generation)) {
        return;
      }
      const message = errorMessage(error);
      this.setStatus({
        state: trigger === "user" ? "Error" : "Reconnecting",
        activeConfigId: request.config.id,
        realTunnelAvailable: false,
        message: trigger === "user" ? message : `Reconnect attempt ${this.status.reconnectAttempt} failed: ${message}`
      });
      this.appendDiagnostic("error", message);
      if (error instanceof SshAuthenticationError && error.diagnostics.length > 0) {
        this.appendDiagnostic("info", `SSH private key parse diagnostics: ${error.diagnostics.join("; ")}`);
      }
      this.handleConnectFailure(error, generation, trigger);
    }
  }

  /**
   * Opens the SSH session, falling back to the address the last session used
   * when the name will not resolve. Right after a resume the resolver often
   * answers EAI_AGAIN for a few seconds although the network is back, and a
   * cached address gets the tunnel up in that window instead of burning a
   * backoff step on it. The pinned fingerprint still decides whether the host
   * at that address is the right one.
   */
  private async connectClient(request: ConnectRequest, protectedAddress?: string): Promise<SshLiveClient> {
    const options = {
      host: protectedAddress ?? request.config.host,
      port: request.config.port,
      username: request.config.username,
      expectedServerFingerprint: request.config.expectedServerFingerprint,
      password: request.config.authType === "password" ? requiredSecret(request.secrets?.password, "SSH password") : undefined,
      privateKey: request.config.authType === "private-key" ? requiredSecret(request.secrets?.privateKey, "SSH private key") : undefined,
      privateKeyPassphrase: request.secrets?.privateKeyPassphrase,
      keepaliveIntervalSec: request.config.keepaliveIntervalSec,
      connectTimeoutMs: 10000,
      operationTimeoutMs: 60000,
      directTcpIpOpenTimeoutMs: 12000
    };
    try {
      return await SshLiveClient.connect(options);
    } catch (error) {
      const fallback = this.lastServerAddress;
      if (
        protectedAddress === undefined &&
        fallback &&
        fallback.host === request.config.host &&
        fallback.address !== request.config.host &&
        net.isIP(request.config.host) === 0 &&
        // Without a pinned fingerprint nothing would tell a reassigned address
        // from the real server, and the credentials would go to whoever owns
        // it now; the resolver stays the only authority in that case.
        Boolean(request.config.expectedServerFingerprint?.trim()) &&
        isDnsFailure(error)
      ) {
        this.appendDiagnostic(
          "warning",
          `DNS lookup for ${request.config.host} failed (${errorMessage(error)}); retrying with the last known address ${fallback.address}.`
        );
        try {
          return await SshLiveClient.connect({ ...options, host: fallback.address });
        } catch (fallbackError) {
          if (isNonRetryableConnectError(fallbackError) && !isAuthenticationFailure(fallbackError)) {
            // A different host answered at the cached address. That says the
            // address is stale, not that the configuration is wrong: forget
            // it and report the resolver failure, which is retryable.
            this.lastServerAddress = undefined;
            this.appendDiagnostic("warning", `The cached address ${fallback.address} no longer belongs to ${request.config.host}: ${errorMessage(fallbackError)}`);
            throw error;
          }
          throw fallbackError;
        }
      }
      throw error;
    }
  }

  private handleConnectFailure(error: unknown, generation: number, trigger: ConnectTrigger): void {
    if (!this.isCurrentLifecycle(generation) || this.disconnectRequested) {
      return;
    }
    const message = errorMessage(error);
    if (isAuthenticationFailure(error)) {
      this.consecutiveAuthFailures += 1;
      if (trigger !== "user" && this.sessionEstablished && this.consecutiveAuthFailures < MAXIMUM_AUTOMATIC_AUTH_FAILURES) {
        this.appendDiagnostic(
          "warning",
          `SSH authentication was rejected during automatic reconnect (${this.consecutiveAuthFailures}/${MAXIMUM_AUTOMATIC_AUTH_FAILURES}); the credentials worked before, so trying once more.`
        );
        this.scheduleReconnect(message, generation);
        return;
      }
      this.haltReconnect("Reconnect stopped. Update the SSH configuration or key, then connect again.");
      return;
    }
    if (isNonRetryableConnectError(error)) {
      this.haltReconnect("Reconnect stopped. Update the SSH configuration or key, then connect again.");
      return;
    }
    this.scheduleReconnect(message, generation);
  }

  /**
   * Stops automatic reconnects until the next user Connect. The status keeps
   * the Error the user must act on; the supervisor and wake detector stand
   * down so nothing restarts a session that cannot succeed.
   */
  private haltReconnect(notice: string): void {
    this.reconnectHalted = true;
    this.pendingWakeReason = undefined;
    this.clearReconnectTimer();
    this.stopSupervisor();
    this.appendDiagnostic("warning", notice);
    if (this.status.state !== "Error") {
      // Keep the failure text the status already carries; only the state flips.
      this.setStatus({ state: "Error", realTunnelAvailable: false });
    }
    // No session is coming until the user acts: routing goes back to direct
    // and the listener stops, so applications get a refusal instead of a wait.
    void this.enqueueMutation(() => this.stopRouting()).catch(() => undefined);
  }

  disconnect(): Promise<void> {
    if (this.disposed) {
      return this.mutationTail;
    }
    this.disconnectRequested = true;
    this.clearReconnectTimer();
    this.stopSupervisor();
    const generation = ++this.lifecycleGeneration;
    this.setStatus({
      state: "Disconnecting",
      realTunnelAvailable: false,
      message: "Disconnecting SSH session."
    });
    return this.enqueueMutation(() => this.disconnectInternal(generation, "User disconnected."));
  }

  private async disconnectInternal(generation: number, reason: string): Promise<void> {
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    const client = this.client;
    this.client = undefined;
    this.shellOpen = false;
    this.tunnelInterruptedAt = undefined;
    await this.stopRouting();
    if (client) {
      await this.disconnectClient(client, reason);
    }
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    this.setStatus({
      state: "Disconnected",
      ...CLEARED_SESSION_STATUS,
      message: "Disconnected."
    });
    this.appendDiagnostic("info", "SSH session disconnected.");
  }

  /**
   * Dismisses an error the user has read: Error becomes Disconnected and
   * nothing is retried until the next Connect. A halted session already
   * released its routing; the stop below only finishes a teardown that was
   * still racing the halt when the user dismissed it.
   */
  clearError(): Promise<void> {
    if (this.disposed || this.status.state !== "Error") {
      return Promise.resolve();
    }
    this.disconnectRequested = true;
    this.clearReconnectTimer();
    this.stopSupervisor();
    this.lifecycleGeneration += 1;
    this.setStatus({
      state: "Disconnected",
      ...CLEARED_SESSION_STATUS,
      message: "Disconnected."
    });
    if (this.systemRoutingApplied || this.socksProxy) {
      void this.enqueueMutation(() => this.stopRouting()).catch(() => undefined);
    }
    return Promise.resolve();
  }

  async checkTunnel(endpoint: string): Promise<TunnelCheckResult> {
    const at = new Date().toISOString();
    const client = this.client;
    if (!client || this.status.state !== "Connected") {
      const result = { endpoint, ok: false, at, message: "SSH session is not connected." };
      this.appendDiagnostic("warning", `Tunnel check skipped for ${endpoint}: SSH session is not connected.`);
      this.emit({ type: "tunnel-check-result", result });
      return result;
    }

    try {
      this.appendDiagnostic("info", `Tunnel check requested for ${endpoint}.`);
      const startedAt = Date.now();
      const target = parseEndpoint(endpoint);
      // Opening the channel only proves the server could connect; the probe
      // also proves bytes cross it, which is the same evidence the Xray check
      // collects. The two transports must not disagree about what a passing
      // tunnel check means.
      const probe = await probeTunnelEndpoint(
        (signal) => client.openDirectTcpIpChannel(target, { address: "127.0.0.1", port: 0 }, signal),
        target,
        // The server confirms a direct-tcpip channel only after its own TCP connect.
        { openReachesTarget: true }
      );
      const result = passedTunnelCheck(endpoint, at, Date.now() - startedAt, probe);
      this.appendDiagnostic(probe.outcome === "unverified" ? "warning" : "info", result.message);
      this.emit({ type: "tunnel-check-result", result });
      return result;
    } catch (error) {
      const result = {
        endpoint,
        ok: false,
        at,
        message: error instanceof Error ? error.message : String(error)
      };
      this.appendDiagnostic("warning", `Tunnel check failed for ${endpoint}: ${result.message}`);
      this.emit({ type: "tunnel-check-result", result });
      return result;
    }
  }

  openTerminal(): Promise<void> {
    return this.enqueueTerminalMutation(async () => {
      const client = this.client;
      if (!client || this.status.state !== "Connected") {
        this.emitError("SSH terminal requires an active connection.");
        return;
      }
      if (this.shellOpen) {
        return;
      }
      await client.openShell();
      if (this.client !== client || this.status.state !== "Connected") {
        await client.closeShell().catch(() => undefined);
        return;
      }
      this.shellOpen = true;
      this.appendTerminal("system", "SSH shell channel opened.\n");
    });
  }

  closeTerminal(): Promise<void> {
    return this.enqueueTerminalMutation(async () => {
      const client = this.client;
      if (!client || !this.shellOpen) {
        return;
      }
      await client.closeShell();
      if (this.client === client) {
        this.shellOpen = false;
        this.appendTerminal("system", "\nSSH shell channel closed.\n");
      }
    });
  }

  terminalInput(input: string): Promise<void> {
    return this.enqueueTerminalMutation(async () => {
      const client = this.client;
      if (!client || !this.shellOpen) {
        this.emitError("SSH shell channel is not open.");
        return;
      }
      await client.writeShell(input);
    });
  }

  dispose(): Promise<void> {
    if (this.disposed) {
      return this.mutationTail;
    }
    this.disposed = true;
    this.disconnectRequested = true;
    this.clearReconnectTimer();
    this.stopSupervisor();
    const generation = ++this.lifecycleGeneration;
    this.setStatus({
      state: "Disconnecting",
      realTunnelAvailable: false,
      message: "Stopping SSH service."
    });
    return this.enqueueMutation(async () => {
      await this.disconnectInternal(generation, "Application is quitting.");
      // The dataplane goes last but must still go: an adapter left up on quit
      // would keep capture routes pointing at a process that no longer exists.
      await this.dataplane?.dispose().catch(() => undefined);
      await this.processAttribution?.dispose().catch(() => undefined);
    });
  }

  private handleClientEvent(client: SshLiveClient, generation: number, event: SshLiveClientEvent): void {
    if (client !== this.client || !this.isCurrentLifecycle(generation)) {
      return;
    }
    if (event.type === "terminal-data") {
      if (event.data.length === 0) {
        return;
      }
      this.appendTerminal(event.stream, event.data.toString("utf8"));
      return;
    }
    if (event.type === "terminal-close") {
      this.shellOpen = false;
      this.appendTerminal("system", "\nSSH shell channel closed by the server.\n");
      return;
    }
    if (event.type === "error") {
      this.handleClientFailure(client, generation, event.error);
      return;
    }
    if (event.type === "close" && !this.disconnectRequested) {
      this.handleClientFailure(client, generation, new Error("SSH transport closed."));
    }
  }

  private handleClientFailure(client: SshLiveClient, generation: number, error: Error): void {
    if (client !== this.client || !this.isCurrentLifecycle(generation)) {
      return;
    }
    const failureGeneration = ++this.lifecycleGeneration;
    this.client = undefined;
    this.shellOpen = false;
    this.clearReconnectTimer();
    const retryable = !isNonRetryableConnectError(error) && !this.disconnectRequested;
    if (retryable) {
      // Straight to Reconnecting: the session is being rebuilt, routing and
      // the listener stay, and the renderer shows "Restoring" rather than an
      // error that resolves itself a second later.
      this.suspendTunnel();
      this.setStatus({
        state: "Reconnecting",
        realTunnelAvailable: false,
        message: `SSH session lost (${error.message}); reconnecting.`
      });
    } else {
      this.setStatus({
        state: "Error",
        realTunnelAvailable: false,
        message: error.message
      });
    }
    this.appendDiagnostic("error", error.message);
    void this.enqueueMutation(async () => {
      try {
        await this.disconnectClient(client, "SSH transport failed.");
      } catch (cleanupError) {
        // The session is gone either way; a failed teardown must not also
        // cost the reconnect that follows it.
        this.appendDiagnostic("warning", `Cleanup after the SSH transport failure failed: ${errorMessage(cleanupError)}`);
      }
      if (!this.isCurrentLifecycle(failureGeneration) || this.disconnectRequested) {
        return;
      }
      if (!retryable) {
        this.haltReconnect("Reconnect stopped because SSH host trust or credentials require user action.");
        return;
      }
      this.scheduleReconnect(error.message, failureGeneration);
    });
  }

  /**
   * The transport is gone but the session is wanted: keep the listener and
   * the system routing for now, and start the clock after which the machine
   * is returned to direct routing if no session has come back.
   */
  private suspendTunnel(): void {
    this.tunnelInterruptedAt ??= Date.now();
    // Process discovery has nothing to learn while the tunnel is down; the
    // next successful attempt restarts it with routing.
    this.stopProcessRoutingMonitor();
    if (!this.systemRoutingApplied || this.routingHoldTimer) {
      return;
    }
    const holdGeneration = ++this.routingHoldGeneration;
    this.routingHoldTimer = setTimeout(() => {
      this.routingHoldTimer = undefined;
      if (this.client || this.disposed || this.disconnectRequested || !this.systemRoutingApplied) {
        return;
      }
      this.appendDiagnostic(
        "warning",
        `The tunnel has been down for ${Math.round(ROUTING_HOLD_TIMEOUT_MS / 1000)} s; returning the machine to direct routing until the session is back.`
      );
      void this.enqueueMutation(async () => {
        // A session may have come and gone again while this waited its turn;
        // that outage has a hold of its own and must not lose it to this one.
        if (holdGeneration !== this.routingHoldGeneration || this.client || this.disposed || this.disconnectRequested) {
          return;
        }
        await this.stopSystemRouting();
      }).catch(() => undefined);
    }, ROUTING_HOLD_TIMEOUT_MS);
    this.routingHoldTimer.unref();
  }

  private clearRoutingHold(): void {
    this.routingHoldGeneration += 1;
    if (this.routingHoldTimer) {
      clearTimeout(this.routingHoldTimer);
      this.routingHoldTimer = undefined;
    }
  }

  /**
   * Hands an accepted proxy connection the session it should open its channel
   * in. While the session is being rebuilt the connection waits here instead
   * of being refused; the wait ends when the new session is up, when the
   * caller's socket goes away, when reconnecting is given up, or after
   * {@link TUNNEL_RECOVERY_PARK_TIMEOUT_MS}.
   */
  private waitForTunnel(signal?: AbortSignal): Promise<SshLiveClient> {
    const client = this.client;
    if (client && this.status.state === "Connected") {
      return Promise.resolve(client);
    }
    if (this.disposed || this.disconnectRequested || this.reconnectHalted || !this.lastRequest) {
      return Promise.reject(new Error("SSH session is not connected."));
    }
    if (signal?.aborted) {
      return Promise.reject(abortedTunnelWaitError());
    }
    return new Promise<SshLiveClient>((resolve, reject) => {
      const waiter: TunnelWaiter = {
        resolve,
        reject,
        timer: setTimeout(() => {
          this.tunnelWaiters.delete(waiter);
          waiter.detachAbort?.();
          reject(new Error(`SSH tunnel is reconnecting; gave up waiting for it after ${Math.round(TUNNEL_RECOVERY_PARK_TIMEOUT_MS / 1000)} s.`));
        }, TUNNEL_RECOVERY_PARK_TIMEOUT_MS)
      };
      waiter.timer.unref();
      if (signal) {
        const onAbort = (): void => {
          this.tunnelWaiters.delete(waiter);
          clearTimeout(waiter.timer);
          reject(abortedTunnelWaitError());
        };
        signal.addEventListener("abort", onAbort, { once: true });
        waiter.detachAbort = () => signal.removeEventListener("abort", onAbort);
      }
      this.tunnelWaiters.add(waiter);
    });
  }

  private releaseTunnelWaiters(client: SshLiveClient): number {
    const waiters = [...this.tunnelWaiters];
    this.tunnelWaiters.clear();
    for (const waiter of waiters) {
      clearTimeout(waiter.timer);
      waiter.detachAbort?.();
      waiter.resolve(client);
    }
    return waiters.length;
  }

  private rejectTunnelWaiters(error: Error): void {
    const waiters = [...this.tunnelWaiters];
    this.tunnelWaiters.clear();
    for (const waiter of waiters) {
      clearTimeout(waiter.timer);
      waiter.detachAbort?.();
      waiter.reject(error);
    }
  }

  private scheduleReconnect(reason: string, generation: number, options: { immediate?: boolean } = {}): void {
    if (
      this.disposed ||
      !this.isCurrentLifecycle(generation) ||
      this.disconnectRequested ||
      this.reconnectHalted ||
      !this.lastRequest ||
      this.reconnectTimer
    ) {
      return;
    }
    // A wake that brings an already announced attempt forward is still that
    // attempt; only a new failure counts up.
    const attempt = options.immediate && this.status.state === "Reconnecting"
      ? Math.max(1, this.status.reconnectAttempt)
      : this.status.reconnectAttempt + 1;
    let immediate = options.immediate === true;
    let wakeReason: string | undefined;
    if (!immediate && this.pendingWakeReason !== undefined && this.mayResetBackoffOnWake()) {
      // The world changed while the failed attempt was running; that attempt
      // may have been fighting the old network. Start over without delay.
      wakeReason = this.pendingWakeReason;
      immediate = true;
      this.reconnectBackoffStep = 0;
    }
    this.pendingWakeReason = undefined;
    let delayMs: number;
    if (immediate) {
      // Something changed (a resume, a network change, the watchdog), so the
      // backoff is stale; only the spacing floor still applies. The floor is
      // measured on the wall clock, which can step backwards; never let that
      // stretch the wait beyond the floor itself.
      const sinceLastAttemptMs = Date.now() - this.lastConnectAttemptAt;
      delayMs = Math.min(MINIMUM_RECONNECT_SPACING_MS, Math.max(0, MINIMUM_RECONNECT_SPACING_MS - sinceLastAttemptMs));
    } else {
      // The tunnel is the machine's egress while it is down, so every second
      // of backoff is a second of failed connections for every proxied
      // application. Backing off for minutes only turns a transient drop into
      // an outage the user reads as "the client died"; half a minute is enough
      // to stop hammering an unreachable host.
      const baseDelayMs = RECONNECT_BACKOFF_STEPS_MS[Math.min(this.reconnectBackoffStep, RECONNECT_BACKOFF_STEPS_MS.length - 1)];
      const jitterMs = Math.floor(Math.random() * Math.min(5000, baseDelayMs * 0.2));
      // The spacing floor still applies to the immediate first retry.
      const sinceLastAttemptMs = Date.now() - this.lastConnectAttemptAt;
      delayMs = Math.max(baseDelayMs + jitterMs, Math.min(MINIMUM_RECONNECT_SPACING_MS, Math.max(0, MINIMUM_RECONNECT_SPACING_MS - sinceLastAttemptMs)));
      this.reconnectBackoffStep += 1;
    }
    this.setStatus({
      state: "Reconnecting",
      reconnectAttempt: attempt,
      realTunnelAvailable: false,
      message: `Reconnecting after SSH failure: ${reason}`
    });
    this.appendDiagnostic(
      "info",
      `Reconnect attempt ${attempt} scheduled in ${Math.round(delayMs / 1000)} s: ${reason}${wakeReason ? ` (brought forward by wake: ${wakeReason})` : ""}`
    );
    this.startSupervisor();
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      if (!this.lastRequest || !this.isCurrentLifecycle(generation) || this.disconnectRequested || this.reconnectHalted) {
        return;
      }
      this.startConnect(this.lastRequest, "reconnect").catch((error: unknown) => {
        // startConnect only rejects when the mutation queue itself breaks.
        // The loop must survive that too: log it and try again.
        const message = errorMessage(error);
        this.appendDiagnostic("error", `Reconnect attempt could not be started: ${message}`);
        this.scheduleReconnect(message, this.lifecycleGeneration);
      });
    }, delayMs);
    this.reconnectTimer.unref();
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
  }

  /**
   * Runs while a connection is wanted: the wake detector that notices sleep
   * and network changes, and the watchdog below.
   */
  private startSupervisor(): void {
    if (this.disposed) {
      return;
    }
    this.wakeDetector?.start();
    if (this.supervisorWatchdog) {
      return;
    }
    this.supervisorStallReported = false;
    this.supervisorWatchdog = setInterval(() => this.checkSupervisorInvariant(), SUPERVISOR_WATCHDOG_INTERVAL_MS);
    this.supervisorWatchdog.unref();
  }

  private stopSupervisor(): void {
    this.wakeDetector?.stop();
    if (this.supervisorWatchdog) {
      clearInterval(this.supervisorWatchdog);
      this.supervisorWatchdog = undefined;
    }
  }

  /**
   * The invariant of the reconnect loop: while a session is wanted and not
   * halted, there is a connected client, an attempt in progress, or a timer
   * that will start one. Every failure path above keeps it, but "sometimes it
   * just never reconnected" is precisely the class of bug a guarantee on
   * paper does not fix. A violation is logged as such and repaired.
   */
  private checkSupervisorInvariant(): void {
    if (this.disposed || this.disconnectRequested || !this.lastRequest || this.reconnectHalted) {
      return;
    }
    if (this.client) {
      this.supervisorStallReported = false;
      return;
    }
    if (this.reconnectTimer) {
      this.supervisorStallReported = false;
      return;
    }
    if (this.mutationsInFlight > 0) {
      const runningForMs = Date.now() - this.mutationInFlightSince;
      if (runningForMs >= SUPERVISOR_STUCK_ATTEMPT_MS && !this.supervisorStallReported) {
        this.supervisorStallReported = true;
        this.appendDiagnostic(
          "warning",
          `Connection supervisor: the current operation has been running for ${Math.round(runningForMs / 1000)} s without finishing (state=${this.status.state}).`
        );
      }
      return;
    }
    this.appendDiagnostic(
      "warning",
      `Connection supervisor: no session, no attempt in progress and no reconnect scheduled while a connection is wanted (state=${this.status.state}, attempt=${this.status.reconnectAttempt}). Scheduling a reconnect.`
    );
    this.scheduleReconnect("supervisor watchdog", this.lifecycleGeneration, { immediate: true });
  }

  private handleSystemWake(event: SystemWakeEvent): void {
    this.wake(`${event.reason}: ${event.detail}`);
  }

  /**
   * The local HTTP/SOCKS listener. It is created once per connected episode
   * and then outlives the SSH session: on a transport failure it keeps
   * accepting and parks connections until the session is back, so the port
   * applications were pointed at never goes dark. Only a user Disconnect, a
   * halt, or disposal stops it.
   */
  private async ensureLocalListener(): Promise<{ host: string; port: number }> {
    if (this.socksProxy && this.socksEndpoint) {
      return this.socksEndpoint;
    }
    const proxy = new Socks5Proxy({
      listenHost: "127.0.0.1",
      // Transport switches rebuild this listener; reusing the previous port
      // keeps manually configured clients pointing at a live endpoint instead
      // of a port that moved out from under them.
      preferredListenPort: preferredLocalProxyPort(),
      connectChannel: (target, originator, signal) => this.openTunnelChannel(target, originator, signal)
    });
    proxy.onEvent((event) => {
      if (this.socksProxy !== proxy) {
        return;
      }
      if (event.type === "error") {
        this.appendProxyDiagnostic("warning", event.message);
        return;
      }
      if (event.type === "connection" || event.type === "tunnel-opened") {
        this.appendProxyDiagnostic("info", event.message);
      }
    });
    let endpoint: { host: string; port: number };
    try {
      endpoint = await proxy.start();
    } catch (error) {
      await proxy.stop().catch(() => undefined);
      throw error;
    }
    rememberLocalProxyPort(endpoint.port);
    this.socksProxy = proxy;
    this.socksEndpoint = endpoint;
    this.startSocksProxyHeartbeat(proxy);
    this.appendDiagnostic("info", `Local HTTP/SOCKS proxy is listening on ${endpoint.host}:${endpoint.port}.`);
    this.syncDerivedStatus();
    return endpoint;
  }

  /**
   * Opens the channel for one accepted proxy connection in whichever session
   * is current, waiting for a session to come back if none is up.
   */
  private openTunnelChannel(
    target: DirectTcpIpTarget,
    originator: { address: string; port: number },
    signal?: AbortSignal
  ): Promise<DirectTcpIpChannel> {
    return this.openProxyChannel(() => this.waitForTunnel(signal), target, originator, signal);
  }

  /**
   * Chooses the egress path for one accepted proxy connection.
   *
   * While local per-process enforcement is active the system proxy hands us
   * every proxy-aware TCP connection, because Windows PAC cannot express
   * process identity. The routing decision therefore moves here, where the
   * owning process is known: `TrafficPolicy` evaluates domain, IP and
   * process.name rules together, matching traffic enters the SSH tunnel, and
   * everything else leaves the machine directly and unchanged.
   *
   * When enforcement is inactive the system proxy has already selected the
   * traffic, so every accepted connection is tunnelled as before.
   *
   * The session is acquired lazily, and only for traffic that is going into
   * the tunnel: while a reconnect is in progress that acquisition waits for
   * the new session, and traffic that leaves directly must not wait with it.
   */
  private async openProxyChannel(
    client: SshLiveClient | (() => Promise<SshLiveClient>),
    target: DirectTcpIpTarget,
    originator: { address: string; port: number },
    signal?: AbortSignal
  ): Promise<DirectTcpIpChannel> {
    const acquire = typeof client === "function" ? client : () => Promise.resolve(client);
    const request = this.lastRequest;
    if (!this.localProcessEnforcement || !request) {
      return (await acquire()).openDirectTcpIpChannel(target, originator, signal);
    }

    const context = this.localRoutingContext ?? buildLocalRoutingContext(request);
    const { channel, decision } = await this.localRoutingEnforcer.openChannel(
      context,
      target,
      originator,
      async () => (await acquire()).openDirectTcpIpChannel(target, originator, signal),
      signal
    );
    this.routingDecisions.record(target, decision);
    return channel;
  }

  /**
   * Logs a periodic summary of proxy traffic while the tunnel is up, so a
   * data-plane stall shows up in the log even when no routing decisions are
   * being made - the SSH transport carries every selected connection through
   * this one listener.
   */
  private startSocksProxyHeartbeat(proxy: Socks5Proxy): void {
    this.stopSocksProxyHeartbeat();
    const heartbeat = new ProxyActivityHeartbeat(
      () => (this.socksProxy === proxy ? proxy.snapshotStats() : undefined),
      (message) => {
        if (this.socksProxy === proxy) {
          this.appendDiagnostic("info", message);
        }
      }
    );
    heartbeat.start();
    this.socksProxyHeartbeat = setInterval(() => heartbeat.tick(), PROXY_HEARTBEAT_INTERVAL_MS);
    this.socksProxyHeartbeat.unref();
  }

  private stopSocksProxyHeartbeat(): void {
    if (this.socksProxyHeartbeat) {
      clearInterval(this.socksProxyHeartbeat);
      this.socksProxyHeartbeat = undefined;
    }
  }

  private async disconnectClient(client: SshLiveClient, reason: string): Promise<void> {
    try {
      await client.disconnect(reason);
    } catch (error) {
      this.appendDiagnostic("warning", `SSH client cleanup failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private enqueueMutation(operation: () => Promise<void>): Promise<void> {
    if (this.mutationsInFlight === 0) {
      this.mutationInFlightSince = Date.now();
    }
    this.mutationsInFlight += 1;
    const settle = (): void => {
      this.mutationsInFlight -= 1;
    };
    const result = this.mutationTail.then(operation, operation);
    result.then(settle, settle);
    this.mutationTail = result.catch(() => undefined);
    return result;
  }

  private enqueueTerminalMutation(operation: () => Promise<void>): Promise<void> {
    const result = this.terminalMutationTail.then(operation, operation);
    this.terminalMutationTail = result.catch(() => undefined);
    return result;
  }

  private isCurrentLifecycle(generation: number): boolean {
    return generation === this.lifecycleGeneration;
  }

  private isCurrentMutation(lifecycleGeneration: number, routingGeneration: number): boolean {
    return !this.disposed && this.isCurrentLifecycle(lifecycleGeneration) && routingGeneration === this.routingGeneration;
  }

  private clearProcessRoutingState(): void {
    this.processRoutingIps.clear();
    this.processRoutingHintDomains.clear();
    this.processRoutingDomains.clear();
    this.processRoutingDnsLookupAt.clear();
    this.processRoutingDnsLookupFailures.clear();
    this.processRoutingProfileCoveredAddresses.clear();
    this.processRoutingSessionLeases.clear();
    this.processRoutingLastSignature = "";
    this.processRoutingAppliedSignature = "";
    this.processRoutingTargetSignature = "";
    this.processRoutingApplyPending = false;
    this.processRoutingLastMatchedConnections = 0;
    this.processRoutingDnsWarningEmitted = false;
  }

  /** Takes down system routing and the local listener; the full teardown. */
  private async stopRouting(): Promise<void> {
    await this.stopSystemRouting();
    await this.stopLocalListener();
  }

  /**
   * Returns the machine to direct routing: TUN capture, process discovery
   * and the Windows proxy setting. The local listener is left alone.
   */
  private async stopSystemRouting(): Promise<void> {
    this.clearRoutingHold();
    this.systemRoutingApplied = false;
    this.stopProcessRoutingMonitor();
    // The adapter owns the routing table, so it comes down before anything
    // else: leaving capture routes pointing at a dead adapter takes the
    // machine offline.
    await this.stopTunRouting();
    this.localProcessEnforcement = false;
    this.localRoutingContext = undefined;
    this.clearProcessRoutingState();
    try {
      await this.systemProxy.restore();
    } catch (error) {
      this.appendDiagnostic("warning", `Windows proxy restore failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async stopLocalListener(): Promise<void> {
    this.stopSocksProxyHeartbeat();
    const socksProxy = this.socksProxy;
    this.socksProxy = undefined;
    this.socksEndpoint = undefined;
    if (this.tunnelWaiters.size > 0) {
      this.rejectTunnelWaiters(new Error("SSH session is not connected."));
      // Give the listener's handlers a turn to answer the waiting clients with
      // a proper proxy failure before their sockets are destroyed below.
      await new Promise<void>((resolve) => process.nextTick(resolve));
    }
    if (socksProxy) {
      try {
        await socksProxy.stop();
      } catch (error) {
        this.appendDiagnostic("warning", `Local proxy cleanup failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    this.syncDerivedStatus();
  }

  private async applySystemRouting(
    request: ConnectRequest,
    socksEndpoint: { host: string; port: number },
    allowConnecting = false
  ): Promise<void> {
    this.stopProcessRoutingMonitor();
    const generation = this.processRoutingGeneration;
    const summary = new RoutingMatcher(request.routingMode, request.routingRules).summary();
    const hasProcessRouting = supportsDynamicProcessRouting(request);

    // A TUN adapter is the only path that can hold a `process.name` rule
    // against an application that ignores the Windows proxy setting, so it is
    // tried first. Everything below is the fallback for a machine where it
    // cannot come up.
    if (await this.applyTunRouting(request, socksEndpoint, generation, allowConnecting)) {
      return;
    }

    // Per-process routing is enforced locally whenever the native helper can
    // attribute connections. Only when it cannot do we fall back to guessing an
    // application's destinations and feeding them to PAC.
    const context = buildLocalRoutingContext(request);
    const enforceability = await this.localRoutingEnforcer.describeEnforceability(context);
    this.localProcessEnforcement = enforceability.enforceable;
    if (generation !== this.processRoutingGeneration || !this.isRoutingStateActive(allowConnecting)) {
      return;
    }
    if (this.localProcessEnforcement) {
      this.localRoutingContext = context;
      await this.applyLocallyEnforcedRouting(request, socksEndpoint, generation, allowConnecting, summary);
      return;
    }
    if (enforceability.reason && hasProcessRouting) {
      // Naming the cause matters because the tunnel keeps working: domain and
      // IP rules are unaffected, so the only visible symptom is that selected
      // applications quietly stop being selected.
      this.appendDiagnostic(
        "warning",
        `Per-process enforcement is unavailable, so process rules fall back to PAC guessing - ${enforceability.reason}.`
      );
    }
    this.localRoutingContext = undefined;

    let literalIpSnapshotResult: SystemProxyApplyResult | undefined;
    let literalIpSnapshotError: unknown;
    let literalIpSnapshotFailed = false;
    let literalIpSnapshotSignature: string | undefined;
    if (hasProcessRouting) {
      await this.learnProcessRoutingIps(request, generation, async (signature) => {
        literalIpSnapshotSignature = signature;
        try {
          literalIpSnapshotResult = await this.publishProcessRoutingSnapshot(
            request,
            socksEndpoint,
            generation,
            signature,
            allowConnecting
          );
        } catch (error) {
          // DNS enrichment and the final publish below remain authoritative.
          // A transient failure of the literal-IP fast path must not skip them.
          literalIpSnapshotFailed = true;
          literalIpSnapshotError = error;
          this.processRoutingApplyPending = true;
        }
      });
      if (generation !== this.processRoutingGeneration || !this.isRoutingStateActive(allowConnecting)) {
        return;
      }
      this.appendDiagnostic(
        "warning",
        "Selected process-name routing is using dynamic process destination PAC rules. Reviewed host families stay stable while DNS-learned exact names use a bounded TTL; already-open sockets may still need reconnect, and strict per-process enforcement requires WFP/TUN."
      );
      if (
        literalIpSnapshotFailed &&
        literalIpSnapshotSignature === this.processRoutingLastSignature
      ) {
        if (this.status.state === "Connected") {
          this.startProcessRoutingMonitor(request, socksEndpoint);
        }
        throw literalIpSnapshotError;
      }
    } else {
      this.clearProcessRoutingState();
    }
    this.processRoutingApplyPending = hasProcessRouting;
    let result: SystemProxyApplyResult;
    if (
      hasProcessRouting &&
      literalIpSnapshotResult &&
      literalIpSnapshotSignature === this.processRoutingLastSignature
    ) {
      result = literalIpSnapshotResult;
    } else {
      try {
        result = await this.systemProxy.apply({
          mode: request.routingMode,
          rules: buildSelectedRulesWithProcessIps(
            request.routingRules,
            this.currentProcessRoutingIps(),
            this.currentProcessRoutingDomains()
          ),
          proxyDomains: request.routingProxyDomains,
          directDomains: request.routingDirectDomains,
          socksHost: socksEndpoint.host,
          socksPort: socksEndpoint.port,
          forcePacEndpointRotation: hasProcessRouting
        });
      } catch (error) {
        if (hasProcessRouting && generation === this.processRoutingGeneration && this.status.state === "Connected") {
          this.startProcessRoutingMonitor(request, socksEndpoint);
        }
        throw error;
      }
    }
    if (generation !== this.processRoutingGeneration || !this.isRoutingStateActive(allowConnecting)) {
      return;
    }
    if (hasProcessRouting && result.applied) {
      this.processRoutingAppliedSignature = this.processRoutingLastSignature;
      this.processRoutingApplyPending = false;
    }
    this.appendDiagnostic(result.applied ? "info" : "warning", result.message);
    if (hasProcessRouting) {
      this.startProcessRoutingMonitor(request, socksEndpoint);
    }

    if (request.routingMode === "proxy-all") {
      this.appendDiagnostic("info", "Proxy-all TCP routing uses the local HTTP/SOCKS proxy through the Windows system proxy when running on Windows.");
      return;
    }
    this.appendDiagnostic(
      summary.enabledRules > 0 ? "info" : "warning",
      `Selected routing prepared: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}, matchedProcessConnections=${this.processRoutingLastMatchedConnections}, learnedProcessIps=${this.processRoutingIps.size}, learnedProcessDomains=${this.currentProcessRoutingDomains().size}.`
    );
  }

  /**
   * Applies routing for the locally enforced path.
   *
   * The system proxy is pointed at the local listener for all proxy-aware TCP
   * traffic, because a PAC file cannot tell which process opened a connection.
   * That is not proxy-all routing: `openProxyChannel` evaluates every rule type
   * per connection and gives non-matching traffic a direct egress, so only the
   * selected domains, addresses and processes reach the tunnel. The configured
   * direct list is still honoured by the PAC itself and never reaches us.
   */
  /**
   * Puts the TUN adapter in front of the machine's traffic.
   *
   * Returns false, having changed nothing, whenever the adapter cannot be
   * used. Falling back matters more than reporting: a machine that is not
   * elevated still deserves the proxy path's partial protection rather than no
   * routing at all.
   */
  private async applyTunRouting(
    request: ConnectRequest,
    socksEndpoint: { host: string; port: number },
    generation: number,
    allowConnecting: boolean
  ): Promise<boolean> {
    const dataplane = this.dataplane;
    if (!dataplane || request.tunDataplaneEnabled !== true || process.platform !== "win32") {
      return false;
    }

    const availability = await dataplane.probe();
    if (generation !== this.processRoutingGeneration || !this.isRoutingStateActive(allowConnecting)) {
      return false;
    }
    if (!availability.available) {
      this.appendDiagnostic(
        "warning",
        `TUN routing is unavailable, continuing on the Windows proxy path: ${availability.reason ?? "unknown reason"}`
      );
      return false;
    }

    // The helper must exclude the address this process actually reached the
    // server on. The live socket's own peer address is authoritative: a fresh
    // lookup of a multi-record hostname can answer differently and would leave
    // the connection in use unprotected, which routes the tunnel into itself.
    const connectedAddress = this.client?.serverAddress;
    const resolved = await this.protectedAddressResolver(request.config.host);
    const protectedAddresses = connectedAddress
      ? [connectedAddress, ...resolved.filter((address) => address !== connectedAddress)]
      : resolved;
    if (generation !== this.processRoutingGeneration || !this.isRoutingStateActive(allowConnecting)) {
      return false;
    }
    if (protectedAddresses.length === 0) {
      // Capturing the default route without excluding the server would reset
      // the transport's own connection the moment the routes go in, and leave
      // the adapter black-holing everything it was meant to protect.
      this.appendDiagnostic(
        "warning",
        `TUN routing is unavailable: no address could be resolved for ${request.config.host} to keep off the adapter. Continuing on the Windows proxy path.`
      );
      return false;
    }

    try {
      await startDataplaneWithRetry(dataplane, {
        routingMode: request.routingMode,
        routingRules: request.routingRules,
        routingProxyDomains: request.routingProxyDomains,
        routingDirectDomains: request.routingDirectDomains,
        tunnelProxyEndpoint: `${socksEndpoint.host}:${socksEndpoint.port}`,
        protectedAddresses,
        protectedPort: request.config.port,
        // The SSH connection protocol has no datagram channel, so a selected
        // application's UDP is dropped by the helper rather than leaked. QUIC
        // clients fall back to TCP, which is carried.
        udpSupported: false,
        enforceIpv6: true,
        adapterName: TUN_ADAPTER_NAME,
        journalPath: this.dataplaneJournalPath
      }, {
        onRetry: (attempt, attempts, error) =>
          this.appendDiagnostic(
            "warning",
            `TUN routing did not start on attempt ${attempt} of ${attempts}, retrying: ${errorText(error)}`
          )
      });
    } catch (error) {
      // Worth spelling out: the fallback still routes domains and IP ranges, so
      // the tunnel looks healthy while process rules quietly stop reaching the
      // applications that ignore the Windows proxy setting.
      this.appendDiagnostic(
        "warning",
        `TUN routing could not start, continuing on the Windows proxy path - process rules will not reach applications that ignore the Windows proxy setting: ${errorText(error)}`
      );
      return false;
    }

    // With the adapter carrying traffic the Windows proxy setting must go:
    // leaving it would hand proxy-aware applications a second, redundant path
    // into the same listener, with different rules applied on the way.
    try {
      await this.systemProxy.restore();
    } catch (error) {
      this.appendDiagnostic(
        "warning",
        `Windows proxy restore after enabling TUN routing failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    this.tunRoutingActive = true;
    this.syncDerivedStatus();
    // The local listener now only receives traffic the helper already decided
    // to tunnel, so a second policy pass here would double-count the rules.
    this.localProcessEnforcement = false;
    this.localRoutingContext = undefined;
    this.clearProcessRoutingState();
    this.appendDiagnostic(
      "info",
      "TUN routing is active: every selected application's traffic is captured at the adapter, including UDP, which this transport drops rather than leaks. Domain rules match on the name each connection opens (TLS SNI, HTTP Host, QUIC), so a browser that resolved before connecting or uses DNS-over-HTTPS is covered."
    );
    return true;
  }

  private async stopTunRouting(): Promise<void> {
    if (!this.dataplane || !this.tunRoutingActive) {
      return;
    }
    this.tunRoutingActive = false;
    try {
      await this.dataplane.stop();
    } catch (error) {
      this.appendDiagnostic(
        "error",
        `TUN routing teardown failed; the machine may still be routing through a stale adapter: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    this.syncDerivedStatus();
  }

  private async applyLocallyEnforcedRouting(
    request: ConnectRequest,
    socksEndpoint: { host: string; port: number },
    generation: number,
    allowConnecting: boolean,
    summary: RoutingMatcherSummary
  ): Promise<void> {
    this.clearProcessRoutingState();
    // The direct list is deliberately withheld from the PAC here: the PAC runs
    // before the listener and cannot see processes, so a direct-list entry
    // there would carve holes in a selected application's traffic. It is
    // applied per connection instead, after the process rule.
    const result = await this.systemProxy.apply({
      mode: "proxy-all",
      rules: request.routingRules,
      proxyDomains: request.routingProxyDomains,
      directDomains: [],
      socksHost: socksEndpoint.host,
      socksPort: socksEndpoint.port
    });
    if (generation !== this.processRoutingGeneration || !this.isRoutingStateActive(allowConnecting)) {
      return;
    }
    this.appendDiagnostic(result.applied ? "info" : "warning", result.message);
    this.appendDiagnostic(
      "info",
      `Selected routing is enforced locally with native process attribution: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}. Domain, IP and process rules are evaluated together per connection; unmatched traffic leaves the machine directly.`
    );
  }

  private isRoutingStateActive(allowConnecting: boolean): boolean {
    if (this.status.state === "Connected") {
      return true;
    }
    // An automatic attempt keeps the Reconnecting status while it applies
    // routing, so the renderer keeps saying "Restoring" rather than "Starting".
    return allowConnecting && (this.status.state === "Connecting" || this.status.state === "Reconnecting");
  }

  private startProcessRoutingMonitor(request: ConnectRequest, socksEndpoint: { host: string; port: number }): void {
    this.stopProcessRoutingMonitor();
    if (!supportsDynamicProcessRouting(request)) {
      return;
    }

    const generation = this.processRoutingGeneration;
    // Multi-endpoint applications often expose additional API/CDN/WebSocket
    // destinations only after the first connection succeeds. Always complete
    // one bounded discovery burst instead of stopping at the first learned IP.
    this.processRoutingDiscoveryStep = 0;
    this.scheduleProcessRoutingRefresh(request, socksEndpoint, generation);
  }

  private scheduleProcessRoutingRefresh(
    request: ConnectRequest,
    socksEndpoint: { host: string; port: number },
    generation: number
  ): void {
    if (generation !== this.processRoutingGeneration || !this.isRoutingStateActive(true)) {
      return;
    }
    this.processRoutingMonitor = setTimeout(() => {
      this.processRoutingMonitor = undefined;
      if (generation !== this.processRoutingGeneration || !this.isRoutingStateActive(true)) {
        return;
      }
      void this.enqueueMutation(() => this.refreshProcessRouting(request, socksEndpoint, generation))
        .catch((error: unknown) => {
          if (!this.processRoutingWarningEmitted) {
            this.processRoutingWarningEmitted = true;
            this.appendDiagnostic(
              "warning",
              `Process-name routing refresh failed: ${error instanceof Error ? error.message : String(error)}`
            );
          }
        })
        .finally(() => {
          this.scheduleProcessRoutingRefresh(request, socksEndpoint, generation);
        });
    }, this.nextProcessRoutingRefreshIntervalMs());
    this.processRoutingMonitor.unref();
  }

  private stopProcessRoutingMonitor(): void {
    this.processRoutingGeneration += 1;
    if (!this.processRoutingMonitor) {
      return;
    }
    clearTimeout(this.processRoutingMonitor);
    this.processRoutingMonitor = undefined;
  }

  private async refreshProcessRouting(
    request: ConnectRequest,
    socksEndpoint: { host: string; port: number },
    generation: number
  ): Promise<void> {
    if (generation !== this.processRoutingGeneration || this.status.state !== "Connected") {
      return;
    }
    let literalIpSnapshotResult: SystemProxyApplyResult | undefined;
    let literalIpSnapshotError: unknown;
    let literalIpSnapshotFailed = false;
    let literalIpSnapshotSignature: string | undefined;
    await this.learnProcessRoutingIps(request, generation, async (signature) => {
      literalIpSnapshotSignature = signature;
      try {
        literalIpSnapshotResult = await this.publishProcessRoutingSnapshot(
          request,
          socksEndpoint,
          generation,
          signature,
          false
        );
      } catch (error) {
        literalIpSnapshotFailed = true;
        literalIpSnapshotError = error;
        this.processRoutingApplyPending = true;
      }
    });
    if (
      literalIpSnapshotFailed &&
      literalIpSnapshotSignature === this.processRoutingLastSignature
    ) {
      throw literalIpSnapshotError;
    }
    if (generation !== this.processRoutingGeneration || this.status.state !== "Connected") {
      return;
    }
    if (
      literalIpSnapshotResult &&
      literalIpSnapshotSignature === this.processRoutingLastSignature
    ) {
      this.appendDiagnostic(
        literalIpSnapshotResult.applied ? "info" : "warning",
        `Process-name literal-IP routing updated before DNS enrichment: matchedProcessConnections=${this.processRoutingLastMatchedConnections}, learnedProcessIps=${this.processRoutingIps.size}. ${literalIpSnapshotResult.message}`
      );
      return;
    }
    if (!this.processRoutingApplyPending && this.processRoutingLastSignature === this.processRoutingAppliedSignature) {
      return;
    }

    const observedSignature = this.processRoutingLastSignature;
    const result = await this.publishProcessRoutingSnapshot(
      request,
      socksEndpoint,
      generation,
      observedSignature,
      false
    );
    if (!result) {
      return;
    }
    this.appendDiagnostic(
      result.applied ? "info" : "warning",
      `Process-name routing updated: matchedProcessConnections=${this.processRoutingLastMatchedConnections}, learnedProcessIps=${this.processRoutingIps.size}, learnedProcessDomains=${this.currentProcessRoutingDomains().size}. ${result.message}`
    );
  }

  private async publishProcessRoutingSnapshot(
    request: ConnectRequest,
    socksEndpoint: { host: string; port: number },
    generation: number,
    signature: string,
    allowConnecting: boolean
  ): Promise<SystemProxyApplyResult | undefined> {
    if (
      generation !== this.processRoutingGeneration ||
      !this.isRoutingStateActive(allowConnecting) ||
      signature !== this.processRoutingLastSignature
    ) {
      return undefined;
    }
    this.processRoutingApplyPending = true;
    const result = await this.systemProxy.apply({
      mode: request.routingMode,
      rules: buildSelectedRulesWithProcessIps(
        request.routingRules,
        this.currentProcessRoutingIps(),
        this.currentProcessRoutingDomains()
      ),
      proxyDomains: request.routingProxyDomains,
      directDomains: request.routingDirectDomains,
      socksHost: socksEndpoint.host,
      socksPort: socksEndpoint.port,
      forcePacEndpointRotation: true
    });
    if (
      result.applied &&
      generation === this.processRoutingGeneration &&
      this.isRoutingStateActive(allowConnecting) &&
      this.processRoutingLastSignature === signature
    ) {
      this.processRoutingAppliedSignature = signature;
      this.processRoutingApplyPending = false;
    }
    return result;
  }

  private async learnProcessRoutingIps(
    request: ConnectRequest,
    generation?: number,
    publishLiteralIpSnapshot?: (signature: string) => Promise<void>
  ): Promise<boolean> {
    if (!supportsDynamicProcessRouting(request)) {
      return false;
    }
    if (generation !== undefined && generation !== this.processRoutingGeneration) {
      return false;
    }
    const directDomainSuffixes = normalizeProcessRouteDirectDomains(request.routingDirectDomains);
    const signatureBeforeLearning = this.processRoutingLastSignature;
    const literalIpsBeforeLearning = new Set(this.processRoutingIps.keys());

    try {
      const processNames = enabledProcessRuleNames(request.routingRules);
      this.resetProcessRoutingIpsForTargets(processNames);
      const connections = await this.processConnectionsProvider(processNames);
      if (generation !== undefined && generation !== this.processRoutingGeneration) {
        return false;
      }
      const now = Date.now();
      const routeTtlMs = this.currentProcessRoutingTtlMs();
      const expiresBefore = now - routeTtlMs;
      // A learned destination can never be observed a second time: as soon as it
      // enters the PAC the application connects to the loopback proxy instead of
      // the real remote address, so Get-NetTCPConnection stops reporting it and
      // nothing re-populates its Windows DNS cache entry. Expiring such a route
      // on its original TTL therefore dropped a destination the application was
      // still actively using back to DIRECT, which is why process-name routing
      // only ever covered part of an application's traffic. Renew every retained
      // route on each successful discovery cycle instead: routes live for the
      // connected session (bounded by the LRU caps, and cleared by stopRouting()
      // or a routing-target change) and only decay once discovery itself has
      // been failing for a full TTL.
      const nextIps = new Map(
        [...this.processRoutingIps]
          .filter((entry) => entry[1] >= expiresBefore)
          .map(([address]) => [address, now] as const)
      );
      const nextDomains = new Map(
        [...this.processRoutingDomains]
          .filter((entry) =>
            entry[1] > now && !isDomainCoveredByDirectDomainSuffixes(entry[0], directDomainSuffixes)
          )
          .map(([domain]) => [domain, now + routeTtlMs] as const)
      );
      const activeProfileCoveredAddresses = new Map(
        [...this.processRoutingProfileCoveredAddresses]
          .filter((entry) => entry[1] > now)
          .map(([address]) => [address, now + routeTtlMs] as const)
      );
      const nextSessionLeases = new Map(this.processRoutingSessionLeases);
      const knownAddressesBeforeObservation = new Set([
        ...nextIps.keys(),
        ...activeProfileCoveredAddresses.keys(),
        ...nextSessionLeases.keys()
      ]);
      const observedAddresses = new Set<string>();
      const unprofiledAddresses = new Set<string>();
      const processOwnersByAddress = new Map<string, Set<string>>();
      const profilePatternsByAddress = new Map<string, Set<string>>();
      const profilePatternsByProcess = new Map(
        [...processNames].map((processName) => [processName, processRouteDomainHints([processName])] as const)
      );
      let matchedConnections = 0;
      for (const connection of connections) {
        const processName = normalizeWindowsProcessName(connection.processName);
        if (processNames.has(processName)) {
          matchedConnections += 1;
          observedAddresses.add(connection.remoteAddress);
          recordBoundedProcessRouteIp(nextIps, connection.remoteAddress, now);
          const owners = processOwnersByAddress.get(connection.remoteAddress) ?? new Set<string>();
          owners.add(processName);
          processOwnersByAddress.set(connection.remoteAddress, owners);
          const profilePatterns = profilePatternsByProcess.get(processName) ?? new Set<string>();
          if (profilePatterns.size === 0) {
            unprofiledAddresses.add(connection.remoteAddress);
          } else {
            const addressPatterns = profilePatternsByAddress.get(connection.remoteAddress) ?? new Set<string>();
            for (const pattern of profilePatterns) {
              addressPatterns.add(pattern);
            }
            profilePatternsByAddress.set(connection.remoteAddress, addressPatterns);
          }
        }
      }
      this.processRoutingLastMatchedConnections = matchedConnections;

      for (const [address, lease] of [...nextSessionLeases]) {
        if (isDomainCoveredByDirectDomainSuffixes(lease.domain, directDomainSuffixes)) {
          nextSessionLeases.delete(address);
        }
      }

      for (const address of [...activeProfileCoveredAddresses.keys()]) {
        if (profilePatternsByAddress.has(address) && !unprofiledAddresses.has(address)) {
          activeProfileCoveredAddresses.set(address, now + routeTtlMs);
          nextIps.delete(address);
        }
      }

      // Publish the literal-IP fallback before the optional DNS cache query.
      // Dynamic process IPs intentionally do not resolve PAC hostnames, so this
      // fast path only helps clients that give PAC an already-resolved IP. DNS
      // enrichment below remains the required hostname-routing phase.
      const literalIpSnapshotChanged = this.commitProcessRoutingSnapshot(
        nextIps,
        nextDomains,
        activeProfileCoveredAddresses,
        nextSessionLeases
      );
      const literalIpSetChanged =
        literalIpsBeforeLearning.size !== nextIps.size ||
        [...literalIpsBeforeLearning].some((address) => !nextIps.has(address));
      if (
        directDomainSuffixes.size === 0 &&
        literalIpSnapshotChanged &&
        literalIpSetChanged &&
        publishLiteralIpSnapshot
      ) {
        await publishLiteralIpSnapshot(this.processRoutingLastSignature);
        if (generation !== undefined && generation !== this.processRoutingGeneration) {
          return false;
        }
      }

      const dnsLookupAddresses = [...observedAddresses].filter((address) => {
        const nextLookupAt = this.processRoutingDnsLookupAt.get(address);
        return nextLookupAt === undefined || now >= nextLookupAt;
      });
      if (dnsLookupAddresses.length > 0) {
        for (const address of dnsLookupAddresses) {
          const failures = Math.min((this.processRoutingDnsLookupFailures.get(address) ?? 0) + 1, 16);
          const retryDelay = Math.min(
            PROCESS_ROUTE_DNS_REFRESH_MS,
            PROCESS_ROUTE_DNS_RETRY_BASE_MS * 2 ** Math.min(failures - 1, 5)
          );
          recordBoundedProcessRouteIp(this.processRoutingDnsLookupFailures, address, failures);
          recordBoundedProcessRouteIp(this.processRoutingDnsLookupAt, address, now + retryDelay);
        }
        try {
          const dnsEntries = await this.processDnsEntriesProvider(dnsLookupAddresses);
          if (generation !== undefined && generation !== this.processRoutingGeneration) {
            return false;
          }
          const configuredDomainPatterns = request.routingRules
            .filter((rule) => rule.enabled && rule.type === "domain" && validateRoutingRuleValue(rule.type, rule.value).ok)
            .map((rule) => normalizeRuleValue("domain", rule.value));
          const stableDomainPatterns = [...this.processRoutingHintDomains, ...configuredDomainPatterns];
          const addressesWithDnsEntries = new Set<string>();
          const profileCoveredAddresses = new Set<string>();
          const validDnsEntriesByTuple = new Map<string, WindowsDnsCacheEntry>();
          for (const entry of dnsEntries) {
            const domain = normalizeRuleValue("domain", entry.domain).replace(/\.$/u, "");
            if (
              !observedAddresses.has(entry.address) ||
              !Number.isSafeInteger(entry.ttlSeconds) ||
              entry.ttlSeconds <= 0 ||
              domain.startsWith("*.") ||
              !validateRoutingRuleValue("domain", domain).ok
            ) {
              continue;
            }
            const key = `${entry.address}\u0000${domain}`;
            const existing = validDnsEntriesByTuple.get(key);
            if (!existing || entry.ttlSeconds > existing.ttlSeconds) {
              validDnsEntriesByTuple.set(key, { ...entry, domain });
            }
          }
          const validDnsEntries = [...validDnsEntriesByTuple.values()];
          const exactDomainsByAddress = new Map<string, Set<string>>();
          for (const entry of validDnsEntries) {
            addressesWithDnsEntries.add(entry.address);
            const domains = exactDomainsByAddress.get(entry.address) ?? new Set<string>();
            domains.add(entry.domain);
            exactDomainsByAddress.set(entry.address, domains);
            const profilePatterns = profilePatternsByAddress.get(entry.address);
            if (profilePatterns && isDomainCoveredByRoutePatterns(entry.domain, profilePatterns)) {
              profileCoveredAddresses.add(entry.address);
            }
          }
          const dnsRefreshAtByAddress = new Map<string, number>();
          for (const entry of validDnsEntries) {
            const ttlMs = Math.min(routeTtlMs, PROCESS_ROUTE_DNS_REFRESH_MS, entry.ttlSeconds * 1000);
            const refreshAt = now + Math.max(PROCESS_ROUTE_DNS_MIN_REFRESH_MS, ttlMs);
            const currentRefreshAt = dnsRefreshAtByAddress.get(entry.address);
            if (currentRefreshAt === undefined || refreshAt < currentRefreshAt) {
              dnsRefreshAtByAddress.set(entry.address, refreshAt);
            }
          }

          const promotedSessionLeaseAddresses = new Set<string>();
          for (const address of dnsLookupAddresses) {
            const owners = processOwnersByAddress.get(address);
            const soleProcessName = owners?.size === 1 ? owners.values().next().value as string | undefined : undefined;
            const exactDomains = exactDomainsByAddress.get(address) ?? new Set<string>();
            const exactDomain = exactDomains.size === 1
              ? exactDomains.values().next().value as string | undefined
              : undefined;
            const hasProfileEvidence =
              profilePatternsByAddress.has(address) ||
              profileCoveredAddresses.has(address) ||
              activeProfileCoveredAddresses.has(address);
            const isHighConfidenceEvidence = Boolean(
              soleProcessName &&
              exactDomain &&
              (profilePatternsByProcess.get(soleProcessName)?.size ?? 0) === 0 &&
              !hasProfileEvidence &&
              isAutoLearnableRemoteAddress(address) &&
              !isDomainCoveredByDirectDomainSuffixes(exactDomain, directDomainSuffixes)
            );
            if (
              isHighConfidenceEvidence &&
              soleProcessName &&
              exactDomain &&
              !knownAddressesBeforeObservation.has(address) &&
              nextSessionLeases.size < MAX_PROCESS_ROUTE_SESSION_LEASES
            ) {
              nextSessionLeases.set(address, {
                processName: soleProcessName,
                address,
                domain: exactDomain,
                firstObservedAt: now
              });
              promotedSessionLeaseAddresses.add(address);
            }
          }

          for (const entry of validDnsEntries) {
            const profilePatterns = profilePatternsByAddress.get(entry.address);
            const restrictToReviewedProfile =
              (profileCoveredAddresses.has(entry.address) || activeProfileCoveredAddresses.has(entry.address)) &&
              !unprofiledAddresses.has(entry.address);
            if (
              restrictToReviewedProfile &&
              (!profilePatterns || !isDomainCoveredByRoutePatterns(entry.domain, profilePatterns))
            ) {
              continue;
            }
            if (!isDomainCoveredByRoutePatterns(
              entry.domain,
              stableDomainPatterns
            ) && !isDomainCoveredByDirectDomainSuffixes(entry.domain, directDomainSuffixes)) {
              // The record TTL only says when the Windows DNS cache entry has to
              // be re-read (dnsRefreshAtByAddress above); it says nothing about
              // how long the application keeps using the hostname. Binding the
              // PAC route to it expired CDN/API hosts after a few tens of
              // seconds, so route on the process-route TTL and let the renewal
              // above keep it alive for the session.
              recordBoundedProcessRouteDomain(nextDomains, entry.domain, now + routeTtlMs);
            }
          }
          for (const address of addressesWithDnsEntries) {
            const refreshAt = dnsRefreshAtByAddress.get(address) ?? now + PROCESS_ROUTE_DNS_RETRY_BASE_MS;
            recordBoundedProcessRouteIp(this.processRoutingDnsLookupAt, address, refreshAt);
            this.processRoutingDnsLookupFailures.delete(address);
          }
          for (const address of promotedSessionLeaseAddresses) {
            recordBoundedProcessRouteIp(
              this.processRoutingDnsLookupAt,
              address,
              now + PROCESS_ROUTE_DNS_RETRY_BASE_MS
            );
          }
          for (const address of profileCoveredAddresses) {
            recordBoundedProcessRouteIp(
              activeProfileCoveredAddresses,
              address,
              now + routeTtlMs
            );
            if (!unprofiledAddresses.has(address)) {
              nextIps.delete(address);
            }
          }
          if (addressesWithDnsEntries.size > 0) {
            this.processRoutingDnsWarningEmitted = false;
          }
        } catch (error) {
          for (const address of dnsLookupAddresses) {
            if (nextSessionLeases.has(address) && observedAddresses.has(address)) {
              recordBoundedProcessRouteIp(nextIps, address, now);
            }
          }
          if (!this.processRoutingDnsWarningEmitted) {
            this.processRoutingDnsWarningEmitted = true;
            this.appendDiagnostic(
              "warning",
              `Process-name DNS enrichment failed; IP fallback remains active: ${error instanceof Error ? error.message : String(error)}`
            );
          }
        }
      }

      this.commitProcessRoutingSnapshot(
        nextIps,
        nextDomains,
        activeProfileCoveredAddresses,
        nextSessionLeases
      );
      return this.processRoutingLastSignature !== signatureBeforeLearning;
    } catch (error) {
      this.processRoutingLastMatchedConnections = 0;
      this.processRoutingDomains = new Map(
        [...this.processRoutingDomains].filter((entry) =>
          !isDomainCoveredByDirectDomainSuffixes(entry[0], directDomainSuffixes)
        )
      );
      this.processRoutingSessionLeases = new Map(
        [...this.processRoutingSessionLeases].filter((entry) =>
          !isDomainCoveredByDirectDomainSuffixes(entry[1].domain, directDomainSuffixes)
        )
      );
      const changed = this.pruneExpiredProcessRoutingState();
      if (!this.processRoutingWarningEmitted) {
        this.processRoutingWarningEmitted = true;
        this.appendDiagnostic(
          "warning",
          `Process-name routing monitor failed: ${error instanceof Error ? error.message : String(error)}`
        );
      }
      return changed;
    }
  }

  private commitProcessRoutingSnapshot(
    ips: ReadonlyMap<string, number>,
    domains: ReadonlyMap<string, number>,
    profileCoveredAddresses: ReadonlyMap<string, number>,
    sessionLeases: ReadonlyMap<string, ProcessRouteSessionEvidence>
  ): boolean {
    const signature = buildProcessRouteSignature(
      ips.keys(),
      [
        ...this.processRoutingHintDomains,
        ...domains.keys(),
        ...[...sessionLeases.values()].map((lease) => lease.domain)
      ]
    );
    const changed = signature !== this.processRoutingLastSignature;
    // Clone the phase-local maps so DNS enrichment cannot mutate the
    // published interim snapshot while its PAC application is in flight.
    this.processRoutingIps = new Map(ips);
    this.processRoutingDomains = new Map(domains);
    this.processRoutingProfileCoveredAddresses = new Map(profileCoveredAddresses);
    this.processRoutingSessionLeases = new Map(sessionLeases);
    this.processRoutingLastSignature = signature;
    return changed;
  }

  private setStatus(update: Partial<RuntimeStatus>): void {
    this.status = {
      ...this.status,
      ...update,
      ...this.derivedStatus(),
      transport: "live-ssh",
      platformTarget: this.status.platformTarget
    };
    this.emit({ type: "status-changed", status: this.getStatus() });
  }

  /** Status fields that follow the listener and the adapter rather than the session state. */
  private derivedStatus(): Pick<RuntimeStatus, "localProxy" | "tunActive"> {
    const endpoint = this.socksEndpoint;
    return {
      // One listener speaks both protocols, so there is no separate SOCKS port.
      localProxy: endpoint ? { host: endpoint.host, httpPort: endpoint.port } : undefined,
      tunActive: this.tunRoutingActive && this.dataplane?.isActive === true
    };
  }

  /** Publishes a listener or adapter change that happened without a state change. */
  private syncDerivedStatus(): void {
    const derived = this.derivedStatus();
    if (!sameLocalProxy(derived.localProxy, this.status.localProxy) || derived.tunActive !== this.status.tunActive) {
      this.setStatus({});
    }
  }

  private currentProcessRoutingRefreshIntervalMs(): number {
    try {
      const requested = this.processRoutingRefreshIntervalMs();
      return Number.isFinite(requested) && requested >= 1_000
        ? Math.min(requested, 10 * 60 * 1000)
        : PROCESS_ROUTE_REFRESH_INTERVAL_MS;
    } catch {
      return PROCESS_ROUTE_REFRESH_INTERVAL_MS;
    }
  }

  private nextProcessRoutingRefreshIntervalMs(): number {
    const discoveryDelay = PROCESS_ROUTE_DISCOVERY_DELAYS_MS[this.processRoutingDiscoveryStep];
    if (discoveryDelay !== undefined) {
      this.processRoutingDiscoveryStep += 1;
      return discoveryDelay;
    }
    return this.currentProcessRoutingRefreshIntervalMs();
  }

  private currentProcessRoutingTtlMs(): number {
    return Math.max(PROCESS_ROUTE_TTL_MS, this.currentProcessRoutingRefreshIntervalMs() * 3);
  }

  private appendDiagnostic(level: DiagnosticsEntry["level"], message: string): void {
    this.emit({
      type: "diagnostics-appended",
      entry: {
        id: randomUUID(),
        at: new Date().toISOString(),
        level,
        message: redactSecrets(message)
      }
    });
  }

  private appendProxyDiagnostic(level: DiagnosticsEntry["level"], message: string): void {
    if (level === "warning") {
      if (this.proxyWarningDiagnostics >= 40) {
        return;
      }
      this.proxyWarningDiagnostics += 1;
      if (this.proxyWarningDiagnostics === 40) {
        this.appendDiagnostic("warning", "Further proxy warnings are suppressed for this session.");
        return;
      }
    }
    if (level === "info") {
      if (this.proxyInfoDiagnostics >= 80) {
        return;
      }
      this.proxyInfoDiagnostics += 1;
      if (this.proxyInfoDiagnostics === 80) {
        this.appendDiagnostic("info", "Further proxy connection diagnostics are suppressed for this session.");
        return;
      }
    }
    this.appendDiagnostic(level, message);
  }

  private appendTerminal(stream: TerminalLine["stream"], text: string): void {
    this.emit({
      type: "terminal-output",
      line: {
        id: randomUUID(),
        at: new Date().toISOString(),
        stream,
        text
      }
    });
  }

  private emitError(message: string): void {
    this.emit({ type: "error", message: redactSecrets(message) });
  }

  private emit(event: ServiceEvent): void {
    this.events.emit("event", event);
  }

  private currentProcessRoutingIps(): Set<string> {
    return new Set(this.processRoutingIps.keys());
  }

  private currentProcessRoutingDomains(): Set<string> {
    return new Set([
      ...this.processRoutingHintDomains,
      ...this.processRoutingDomains.keys(),
      ...[...this.processRoutingSessionLeases.values()].map((lease) => lease.domain)
    ]);
  }

  private pruneExpiredProcessRoutingState(now = Date.now()): boolean {
    const expiresBefore = now - this.currentProcessRoutingTtlMs();
    const nextIps = new Map([...this.processRoutingIps].filter((entry) => entry[1] >= expiresBefore));
    const nextDomains = new Map([...this.processRoutingDomains].filter((entry) => entry[1] > now));
    const activeProfileCoveredAddresses = new Map(
      [...this.processRoutingProfileCoveredAddresses].filter((entry) => entry[1] > now)
    );
    const nextSignature = buildProcessRouteSignature(
      nextIps.keys(),
      [
        ...this.processRoutingHintDomains,
        ...nextDomains.keys(),
        ...[...this.processRoutingSessionLeases.values()].map((lease) => lease.domain)
      ]
    );
    const changed = nextSignature !== this.processRoutingLastSignature;
    this.processRoutingIps = nextIps;
    this.processRoutingDomains = nextDomains;
    this.processRoutingProfileCoveredAddresses = activeProfileCoveredAddresses;
    this.processRoutingLastSignature = nextSignature;
    return changed;
  }

  private resetProcessRoutingIpsForTargets(processNames: Set<string>): void {
    const targetSignature = [...processNames].sort().join(",");
    if (targetSignature === this.processRoutingTargetSignature) {
      return;
    }
    this.processRoutingTargetSignature = targetSignature;
    this.processRoutingIps.clear();
    this.processRoutingHintDomains.clear();
    this.processRoutingDomains.clear();
    this.processRoutingDnsLookupAt.clear();
    for (const domain of processRouteDomainHints(processNames)) {
      this.processRoutingHintDomains.add(domain);
    }
    this.processRoutingDnsLookupFailures.clear();
    this.processRoutingProfileCoveredAddresses.clear();
    this.processRoutingSessionLeases.clear();
    this.processRoutingLastSignature = "";
    this.processRoutingAppliedSignature = "";
    this.processRoutingApplyPending = false;
    this.processRoutingLastMatchedConnections = 0;
    this.processRoutingWarningEmitted = false;
    this.processRoutingDnsWarningEmitted = false;
  }
}

function buildLocalRoutingContext(request: ConnectRequest): LocalRoutingContext {
  return {
    routingMode: request.routingMode,
    routingRules: request.routingRules,
    routingProxyDomains: request.routingProxyDomains,
    routingDirectDomains: request.routingDirectDomains,
    protectedEndpoint: { host: request.config.host, port: request.config.port }
  };
}

function requiredSecret(secret: string | undefined, label: string): string {
  if (!secret) {
    throw new Error(`${label} is unavailable.`);
  }
  return secret;
}

/** Clears what describes a session, for a status that no longer has one. */
const CLEARED_SESSION_STATUS = {
  activeConfigId: undefined,
  activeConfigName: undefined,
  activeTarget: undefined,
  observedHostKeyFingerprint: undefined,
  connectedAt: undefined,
  reconnectAttempt: 0,
  realTunnelAvailable: false
} as const satisfies Partial<RuntimeStatus>;

/** `host:port`, with an IPv6 literal in brackets so the port stays unambiguous. */
export function formatServiceTarget(host: string, port: number): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]:${port}` : `${host}:${port}`;
}

export function sameLocalProxy(left: LocalProxyEndpoint | undefined, right: LocalProxyEndpoint | undefined): boolean {
  return left?.host === right?.host && left?.httpPort === right?.httpPort && left?.socksPort === right?.socksPort;
}

function redactSecrets(message: string): string {
  return message.replace(/(password|passphrase|private key)\s*[:=]\s*\S+/giu, "$1=<redacted>");
}

type ConnectTrigger = "user" | "reconnect";

type TunnelWaiter = {
  resolve: (client: SshLiveClient) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
  detachAbort?: () => void;
};

function abortedTunnelWaitError(): Error {
  const error = new Error("Proxy connection closed while waiting for the SSH tunnel.");
  error.name = "AbortError";
  return error;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isAuthenticationFailure(error: unknown): boolean {
  if (error instanceof SshAuthenticationError) {
    return true;
  }
  return /SSH authentication failed|password auth rejected|private-key auth rejected|no auth method available/i.test(errorMessage(error));
}

/**
 * Name resolution failed, as opposed to the host refusing or timing out. Node
 * reports these with a getaddrinfo syscall and one of the EAI_* codes, which
 * are also what a resolver returns for the first seconds after a resume.
 */
function isDnsFailure(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }
  const { code, syscall } = error as Error & { code?: string; syscall?: string };
  if (syscall === "getaddrinfo") {
    return true;
  }
  return code !== undefined && /^(ENOTFOUND|EAI_AGAIN|EAI_FAIL|EAI_NONAME|EAI_NODATA|ENODATA|ESERVFAIL)$/.test(code);
}

function isNonRetryableConnectError(error: unknown): boolean {
  if (error instanceof SshAuthenticationError) {
    return true;
  }
  const message = error instanceof Error ? error.message : String(error);
  return /SSH authentication failed|SSH private key|password auth rejected|private-key auth rejected|no auth method available|is unavailable|host key|fingerprint|not trusted/i.test(
    message
  );
}

export function describeUnsupportedSelectedRouting(request: ConnectRequest, platform: NodeJS.Platform = process.platform): string | undefined {
  void request;
  void platform;
  return undefined;
}

export function buildSelectedRulesWithProcessIps(
  rules: RoutingRule[],
  processIps: ReadonlySet<string>,
  processDomains: ReadonlySet<string> = new Set()
): RoutingRule[] {
  if (processIps.size === 0 && processDomains.size === 0) {
    return rules;
  }

  const existingIpRules = new Set(
    rules.filter((rule) => rule.enabled && rule.type === "ip").map((rule) => normalizeRuleValue("ip", rule.value).toLowerCase())
  );
  const existingDomainRules = new Set(
    rules.filter((rule) => rule.enabled && rule.type === "domain").map((rule) => normalizeRuleValue("domain", rule.value))
  );
  const now = new Date(0).toISOString();
  const dynamicDomainRules = [...processDomains]
    .map((domain) => normalizeRuleValue("domain", domain))
    .filter((domain) => validateRoutingRuleValue("domain", domain).ok)
    .filter((domain) => !existingDomainRules.has(domain))
    .sort()
    .map<RoutingRule>((domain) => ({
      id: `process-domain:${domain}`,
      type: "domain",
      value: domain,
      enabled: true,
      createdAt: now,
      updatedAt: now
    }));
  const dynamicIpRules = [...processIps]
    .map((ip) => ip.trim())
    .filter((ip) => validateRoutingRuleValue("ip", ip).ok)
    .filter((ip) => !existingIpRules.has(ip.toLowerCase()))
    .sort()
    .map<RoutingRule>((ip) => ({
      id: `process-ip:${ip}`,
      type: "ip",
      value: ip,
      enabled: true,
      createdAt: now,
      updatedAt: now
    }));

  return [...rules, ...dynamicDomainRules, ...dynamicIpRules];
}

export const MAX_LEARNED_PROCESS_ROUTE_IPS = 2048;
export const MAX_LEARNED_PROCESS_ROUTE_DOMAINS = 512;

export function recordBoundedProcessRouteIp(
  entries: Map<string, number>,
  ip: string,
  observedAt: number,
  maximum = MAX_LEARNED_PROCESS_ROUTE_IPS
): void {
  if (maximum <= 0) {
    entries.clear();
    return;
  }
  // Refresh insertion order so actively used destinations survive eviction.
  entries.delete(ip);
  entries.set(ip, observedAt);
  while (entries.size > maximum) {
    const oldest = entries.keys().next().value as string | undefined;
    if (!oldest) {
      break;
    }
    entries.delete(oldest);
  }
}

export function recordBoundedProcessRouteDomain(
  entries: Map<string, number>,
  domain: string,
  expiresAt: number,
  maximum = MAX_LEARNED_PROCESS_ROUTE_DOMAINS
): void {
  const normalized = normalizeRuleValue("domain", domain).replace(/\.$/u, "");
  if (normalized.startsWith("*.") || !validateRoutingRuleValue("domain", normalized).ok) {
    return;
  }
  if (maximum <= 0) {
    entries.clear();
    return;
  }
  entries.delete(normalized);
  entries.set(normalized, expiresAt);
  while (entries.size > maximum) {
    const oldest = entries.keys().next().value as string | undefined;
    if (!oldest) {
      break;
    }
    entries.delete(oldest);
  }
}

export function buildProcessRouteSignature(processIps: Iterable<string>, processDomains: Iterable<string>): string {
  return [
    `ips:${[...processIps].sort().join(",")}`,
    `domains:${[...processDomains].sort().join(",")}`
  ].join("|");
}

function supportsDynamicProcessRouting(request: ConnectRequest, platform: NodeJS.Platform = process.platform): boolean {
  return platform === "win32" && request.routingMode === "selected-rules" && enabledProcessRuleNames(request.routingRules).size > 0;
}

function enabledProcessRuleNames(rules: RoutingRule[]): Set<string> {
  return new Set(
    rules
      .filter((rule) => rule.enabled && rule.type === "process.name")
      .filter((rule) => validateRoutingRuleValue(rule.type, rule.value).ok)
      .map((rule) => normalizeWindowsProcessName(normalizeRuleValue("process.name", rule.value)))
      .filter(Boolean)
  );
}
