import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { access, chmod, mkdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { parseEndpoint } from "../core/network/socks5-check.js";
import { probeTunnelEndpoint } from "../core/network/tunnel-probe.js";
import { RoutingMatcher, type RoutingMatcherSummary } from "../core/routing/routing-matcher.js";
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
import { WindowsSystemProxyManager, type SystemProxyApplyResult } from "../core/network/windows-system-proxy.js";
import { Socks5Proxy } from "../core/network/socks5-proxy.js";
import { openSocks5UpstreamChannel } from "../core/network/socks5-upstream.js";
import { LocalRoutingEnforcer, RoutingDecisionLog, type LocalRoutingContext } from "./local-routing-enforcement.js";
import { NativeDataplaneController, type DataplaneController } from "./native-dataplane.js";
import { errorText, resolveProtectedAddresses, startDataplaneWithRetry, TUN_ADAPTER_NAME, TUN_ROUTING_JOURNAL_FILE } from "./tun-routing.js";
import { NativeProcessAttribution, type ProcessAttribution } from "./process-attribution.js";
import { buildXrayConfig } from "../core/proxy/xray-config.js";
import type { ServiceEvent } from "../shared/ipc.js";
import type { DiagnosticsEntry, ProxyConnectRequest, RoutingRule, RoutingUpdateRequest, RuntimeStatus, TunnelCheckResult } from "../shared/types.js";
import { normalizeRuleValue, validateRoutingRuleValue } from "../shared/validation.js";
import {
  buildProcessRouteSignature,
  buildSelectedRulesWithProcessIps,
  recordBoundedProcessRouteDomain,
  recordBoundedProcessRouteIp
} from "./live-ssh-service.js";
import { reserveDistinctLocalTcpPorts, terminateProcess, waitForProcessStartup, type XrayProcess } from "./xray/process-utils.js";

export interface XrayServiceBridgeOptions {
  pacDirectory?: string;
  runtimeDirectory: string;
  executablePath?: string;
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
  /** Injection seam for tests; defaults to a DNS lookup of the profile host. */
  protectedAddressResolver?: (host: string) => Promise<string[]>;
}

const PROCESS_ROUTE_TTL_MS = 5 * 60 * 1000;
const PROCESS_ROUTE_REFRESH_INTERVAL_MS = 10 * 1000;
const PROCESS_ROUTE_DISCOVERY_DELAYS_MS = [1_000, 2_000, 4_000, 8_000] as const;
const PROCESS_ROUTE_DNS_REFRESH_MS = 5 * 60 * 1000;
const PROCESS_ROUTE_DNS_MIN_REFRESH_MS = 1_000;
const PROCESS_ROUTE_DNS_RETRY_BASE_MS = 10_000;
const MAX_LOCAL_PROXY_DIAGNOSTICS = 80;
/**
 * Xray writes one `[Info] ... accepted ...` line per connection, and a client
 * like Telegram opens hundreds in a minute. A single shared budget therefore
 * spent itself on chatter within seconds and then detached the stream
 * altogether, so the `[Warning]` explaining why the outbound was failing never
 * reached the log - the one line anyone actually needed.
 *
 * Warnings and errors get their own budget that the chatter cannot touch.
 */
const MAX_XRAY_IMPORTANT_LOG_LINES = 200;
const MAX_XRAY_ROUTINE_LOG_LINES = 40;
const MAX_XRAY_PROCESS_LOG_CHUNK_CHARACTERS = 64 * 1024;
const MAX_XRAY_PROCESS_LOG_LINE_CHARACTERS = 4096;

export class XrayServiceBridge {
  private readonly events = new EventEmitter();
  private readonly systemProxy: WindowsSystemProxyManager;
  private readonly processRoutingRefreshIntervalMs: () => number;
  private readonly processConnectionsProvider: (processNames: Iterable<string>) => Promise<WindowsProcessConnection[]>;
  private readonly processDnsEntriesProvider: (addresses: Iterable<string>) => Promise<WindowsDnsCacheEntry[]>;
  private readonly runtimeDirectory: string;
  private readonly configPath: string;
  private readonly startupConfigCleanup: Promise<void>;
  private readonly executablePath: string | undefined;
  private status: RuntimeStatus;
  private process: XrayProcess | undefined;
  private socksEndpoint: { host: string; port: number } | undefined;
  private httpEndpoint: { host: string; port: number } | undefined;
  private lastRequest: ProxyConnectRequest | undefined;
  private disconnectRequested = false;
  private reconnectTimer: NodeJS.Timeout | undefined;
  private startupAbortController: AbortController | undefined;
  private routingRules: RoutingRule[] = [];
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
  private localRoutingContext: LocalRoutingContext | undefined;
  private localProxy: Socks5Proxy | undefined;
  private proxyDiagnostics = 0;
  /**
   * Both directions of every routing decision, so the log can tell "no rule
   * matched" apart from "the rules matched and the tunnel behind them is
   * dead". See {@link RoutingDecisionLog}.
   */
  private readonly routingDecisions = new RoutingDecisionLog((message) => this.appendDiagnostic("info", message));
  private importantProcessLogLines = 0;
  private routineProcessLogLines = 0;
  private readonly processLogDrainers = new WeakMap<XrayProcess, () => void>();
  private mutationTail: Promise<void> = Promise.resolve();
  private lifecycleGeneration = 0;
  private routingGeneration = 0;
  private disposed = false;

  constructor(initialStatus: RuntimeStatus, options: XrayServiceBridgeOptions) {
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
          onDiagnostic: (level, message) => this.appendDiagnostic(level === "error" ? "error" : level, message)
        })
      : undefined);
    this.dataplaneJournalPath = path.join(options.userDataDirectory ?? options.pacDirectory ?? options.runtimeDirectory, TUN_ROUTING_JOURNAL_FILE);
    this.protectedAddressResolver = options.protectedAddressResolver ?? resolveProtectedAddresses;
    this.localRoutingEnforcer = new LocalRoutingEnforcer(this.processAttribution);
    this.runtimeDirectory = options.runtimeDirectory;
    this.configPath = path.join(this.runtimeDirectory, "xray-config.json");
    this.startupConfigCleanup = rm(this.configPath, { force: true }).catch(() => undefined);
    this.executablePath = options.executablePath;
    this.status = {
      ...initialStatus,
      state: "Disconnected",
      transport: "xray",
      realTunnelAvailable: false,
      message: "Xray transport is ready."
    };
  }

  onEvent(listener: (event: ServiceEvent) => void): () => void {
    this.events.on("event", listener);
    return () => this.events.off("event", listener);
  }

  getStatus(): RuntimeStatus {
    return structuredClone(this.status);
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
          `Routing rules changed while Xray transport is connected: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}. Re-applying routing.`
        );
        await this.applySystemRouting(request, socksEndpoint);
        return;
      }
      this.appendDiagnostic(
        "info",
        `Routing rules prepared for Xray transport: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`
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
        this.appendDiagnostic(
          "info",
          `Routing mode changed while Xray transport is connected: mode=${update.routingMode}, enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}. Re-applying routing without Xray restart.`
        );
        await this.applySystemRouting(request, socksEndpoint);
        return;
      }
      this.appendDiagnostic(
        "info",
        `Routing prepared for Xray transport: mode=${update.routingMode}, enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`
      );
    });
  }

  connect(request: ProxyConnectRequest): Promise<void> {
    if (this.disposed) {
      return Promise.reject(new Error("Xray service has been disposed."));
    }
    this.clearReconnectTimer();
    this.cancelProcessStartup();
    this.lastRequest = request;
    this.routingRules = request.routingRules;
    this.routingGeneration += 1;
    this.disconnectRequested = false;
    const generation = ++this.lifecycleGeneration;
    this.setStatus({
      state: "Connecting",
      activeConfigId: request.profile.id,
      connectedAt: undefined,
      realTunnelAvailable: false,
      message: `Starting ${request.profile.protocol.toUpperCase()} profile ${request.profile.name}.`
    });
    return this.enqueueMutation(() => this.connectInternal(request, generation));
  }

  private async connectInternal(request: ProxyConnectRequest, generation: number): Promise<void> {
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    this.importantProcessLogLines = 0;
    this.routineProcessLogLines = 0;
    // Both budgets are per connection attempt. Left unreset, a long-lived
    // process went permanently silent after its first busy session.
    this.proxyDiagnostics = 0;
    this.routingDecisions.reset();
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
    this.processRoutingWarningEmitted = false;
    this.processRoutingDnsWarningEmitted = false;
    await this.stopRouting();
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    await this.stopXrayProcess(this.process);
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    this.appendDiagnostic(
      "info",
      `Xray connect requested for ${request.profile.protocol.toUpperCase()} ${request.profile.host}:${request.profile.port}, transport=${request.profile.transport}, security=${request.profile.security}, routing=${request.routingMode}.`
    );

    let acquiredProcess: XrayProcess | undefined;
    try {
      const executablePath = await this.requireExecutablePath();
      if (!this.isCurrentLifecycle(generation)) {
        return;
      }
      const [socksEndpoint, httpEndpoint] = await reserveDistinctLocalTcpPorts(2);
      if (!socksEndpoint || !httpEndpoint) {
        throw new Error("Unable to reserve distinct Xray listener ports.");
      }
      if (!this.isCurrentLifecycle(generation)) {
        return;
      }
      await this.writeRuntimeConfig(
        buildXrayConfig({
          rawUri: request.secrets.rawUri,
          socksHost: socksEndpoint.host,
          socksPort: socksEndpoint.port,
          httpHost: httpEndpoint.host,
          httpPort: httpEndpoint.port
        })
      );
      if (!this.isCurrentLifecycle(generation)) {
        await this.removeRuntimeConfig();
        return;
      }
      const processHandle = spawn(executablePath, ["run", "-config", this.configPath], {
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true
      });
      acquiredProcess = processHandle;
      this.process = processHandle;
      this.attachProcessLogging(processHandle, generation);
      processHandle.on("error", (error) => this.handleXrayFailure(processHandle, generation, error));
      processHandle.once("close", (code, signal) => {
        this.handleXrayClose(processHandle, generation, code, signal);
      });
      const startupAbortController = new AbortController();
      this.startupAbortController = startupAbortController;
      try {
        await waitForProcessStartup(processHandle, [socksEndpoint, httpEndpoint], {
          signal: startupAbortController.signal
        });
      } finally {
        if (this.startupAbortController === startupAbortController) {
          this.startupAbortController = undefined;
        }
      }
      if (!this.isCurrentLifecycle(generation) || this.process !== processHandle) {
        await this.cleanupProcessResources(processHandle);
        return;
      }
      this.socksEndpoint = socksEndpoint;
      this.httpEndpoint = httpEndpoint;
      const effectiveRequest = this.lastRequest ?? request;
      await this.applySystemRouting(effectiveRequest, socksEndpoint);
      if (!this.isCurrentLifecycle(generation) || this.process !== processHandle) {
        await this.cleanupProcessResources(processHandle);
        return;
      }
      this.setStatus({
        state: "Connected",
        activeConfigId: effectiveRequest.profile.id,
        connectedAt: new Date().toISOString(),
        reconnectAttempt: 0,
        realTunnelAvailable: true,
        message: `Connected to ${effectiveRequest.profile.name}. Xray HTTP proxy ${httpEndpoint.host}:${httpEndpoint.port} and SOCKS proxy ${socksEndpoint.host}:${socksEndpoint.port} are live.`
      });
      this.appendDiagnostic(
        "info",
        `Xray runtime started for ${effectiveRequest.profile.protocol.toUpperCase()} ${effectiveRequest.profile.host}:${effectiveRequest.profile.port}.`
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await this.cleanupProcessResources(acquiredProcess);
      if (!this.isCurrentLifecycle(generation)) {
        return;
      }
      this.setStatus({
        state: "Error",
        activeConfigId: request.profile.id,
        realTunnelAvailable: false,
        message
      });
      this.appendDiagnostic("error", message);
    }
  }

  disconnect(): Promise<void> {
    if (this.disposed) {
      return this.mutationTail;
    }
    this.disconnectRequested = true;
    this.clearReconnectTimer();
    this.cancelProcessStartup();
    const generation = ++this.lifecycleGeneration;
    this.setStatus({
      state: "Disconnecting",
      realTunnelAvailable: false,
      message: "Disconnecting Xray transport."
    });
    // Only the tunnel comes down here. The dataplane controller and the
    // attribution helper survive: disposing them is permanent, and doing it on
    // an ordinary disconnect left every later connect reporting "the dataplane
    // controller is disposed" and quietly falling back to the proxy path, where
    // domain rules keep working and process rules do not.
    return this.enqueueMutation(() => this.disconnectInternal(generation));
  }

  private async disconnectInternal(generation: number): Promise<void> {
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    const processHandle = this.process;
    this.process = undefined;
    await this.stopRouting();
    await this.stopXrayProcess(processHandle);
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    this.setStatus({
      state: "Disconnected",
      activeConfigId: undefined,
      connectedAt: undefined,
      reconnectAttempt: 0,
      realTunnelAvailable: false,
      message: "Disconnected."
    });
    this.appendDiagnostic("info", "Xray transport disconnected.");
  }

  async checkTunnel(endpoint: string): Promise<TunnelCheckResult> {
    const at = new Date().toISOString();
    if (!this.socksEndpoint || this.status.state !== "Connected") {
      const result = { endpoint, ok: false, at, message: "Xray transport is not connected." };
      this.appendDiagnostic("warning", `Tunnel check skipped for ${endpoint}: Xray transport is not connected.`);
      this.emit({ type: "tunnel-check-result", result });
      return result;
    }

    // Captured before the probe: the property can be replaced by a concurrent
    // reconnect, and a check must report on the tunnel it started against.
    const socksEndpoint = this.socksEndpoint;
    try {
      this.appendDiagnostic("info", `Xray tunnel check requested for ${endpoint}.`);
      const startedAt = Date.now();
      const target = parseEndpoint(endpoint);
      // Not just the SOCKS reply: Xray answers that as soon as it has chosen an
      // outbound, so a dead VMess outbound used to pass this check while every
      // real connection through it hung.
      const probe = await probeTunnelEndpoint(
        (signal) => openSocks5UpstreamChannel(socksEndpoint, target, { signal }),
        target
      );
      const result = {
        endpoint,
        ok: true,
        at,
        message: `Tunnel check succeeded for ${endpoint} in ${Date.now() - startedAt} ms: ${probe.detail}.`
      };
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
      this.appendDiagnostic("warning", `Xray tunnel check failed for ${endpoint}: ${result.message}`);
      this.emit({ type: "tunnel-check-result", result });
      return result;
    }
  }

  async openTerminal(): Promise<void> {
    this.emitError("SSH terminal is available only for SSH transport.");
  }

  async closeTerminal(): Promise<void> {
    return Promise.resolve();
  }

  async terminalInput(input: string): Promise<void> {
    void input;
    this.emitError("SSH terminal is available only for SSH transport.");
  }

  dispose(): Promise<void> {
    if (this.disposed) {
      return this.mutationTail;
    }
    this.disposed = true;
    this.disconnectRequested = true;
    this.clearReconnectTimer();
    this.cancelProcessStartup();
    const generation = ++this.lifecycleGeneration;
    this.setStatus({
      state: "Disconnecting",
      realTunnelAvailable: false,
      message: "Stopping Xray service."
    });
    return this.enqueueMutation(async () => {
      await this.disconnectInternal(generation);
      // An adapter left up on quit would keep capture routes pointing at a
      // process that no longer exists.
      await this.dataplane?.dispose().catch(() => undefined);
      await this.processAttribution?.dispose().catch(() => undefined);
    });
  }

  private async requireExecutablePath(): Promise<string> {
    const executablePath = this.executablePath;
    if (!executablePath) {
      throw new Error("Xray runtime is not configured. Set SHADOW_SSH_XRAY_PATH or bundle resources/xray/<platform>/<arch>/xray.");
    }
    try {
      await access(executablePath);
      return executablePath;
    } catch {
      throw new Error(`Xray runtime was not found at ${executablePath}.`);
    }
  }

  private handleXrayClose(
    processHandle: XrayProcess,
    generation: number,
    code: number | null,
    signal: NodeJS.Signals | null
  ): void {
    if (this.process !== processHandle || !this.isCurrentLifecycle(generation)) {
      return;
    }
    const reason = `Xray runtime exited${code === null ? "" : ` with code ${code}`}${signal ? ` signal ${signal}` : ""}.`;
    this.handleXrayFailure(processHandle, generation, new Error(reason));
  }

  private handleXrayFailure(processHandle: XrayProcess, generation: number, error: Error): void {
    if (this.process !== processHandle || !this.isCurrentLifecycle(generation)) {
      return;
    }
    const failureGeneration = ++this.lifecycleGeneration;
    this.process = undefined;
    this.socksEndpoint = undefined;
    this.httpEndpoint = undefined;
    this.clearReconnectTimer();
    this.setStatus({
      state: "Error",
      realTunnelAvailable: false,
      message: error.message
    });
    this.appendDiagnostic("error", error.message);
    void this.enqueueMutation(async () => {
      await this.stopRouting();
      await this.stopXrayProcess(processHandle);
      if (!this.isCurrentLifecycle(failureGeneration) || this.disconnectRequested) {
        return;
      }
      this.scheduleReconnect(error.message, failureGeneration);
    });
  }

  private scheduleReconnect(reason: string, generation: number): void {
    if (this.disposed || !this.isCurrentLifecycle(generation) || this.disconnectRequested || !this.lastRequest || this.reconnectTimer) {
      return;
    }
    const attempt = this.status.reconnectAttempt + 1;
    const baseDelayMs = Math.min(5 * 60 * 1000, 1000 * 2 ** Math.min(attempt - 1, 8));
    const jitterMs = Math.floor(Math.random() * Math.min(5000, baseDelayMs * 0.2));
    const delayMs = baseDelayMs + jitterMs;
    this.setStatus({
      state: "Reconnecting",
      reconnectAttempt: attempt,
      realTunnelAvailable: false,
      message: `Restarting Xray transport after failure: ${reason}`
    });
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      if (this.lastRequest && this.isCurrentLifecycle(generation) && !this.disconnectRequested) {
        void this.connect(this.lastRequest);
      }
    }, delayMs);
    this.reconnectTimer.unref();
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
  }

  private cancelProcessStartup(): void {
    this.startupAbortController?.abort();
    this.startupAbortController = undefined;
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

  /**
   * Puts the TUN adapter in front of the machine's traffic.
   *
   * Unlike the SSH transport, the helper is pointed straight at Xray's own
   * SOCKS inbound: it speaks `UDP ASSOCIATE`, so a selected application's
   * datagrams - Discord voice, QUIC - are carried rather than dropped, and no
   * listener of ours needs to sit in between.
   *
   * Returns false, having changed nothing, when the adapter cannot be used.
   */
  private async applyTunRouting(
    request: ProxyConnectRequest,
    socksEndpoint: { host: string; port: number },
    generation: number
  ): Promise<boolean> {
    const dataplane = this.dataplane;
    if (!dataplane || request.tunDataplaneEnabled !== true || process.platform !== "win32") {
      return false;
    }

    const availability = await dataplane.probe();
    if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
      return false;
    }
    if (!availability.available) {
      this.appendDiagnostic(
        "warning",
        `TUN routing is unavailable, continuing on the Windows proxy path: ${availability.reason ?? "unknown reason"}`
      );
      return false;
    }

    // Xray opens its own outbound socket, so this process cannot observe the
    // address in use; every address the name resolves to is excluded instead.
    const protectedAddresses = await this.protectedAddressResolver(request.profile.host);
    if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
      return false;
    }
    if (protectedAddresses.length === 0) {
      this.appendDiagnostic(
        "warning",
        `TUN routing is unavailable: no address could be resolved for ${request.profile.host} to keep off the adapter. Continuing on the Windows proxy path.`
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
        protectedPort: request.profile.port,
        udpSupported: true,
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

    // Our own listener and the Windows proxy setting are both redundant now
    // and would apply the rules a second time on a path the adapter already
    // decided.
    await this.stopLocalProxy();
    try {
      await this.systemProxy.restore();
    } catch (error) {
      this.appendDiagnostic(
        "warning",
        `Windows proxy restore after enabling TUN routing failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    this.tunRoutingActive = true;
    this.localRoutingContext = undefined;
    this.clearProcessRoutingState();
    this.appendDiagnostic(
      "info",
      "TUN routing is active: every selected application's traffic is captured at the adapter, including UDP."
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
  }

  private async stopRouting(): Promise<void> {
    this.stopProcessRoutingMonitor();
    // The adapter owns the routing table, so it comes down before anything
    // else: leaving capture routes pointing at a dead adapter takes the
    // machine offline.
    await this.stopTunRouting();
    await this.stopLocalProxy();
    this.clearProcessRoutingState();
    try {
      await this.systemProxy.restore();
    } catch (error) {
      this.appendDiagnostic("warning", `Windows proxy restore failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    this.socksEndpoint = undefined;
    this.httpEndpoint = undefined;
  }

  private async stopXrayProcess(processHandle: XrayProcess | undefined): Promise<void> {
    try {
      if (processHandle) {
        this.stopParsingProcessLogs(processHandle);
        if (this.process === processHandle) {
          this.process = undefined;
        }
        await terminateProcess(processHandle);
      }
    } catch (error) {
      this.appendDiagnostic("warning", `Xray process cleanup failed: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      await this.removeRuntimeConfig();
    }
  }

  private async writeRuntimeConfig(contents: string): Promise<void> {
    await this.startupConfigCleanup;
    await mkdir(this.runtimeDirectory, { recursive: true, mode: 0o700 });
    await chmod(this.runtimeDirectory, 0o700).catch(() => undefined);
    const temporaryPath = `${this.configPath}.${process.pid}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporaryPath, contents, { encoding: "utf8", mode: 0o600, flag: "wx" });
      await rm(this.configPath, { force: true });
      await rename(temporaryPath, this.configPath);
      await chmod(this.configPath, 0o600).catch(() => undefined);
    } catch (error) {
      await rm(temporaryPath, { force: true }).catch(() => undefined);
      throw error;
    }
  }

  private async removeRuntimeConfig(): Promise<void> {
    await this.startupConfigCleanup;
    await rm(this.configPath, { force: true }).catch(() => undefined);
  }

  private async cleanupProcessResources(processHandle: XrayProcess | undefined): Promise<void> {
    if (this.process === processHandle) {
      this.process = undefined;
    }
    await this.stopRouting();
    await this.stopXrayProcess(processHandle);
  }

  private appendProcessLogFor(
    processHandle: XrayProcess,
    generation: number,
    level: DiagnosticsEntry["level"],
    chunk: string
  ): boolean {
    if (this.process === processHandle && this.isCurrentLifecycle(generation)) {
      return this.appendProcessLog(level, chunk);
    }
    return false;
  }

  private attachProcessLogging(processHandle: XrayProcess, generation: number): void {
    processHandle.stdout.setEncoding("utf8");
    processHandle.stderr.setEncoding("utf8");
    const stdoutLog = (data: string): void => {
      if (!this.appendProcessLogFor(processHandle, generation, "info", data)) {
        this.stopParsingProcessLogs(processHandle);
      }
    };
    const stderrLog = (data: string): void => {
      if (!this.appendProcessLogFor(processHandle, generation, "warning", data)) {
        this.stopParsingProcessLogs(processHandle);
      }
    };
    const drainWithoutParsing = (): void => {
      processHandle.stdout.off("data", stdoutLog);
      processHandle.stderr.off("data", stderrLog);
      // Child stdio must remain flowing: pausing an unread pipe can eventually
      // block the Xray process. resume() discards future output in native stream
      // machinery without JS line parsing, UUIDs, IPC or renderer updates.
      processHandle.stdout.resume();
      processHandle.stderr.resume();
    };
    this.processLogDrainers.set(processHandle, drainWithoutParsing);
    processHandle.stdout.on("data", stdoutLog);
    processHandle.stderr.on("data", stderrLog);
  }

  private stopParsingProcessLogs(processHandle: XrayProcess): void {
    const drain = this.processLogDrainers.get(processHandle);
    if (!drain) {
      return;
    }
    this.processLogDrainers.delete(processHandle);
    drain();
  }

  private enqueueMutation(operation: () => Promise<void>): Promise<void> {
    const result = this.mutationTail.then(operation, operation);
    this.mutationTail = result.catch(() => undefined);
    return result;
  }

  private isCurrentLifecycle(generation: number): boolean {
    return generation === this.lifecycleGeneration;
  }

  private isCurrentMutation(lifecycleGeneration: number, routingGeneration: number): boolean {
    return !this.disposed && this.isCurrentLifecycle(lifecycleGeneration) && routingGeneration === this.routingGeneration;
  }

  private async applySystemRouting(request: ProxyConnectRequest, socksEndpoint: { host: string; port: number }): Promise<void> {
    this.stopProcessRoutingMonitor();
    const generation = this.processRoutingGeneration;
    const httpEndpoint = this.httpEndpoint ?? socksEndpoint;
    const summary = new RoutingMatcher(request.routingMode, request.routingRules).summary();
    const hasProcessRouting = supportsDynamicProcessRouting(request.routingMode, request.routingRules);

    // Process rules can only be honoured where the owning process is known, so
    // when the native helper can attribute connections we place our own
    // listener in front of Xray and decide there.
    const context: LocalRoutingContext = {
      routingMode: request.routingMode,
      routingRules: request.routingRules,
      routingProxyDomains: request.routingProxyDomains,
      routingDirectDomains: request.routingDirectDomains,
      // The SSH transport has always excluded its own server here. Xray did
      // not, so a rule broad enough to cover the profile's own host - a
      // `process.name` rule above all, which routes everything an application
      // sends - handed that connection back to Xray's inbound and asked it to
      // dial itself through itself.
      protectedEndpoint: { host: request.profile.host, port: request.profile.port }
    };
    // The adapter is tried first: it is the only path that holds a
    // `process.name` rule against an application that ignores the Windows
    // proxy setting, and the only one that can carry that application's UDP.
    if (await this.applyTunRouting(request, socksEndpoint, generation)) {
      return;
    }

    const enforceability = await this.localRoutingEnforcer.describeEnforceability(context);
    if (enforceability.enforceable) {
      if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
        return;
      }
      await this.applyLocallyEnforcedRouting(request, socksEndpoint, context, generation, summary);
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
    await this.stopLocalProxy();

    let literalIpSnapshotResult: SystemProxyApplyResult | undefined;
    let literalIpSnapshotError: unknown;
    let literalIpSnapshotFailed = false;
    let literalIpSnapshotSignature: string | undefined;
    if (hasProcessRouting) {
      await this.learnProcessRoutingIps(
        request.routingRules,
        request.routingDirectDomains,
        generation,
        async (signature) => {
          literalIpSnapshotSignature = signature;
          try {
            literalIpSnapshotResult = await this.publishProcessRoutingSnapshot(
              request,
              socksEndpoint,
              generation,
              signature
            );
          } catch (error) {
            literalIpSnapshotFailed = true;
            literalIpSnapshotError = error;
            this.processRoutingApplyPending = true;
          }
        }
      );
      if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
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
          socksHost: httpEndpoint.host,
          socksPort: httpEndpoint.port,
          proxyProtocol: "http",
          forcePacEndpointRotation: hasProcessRouting
        });
      } catch (error) {
        if (hasProcessRouting && generation === this.processRoutingGeneration && this.status.state === "Connected") {
          this.startProcessRoutingMonitor(request, socksEndpoint);
        }
        throw error;
      }
    }
    if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
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
      this.appendDiagnostic("info", "Proxy-all TCP routing uses the local Xray HTTP proxy through the Windows system proxy when running on Windows.");
      return;
    }
    this.appendDiagnostic(
      summary.enabledRules > 0 ? "info" : "warning",
      `Selected routing prepared for Xray transport: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}, matchedProcessConnections=${this.processRoutingLastMatchedConnections}, learnedProcessIps=${this.processRoutingIps.size}, learnedProcessDomains=${this.currentProcessRoutingDomains().size}.`
    );
  }

  /**
   * Routes all proxy-aware TCP through our own listener, which then evaluates
   * domain, IP and process rules per connection and forwards only matching
   * traffic into Xray's SOCKS inbound. Everything else leaves the machine
   * directly, so unselected applications are untouched.
   */
  private async applyLocallyEnforcedRouting(
    request: ProxyConnectRequest,
    xraySocksEndpoint: { host: string; port: number },
    context: LocalRoutingContext,
    generation: number,
    summary: RoutingMatcherSummary
  ): Promise<void> {
    this.clearProcessRoutingState();
    const endpoint = await this.startLocalProxy(xraySocksEndpoint, context, generation);
    if (!endpoint || generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
      return;
    }

    // The direct list is deliberately withheld from the PAC here: the PAC runs
    // before the listener and cannot see processes, so a direct-list entry
    // there would carve holes in a selected application's traffic. It is
    // applied per connection instead, after the process rule.
    const result = await this.systemProxy.apply({
      mode: "proxy-all",
      rules: request.routingRules,
      proxyDomains: request.routingProxyDomains,
      directDomains: [],
      socksHost: endpoint.host,
      socksPort: endpoint.port
    });
    if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
      return;
    }
    this.appendDiagnostic(result.applied ? "info" : "warning", result.message);
    this.appendDiagnostic(
      "info",
      `Selected routing is enforced locally with native process attribution: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}. Matching traffic is forwarded into Xray; unmatched traffic leaves the machine directly.`
    );
  }

  private async startLocalProxy(
    xraySocksEndpoint: { host: string; port: number },
    context: LocalRoutingContext,
    generation: number
  ): Promise<{ host: string; port: number } | undefined> {
    // Retiring any previous listener clears the routing context, so publish the
    // new one only afterwards: a connection accepted without a context cannot
    // be attributed and would bypass the rules entirely.
    await this.stopLocalProxy();
    this.localRoutingContext = context;
    const proxy = new Socks5Proxy({
      listenHost: "127.0.0.1",
      idleTimeoutMs: 5 * 60 * 1000,
      connectChannel: async (target, originator, signal) => {
        const context = this.localRoutingContext;
        if (!context) {
          return openSocks5UpstreamChannel(xraySocksEndpoint, target, { signal });
        }
        const { channel, decision } = await this.localRoutingEnforcer.openChannel(
          context,
          target,
          originator,
          () => openSocks5UpstreamChannel(xraySocksEndpoint, target, { signal }),
          signal
        );
        this.routingDecisions.record(target, decision);
        return channel;
      }
    });
    proxy.onEvent((event) => {
      if (generation !== this.processRoutingGeneration) {
        return;
      }
      if (event.type === "error") {
        this.appendBoundedProxyDiagnostic("warning", event.message);
      }
    });
    try {
      const endpoint = await proxy.start();
      this.localProxy = proxy;
      this.appendDiagnostic("info", `Local routing proxy is listening on ${endpoint.host}:${endpoint.port}.`);
      return endpoint;
    } catch (error) {
      await proxy.stop().catch(() => undefined);
      this.appendDiagnostic(
        "warning",
        `Local routing proxy failed to start: ${error instanceof Error ? error.message : String(error)}`
      );
      return undefined;
    }
  }

  private async stopLocalProxy(): Promise<void> {
    const proxy = this.localProxy;
    this.localProxy = undefined;
    this.localRoutingContext = undefined;
    await proxy?.stop().catch(() => undefined);
  }

  private startProcessRoutingMonitor(request: ProxyConnectRequest, socksEndpoint: { host: string; port: number }): void {
    this.stopProcessRoutingMonitor();
    if (!supportsDynamicProcessRouting(request.routingMode, request.routingRules)) {
      return;
    }

    const generation = this.processRoutingGeneration;
    this.processRoutingDiscoveryStep = 0;
    this.scheduleProcessRoutingRefresh(request, socksEndpoint, generation);
  }

  private scheduleProcessRoutingRefresh(
    request: ProxyConnectRequest,
    socksEndpoint: { host: string; port: number },
    generation: number
  ): void {
    if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
      return;
    }
    this.processRoutingMonitor = setTimeout(() => {
      this.processRoutingMonitor = undefined;
      if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
        return;
      }
      void this.enqueueMutation(() => this.refreshProcessRouting(request, socksEndpoint, generation))
        .catch((error: unknown) => {
          if (!this.processRoutingWarningEmitted) {
            this.processRoutingWarningEmitted = true;
            this.appendDiagnostic(
              "warning",
              `Process-name routing refresh failed for Xray transport: ${error instanceof Error ? error.message : String(error)}`
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
    request: ProxyConnectRequest,
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
    await this.learnProcessRoutingIps(
      request.routingRules,
      request.routingDirectDomains,
      generation,
      async (signature) => {
        literalIpSnapshotSignature = signature;
        try {
          literalIpSnapshotResult = await this.publishProcessRoutingSnapshot(
            request,
            socksEndpoint,
            generation,
            signature
          );
        } catch (error) {
          literalIpSnapshotFailed = true;
          literalIpSnapshotError = error;
          this.processRoutingApplyPending = true;
        }
      }
    );
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
        `Process-name literal-IP routing updated before DNS enrichment for Xray transport: matchedProcessConnections=${this.processRoutingLastMatchedConnections}, learnedProcessIps=${this.processRoutingIps.size}. ${literalIpSnapshotResult.message}`
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
      observedSignature
    );
    if (!result) {
      return;
    }
    this.appendDiagnostic(
      result.applied ? "info" : "warning",
      `Process-name routing updated for Xray transport: matchedProcessConnections=${this.processRoutingLastMatchedConnections}, learnedProcessIps=${this.processRoutingIps.size}, learnedProcessDomains=${this.currentProcessRoutingDomains().size}. ${result.message}`
    );
  }

  private async publishProcessRoutingSnapshot(
    request: ProxyConnectRequest,
    socksEndpoint: { host: string; port: number },
    generation: number,
    signature: string
  ): Promise<SystemProxyApplyResult | undefined> {
    if (
      generation !== this.processRoutingGeneration ||
      !this.isRoutingApplicable() ||
      signature !== this.processRoutingLastSignature
    ) {
      return undefined;
    }
    this.processRoutingApplyPending = true;
    const endpoint = this.httpEndpoint ?? socksEndpoint;
    const result = await this.systemProxy.apply({
      mode: request.routingMode,
      rules: buildSelectedRulesWithProcessIps(
        request.routingRules,
        this.currentProcessRoutingIps(),
        this.currentProcessRoutingDomains()
      ),
      proxyDomains: request.routingProxyDomains,
      directDomains: request.routingDirectDomains,
      socksHost: endpoint.host,
      socksPort: endpoint.port,
      proxyProtocol: "http",
      forcePacEndpointRotation: true
    });
    if (
      result.applied &&
      generation === this.processRoutingGeneration &&
      this.isRoutingApplicable() &&
      this.processRoutingLastSignature === signature
    ) {
      this.processRoutingAppliedSignature = signature;
      this.processRoutingApplyPending = false;
    }
    return result;
  }

  private async learnProcessRoutingIps(
    rules: RoutingRule[],
    directDomains: string[] = [],
    generation?: number,
    publishLiteralIpSnapshot?: (signature: string) => Promise<void>
  ): Promise<boolean> {
    if (!supportsDynamicProcessRouting("selected-rules", rules)) {
      return false;
    }
    if (generation !== undefined && generation !== this.processRoutingGeneration) {
      return false;
    }
    const directDomainSuffixes = normalizeProcessRouteDirectDomains(directDomains);
    const signatureBeforeLearning = this.processRoutingLastSignature;
    const literalIpsBeforeLearning = new Set(this.processRoutingIps.keys());

    try {
      const processNames = enabledProcessRuleNames(rules);
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

      // This first phase is useful only when PAC receives an IP literal. Keep
      // DNS enrichment mandatory below so hostname process routing is never
      // weakened by the fast path.
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
          const configuredDomainPatterns = rules
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
              `Process-name DNS enrichment failed for Xray transport; IP fallback remains active: ${error instanceof Error ? error.message : String(error)}`
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
      transport: "xray",
      platformTarget: this.status.platformTarget
    };
    this.emit({ type: "status-changed", status: this.getStatus() });
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

  private appendProcessLog(streamLevel: DiagnosticsEntry["level"], chunk: string): boolean {
    if (this.importantProcessLogLines >= MAX_XRAY_IMPORTANT_LOG_LINES) {
      return false;
    }
    const boundedChunk = chunk.length > MAX_XRAY_PROCESS_LOG_CHUNK_CHARACTERS
      ? chunk.slice(0, MAX_XRAY_PROCESS_LOG_CHUNK_CHARACTERS)
      : chunk;
    for (const entry of boundedChunk.split(/\r?\n/u)) {
      const line = entry.trim();
      if (!line) {
        continue;
      }
      const level = classifyXrayLogLevel(line, streamLevel);
      if (level === "info") {
        if (this.routineProcessLogLines >= MAX_XRAY_ROUTINE_LOG_LINES) {
          continue;
        }
        this.routineProcessLogLines += 1;
        if (this.routineProcessLogLines === MAX_XRAY_ROUTINE_LOG_LINES) {
          this.appendDiagnostic(
            "info",
            "Further Xray connection notices are suppressed for this session. Warnings and errors are still recorded."
          );
          continue;
        }
      } else {
        this.importantProcessLogLines += 1;
        if (this.importantProcessLogLines === MAX_XRAY_IMPORTANT_LOG_LINES) {
          this.appendDiagnostic("warning", "Further Xray warnings are suppressed for this session.");
          return false;
        }
      }
      const boundedLine = line.length > MAX_XRAY_PROCESS_LOG_LINE_CHARACTERS
        ? `${line.slice(0, MAX_XRAY_PROCESS_LOG_LINE_CHARACTERS)}…`
        : line;
      this.appendDiagnostic(level, `Xray: ${boundedLine}`);
    }
    return true;
  }

  /**
   * Per-connection routing decisions are useful for diagnosing a rule, but a
   * busy browser opens hundreds of sockets, so the stream is capped.
   */
  private appendBoundedProxyDiagnostic(level: DiagnosticsEntry["level"], message: string): void {
    if (this.proxyDiagnostics >= MAX_LOCAL_PROXY_DIAGNOSTICS) {
      return;
    }
    this.proxyDiagnostics += 1;
    if (this.proxyDiagnostics === MAX_LOCAL_PROXY_DIAGNOSTICS) {
      this.appendDiagnostic("info", "Further local routing diagnostics are suppressed for this session.");
      return;
    }
    this.appendDiagnostic(level, message);
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

  private isRoutingApplicable(): boolean {
    return this.status.state === "Connecting" || this.status.state === "Connected";
  }
}

function supportsDynamicProcessRouting(mode: string, rules: RoutingRule[], platform: NodeJS.Platform = process.platform): boolean {
  return platform === "win32" && mode === "selected-rules" && enabledProcessRuleNames(rules).size > 0;
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

function redactSecrets(message: string): string {
  return message.replace(/(password|passphrase|private key|proxy uri|uri)\s*[:=]\s*\S+/giu, "$1=<redacted>");
}

/**
 * Reads Xray's own severity marker, which is what separates a connection
 * notice from the failure that explains it. Xray writes both to stdout, so the
 * stream a line arrived on says nothing useful on its own.
 */
export function classifyXrayLogLevel(
  line: string,
  streamLevel: DiagnosticsEntry["level"]
): DiagnosticsEntry["level"] {
  if (/\[Error\]/u.test(line)) {
    return "error";
  }
  if (/\[Warning\]/u.test(line)) {
    return "warning";
  }
  if (/\[Info\]|\[Debug\]/u.test(line)) {
    return "info";
  }
  return streamLevel;
}
