import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { RoutingMatcher } from "../core/routing/routing-matcher.js";
import { Socks5Proxy } from "../core/network/socks5-proxy.js";
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
import { SshAuthenticationError, SshLiveClient, type SshLiveClientEvent } from "../core/ssh/live-client.js";
import type { ServiceEvent } from "../shared/ipc.js";
import type { ConnectRequest, DiagnosticsEntry, RoutingRule, RoutingUpdateRequest, RuntimeStatus, SshConfig, TerminalLine, TunnelCheckResult } from "../shared/types.js";
import { normalizeRuleValue, validateRoutingRuleValue } from "../shared/validation.js";
import type { ServiceBridge } from "./service-bridge.js";

export interface LiveSshServiceBridgeOptions {
  pacDirectory?: string;
  systemProxy?: WindowsSystemProxyManager;
  processRoutingRefreshIntervalMs?: () => number;
  processConnectionsProvider?: (processNames: Iterable<string>) => Promise<WindowsProcessConnection[]>;
  processDnsEntriesProvider?: (addresses: Iterable<string>) => Promise<WindowsDnsCacheEntry[]>;
}

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
  private lastRequest: ConnectRequest | undefined;
  private routingRules: RoutingRule[] = [];
  private socksProxy: Socks5Proxy | undefined;
  private socksEndpoint: { host: string; port: number } | undefined;
  private readonly systemProxy: WindowsSystemProxyManager;
  private readonly processRoutingRefreshIntervalMs: () => number;
  private readonly processConnectionsProvider: (processNames: Iterable<string>) => Promise<WindowsProcessConnection[]>;
  private readonly processDnsEntriesProvider: (addresses: Iterable<string>) => Promise<WindowsDnsCacheEntry[]>;
  private proxyInfoDiagnostics = 0;
  private proxyWarningDiagnostics = 0;
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
    this.status = {
      ...initialStatus,
      state: "Disconnected",
      transport: "live-ssh",
      realTunnelAvailable: false,
      message: "Live SSH service is ready."
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
      this.appendDiagnostic(
        "info",
        `Routing prepared for live SSH service: mode=${update.routingMode}, enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`
      );
    });
  }

  connect(request: ConnectRequest): Promise<void> {
    if (this.disposed) {
      return Promise.reject(new Error("Live SSH service has been disposed."));
    }
    this.clearReconnectTimer();
    this.lastRequest = request;
    this.disconnectRequested = false;
    this.routingRules = request.routingRules;
    this.routingGeneration += 1;
    const generation = ++this.lifecycleGeneration;
    this.setStatus({
      state: "Connecting",
      activeConfigId: request.config.id,
      message: `Connecting to ${request.config.host}:${request.config.port} over live SSH.`,
      connectedAt: undefined,
      realTunnelAvailable: false
    });
    return this.enqueueMutation(() => this.connectInternal(request, generation));
  }

  private async connectInternal(request: ConnectRequest, generation: number): Promise<void> {
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    this.proxyInfoDiagnostics = 0;
    this.proxyWarningDiagnostics = 0;
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
    this.shellOpen = false;
    await this.stopRouting();
    if (!this.isCurrentLifecycle(generation)) {
      return;
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
      `Connect requested for ${request.config.username}@${request.config.host}:${request.config.port}, auth=${request.config.authType}, routing=${request.routingMode}, privateKey=${Boolean(request.secrets?.privateKey)}, passphraseProvided=${Boolean(request.secrets?.privateKeyPassphrase)}.`
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
      return;
    }

    let acquiredClient: SshLiveClient | undefined;
    let acquiredProxy: Socks5Proxy | undefined;
    try {
      const client = await SshLiveClient.connect({
        host: request.config.host,
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
      });
      acquiredClient = client;
      if (!this.isCurrentLifecycle(generation)) {
        await this.disconnectClient(client, "SSH connection was superseded.");
        return;
      }
      this.client = client;
      client.onEvent((event) => this.handleClientEvent(client, generation, event));
      const { endpoint: socksEndpoint, proxy } = await this.startSocksProxy(client, generation);
      acquiredProxy = proxy;
      if (!this.isCurrentLifecycle(generation) || this.client !== client) {
        await this.cleanupClientResources(client, proxy, "SSH connection was superseded.");
        return;
      }
      this.socksProxy = proxy;
      this.socksEndpoint = socksEndpoint;
      const effectiveRequest = this.lastRequest ?? request;
      await this.applySystemRouting(effectiveRequest, socksEndpoint, true);
      if (!this.isCurrentLifecycle(generation) || this.client !== client) {
        await this.cleanupClientResources(client, proxy, "SSH connection was superseded.");
        return;
      }
      this.setStatus({
        state: "Connected",
        activeConfigId: effectiveRequest.config.id,
        connectedAt: new Date().toISOString(),
        reconnectAttempt: 0,
        realTunnelAvailable: true,
        message: `Connected to ${effectiveRequest.config.name}. HTTP/SOCKS proxy ${socksEndpoint.host}:${socksEndpoint.port}, direct-tcpip, and shell channels are live.`
      });
      this.appendDiagnostic(
        "info",
        `SSH session established for ${effectiveRequest.config.username}@${effectiveRequest.config.host}:${effectiveRequest.config.port}.`
      );
    } catch (error) {
      await this.cleanupClientResources(acquiredClient, acquiredProxy, "SSH connection setup failed.");
      if (!this.isCurrentLifecycle(generation)) {
        return;
      }
      const message = error instanceof Error ? error.message : String(error);
      this.setStatus({
        state: "Error",
        activeConfigId: request.config.id,
        realTunnelAvailable: false,
        message
      });
      this.appendDiagnostic("error", message);
      if (error instanceof SshAuthenticationError && error.diagnostics.length > 0) {
        this.appendDiagnostic("info", `SSH private key parse diagnostics: ${error.diagnostics.join("; ")}`);
      }
      if (isNonRetryableConnectError(error)) {
        this.appendDiagnostic("warning", "Reconnect stopped. Update the SSH configuration or key, then connect again.");
        return;
      }
      this.scheduleReconnect(message, generation);
    }
  }

  disconnect(): Promise<void> {
    if (this.disposed) {
      return this.mutationTail;
    }
    this.disconnectRequested = true;
    this.clearReconnectTimer();
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
    await this.stopRouting();
    if (client) {
      await this.disconnectClient(client, reason);
    }
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
    this.appendDiagnostic("info", "SSH session disconnected.");
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
      await client.checkTunnel(endpoint);
      const result = { endpoint, ok: true, at, message: `SSH direct-tcpip check succeeded for ${endpoint}.` };
      this.appendDiagnostic("info", result.message);
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
    const generation = ++this.lifecycleGeneration;
    this.setStatus({
      state: "Disconnecting",
      realTunnelAvailable: false,
      message: "Stopping SSH service."
    });
    return this.enqueueMutation(() => this.disconnectInternal(generation, "Application is quitting."));
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
    this.setStatus({
      state: "Error",
      realTunnelAvailable: false,
      message: error.message
    });
    this.appendDiagnostic("error", error.message);
    void this.enqueueMutation(async () => {
      await this.stopRouting();
      await this.disconnectClient(client, "SSH transport failed.");
      if (!this.isCurrentLifecycle(failureGeneration) || this.disconnectRequested) {
        return;
      }
      if (isNonRetryableConnectError(error)) {
        this.appendDiagnostic("warning", "Reconnect stopped because SSH host trust or credentials require user action.");
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
      message: `Reconnecting after SSH failure: ${reason}`
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

  private async startSocksProxy(
    client: SshLiveClient,
    generation: number
  ): Promise<{ endpoint: { host: string; port: number }; proxy: Socks5Proxy }> {
    const proxy = new Socks5Proxy({
      listenHost: "127.0.0.1",
      idleTimeoutMs: 5 * 60 * 1000,
      connectChannel: (target, originator, signal) => client.openDirectTcpIpChannel(target, originator, signal)
    });
    proxy.onEvent((event) => {
      if (!this.isCurrentLifecycle(generation) || this.client !== client) {
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
    try {
      const endpoint = await proxy.start();
      this.appendDiagnostic("info", `Local HTTP/SOCKS proxy is listening on ${endpoint.host}:${endpoint.port}.`);
      return { endpoint, proxy };
    } catch (error) {
      await proxy.stop().catch(() => undefined);
      throw error;
    }
  }

  private async cleanupClientResources(
    client: SshLiveClient | undefined,
    proxy: Socks5Proxy | undefined,
    reason: string
  ): Promise<void> {
    if (this.client === client) {
      this.client = undefined;
    }
    if (this.socksProxy === proxy) {
      await this.stopRouting();
    } else {
      await proxy?.stop().catch(() => undefined);
    }
    if (client) {
      await this.disconnectClient(client, reason);
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
    const result = this.mutationTail.then(operation, operation);
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

  private async stopRouting(): Promise<void> {
    this.stopProcessRoutingMonitor();
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
    const socksProxy = this.socksProxy;
    this.socksProxy = undefined;
    this.socksEndpoint = undefined;
    try {
      await this.systemProxy.restore();
    } catch (error) {
      this.appendDiagnostic("warning", `Windows proxy restore failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (socksProxy) {
      try {
        await socksProxy.stop();
      } catch (error) {
        this.appendDiagnostic("warning", `Local proxy cleanup failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
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

  private isRoutingStateActive(allowConnecting: boolean): boolean {
    return this.status.state === "Connected" || (allowConnecting && this.status.state === "Connecting");
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
      const nextIps = new Map([...this.processRoutingIps].filter((entry) => entry[1] >= expiresBefore));
      const nextDomains = new Map(
        [...this.processRoutingDomains].filter((entry) =>
          entry[1] > now && !isDomainCoveredByDirectDomainSuffixes(entry[0], directDomainSuffixes)
        )
      );
      const activeProfileCoveredAddresses = new Map(
        [...this.processRoutingProfileCoveredAddresses].filter((entry) => entry[1] > now)
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
            const ttlMs = Math.min(routeTtlMs, PROCESS_ROUTE_DNS_REFRESH_MS, entry.ttlSeconds * 1000);
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
              recordBoundedProcessRouteDomain(nextDomains, entry.domain, now + ttlMs);
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
      transport: "live-ssh",
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

function requiredSecret(secret: string | undefined, label: string): string {
  if (!secret) {
    throw new Error(`${label} is unavailable.`);
  }
  return secret;
}

function redactSecrets(message: string): string {
  return message.replace(/(password|passphrase|private key)\s*[:=]\s*\S+/giu, "$1=<redacted>");
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
