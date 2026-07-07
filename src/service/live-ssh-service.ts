import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { RoutingMatcher } from "../core/routing/routing-matcher.js";
import { Socks5Proxy } from "../core/network/socks5-proxy.js";
import { WindowsSystemProxyManager } from "../core/network/windows-system-proxy.js";
import { listWindowsProcessConnections } from "../core/network/windows-process-connections.js";
import { SshAuthenticationError, SshLiveClient, type SshLiveClientEvent } from "../core/ssh/live-client.js";
import type { ServiceEvent } from "../shared/ipc.js";
import type { ConnectRequest, DiagnosticsEntry, RoutingRule, RoutingUpdateRequest, RuntimeStatus, SshConfig, TerminalLine, TunnelCheckResult } from "../shared/types.js";
import { normalizeRuleValue } from "../shared/validation.js";
import type { ServiceBridge } from "./service-bridge.js";

export interface LiveSshServiceBridgeOptions {
  pacDirectory?: string;
}

const PROCESS_ROUTE_TTL_MS = 5 * 60 * 1000;
const PROCESS_ROUTE_REFRESH_INTERVAL_MS = 30 * 1000;

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
  private proxyInfoDiagnostics = 0;
  private proxyWarningDiagnostics = 0;
  private processRoutingMonitor: NodeJS.Timeout | undefined;
  private processRoutingIps = new Map<string, number>();
  private processRoutingLastSignature = "";
  private processRoutingWarningEmitted = false;
  private ignoreNextClientClose = false;

  constructor(initialStatus: RuntimeStatus, options: LiveSshServiceBridgeOptions = {}) {
    this.systemProxy = new WindowsSystemProxyManager({ pacDirectory: options.pacDirectory });
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

  async updateRoutingRules(rules: RoutingRule[]): Promise<void> {
    this.routingRules = rules;
    const summary = new RoutingMatcher("selected-rules", rules).summary();
    if (this.lastRequest) {
      this.lastRequest = { ...this.lastRequest, routingRules: rules };
    }
    if (this.status.state === "Connected" && this.lastRequest && this.socksEndpoint) {
      const request = { ...this.lastRequest, routingRules: rules };
      this.appendDiagnostic(
        "info",
        `Routing rules changed while connected: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}. Re-applying routing.`
      );
      await this.applySystemRouting(request, this.socksEndpoint);
      this.lastRequest = request;
      return;
    }
    this.appendDiagnostic(
      "info",
      `Routing rules prepared for live SSH service: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`
    );
  }

  async updateRouting(update: RoutingUpdateRequest): Promise<void> {
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
    const summary = new RoutingMatcher(update.routingMode, update.routingRules).summary();
    if (this.status.state === "Connected" && this.lastRequest && this.socksEndpoint) {
      const unsupportedRouting = describeUnsupportedSelectedRouting(this.lastRequest);
      if (unsupportedRouting) {
        this.setStatus({
          state: "Error",
          activeConfigId: this.lastRequest.config.id,
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
      await this.applySystemRouting(this.lastRequest, this.socksEndpoint);
      return;
    }
    this.appendDiagnostic(
      "info",
      `Routing prepared for live SSH service: mode=${update.routingMode}, enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`
    );
  }

  async connect(request: ConnectRequest): Promise<void> {
    this.clearReconnectTimer();
    this.lastRequest = request;
    this.disconnectRequested = false;
    this.routingRules = request.routingRules;
    this.proxyInfoDiagnostics = 0;
    this.proxyWarningDiagnostics = 0;
    this.processRoutingIps.clear();
    this.processRoutingLastSignature = "";
    this.processRoutingWarningEmitted = false;
    this.shellOpen = false;
    await this.stopRouting();
    const existingClient = this.client;
    this.client = undefined;
    if (existingClient) {
      this.ignoreNextClientClose = true;
      await existingClient.disconnect("Replacing SSH session.");
    }

    this.setStatus({
      state: "Connecting",
      activeConfigId: request.config.id,
      message: `Connecting to ${request.config.host}:${request.config.port} over live SSH.`,
      connectedAt: undefined,
      realTunnelAvailable: false
    });
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
        operationTimeoutMs: 60000
      });
      this.client = client;
      client.onEvent((event) => this.handleClientEvent(event));
      const socksEndpoint = await this.startSocksProxy(client);
      this.socksEndpoint = socksEndpoint;
      this.setStatus({
        state: "Connected",
        activeConfigId: request.config.id,
        connectedAt: new Date().toISOString(),
        reconnectAttempt: 0,
        realTunnelAvailable: true,
        message: `Connected to ${request.config.name}. HTTP/SOCKS proxy ${socksEndpoint.host}:${socksEndpoint.port}, direct-tcpip, and shell channels are live.`
      });
      this.appendDiagnostic("info", `SSH session established for ${request.config.username}@${request.config.host}:${request.config.port}.`);
      await this.applySystemRouting(request, socksEndpoint);
    } catch (error) {
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
      if (isNonRetryableConnectError(message)) {
        this.appendDiagnostic("warning", "Reconnect stopped. Update the SSH configuration or key, then connect again.");
        return;
      }
      this.scheduleReconnect(message);
    }
  }

  async disconnect(): Promise<void> {
    this.disconnectRequested = true;
    this.clearReconnectTimer();
    const client = this.client;
    this.client = undefined;
    this.shellOpen = false;
    await this.stopRouting();
    await client?.disconnect("User disconnected.");
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
    if (!this.client || this.status.state !== "Connected") {
      const result = { endpoint, ok: false, at, message: "SSH session is not connected." };
      this.appendDiagnostic("warning", `Tunnel check skipped for ${endpoint}: SSH session is not connected.`);
      this.emit({ type: "tunnel-check-result", result });
      return result;
    }

    try {
      this.appendDiagnostic("info", `Tunnel check requested for ${endpoint}.`);
      await this.client.checkTunnel(endpoint);
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

  async openTerminal(): Promise<void> {
    if (!this.client || this.status.state !== "Connected") {
      this.emitError("SSH terminal requires an active connection.");
      return;
    }
    if (this.shellOpen) {
      return;
    }
    await this.client.openShell();
    this.shellOpen = true;
    this.appendTerminal("system", "SSH shell channel opened.\n");
  }

  async closeTerminal(): Promise<void> {
    if (!this.client || !this.shellOpen) {
      return;
    }
    await this.client.closeShell();
    this.shellOpen = false;
    this.appendTerminal("system", "\nSSH shell channel closed.\n");
  }

  async terminalInput(input: string): Promise<void> {
    if (!this.client || !this.shellOpen) {
      this.emitError("SSH shell channel is not open.");
      return;
    }
    await this.client.writeShell(input);
  }

  async dispose(): Promise<void> {
    this.clearReconnectTimer();
    await this.stopRouting();
    await this.client?.disconnect("Application is quitting.");
    this.client = undefined;
  }

  private handleClientEvent(event: SshLiveClientEvent): void {
    if (event.type === "terminal-data") {
      this.appendTerminal("stdout", event.data.toString("utf8"));
      return;
    }
    if (event.type === "error") {
      this.appendDiagnostic("error", event.error.message);
      this.scheduleReconnect(event.error.message);
      return;
    }
    if (event.type === "close" && this.ignoreNextClientClose) {
      this.ignoreNextClientClose = false;
      return;
    }
    if (event.type === "close" && !this.disconnectRequested) {
      this.scheduleReconnect("SSH transport closed.");
    }
  }

  private scheduleReconnect(reason: string): void {
    if (this.disconnectRequested || !this.lastRequest || this.reconnectTimer) {
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
      if (this.lastRequest && !this.disconnectRequested) {
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

  private async startSocksProxy(client: SshLiveClient): Promise<{ host: string; port: number }> {
    await this.socksProxy?.stop();
    const proxy = new Socks5Proxy({
      listenHost: "127.0.0.1",
      idleTimeoutMs: 5 * 60 * 1000,
      connectChannel: (target, originator) => client.openDirectTcpIpChannel(target, originator)
    });
    proxy.onEvent((event) => {
      if (event.type === "error") {
        this.appendProxyDiagnostic("warning", event.message);
        return;
      }
      if (event.type === "connection" || event.type === "tunnel-opened") {
        this.appendProxyDiagnostic("info", event.message);
      }
    });
    this.socksProxy = proxy;
    const endpoint = await proxy.start();
    this.appendDiagnostic("info", `Local HTTP/SOCKS proxy is listening on ${endpoint.host}:${endpoint.port}.`);
    return endpoint;
  }

  private async stopRouting(): Promise<void> {
    this.stopProcessRoutingMonitor();
    this.processRoutingIps.clear();
    this.processRoutingLastSignature = "";
    try {
      await this.systemProxy.restore();
    } catch (error) {
      this.appendDiagnostic("warning", `Windows proxy restore failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (this.socksProxy) {
      await this.socksProxy.stop();
      this.socksProxy = undefined;
    }
    this.socksEndpoint = undefined;
  }

  private async applySystemRouting(request: ConnectRequest, socksEndpoint: { host: string; port: number }): Promise<void> {
    this.stopProcessRoutingMonitor();
    const summary = new RoutingMatcher(request.routingMode, request.routingRules).summary();
    const hasProcessRouting = supportsDynamicProcessRouting(request);
    if (hasProcessRouting) {
      await this.learnProcessRoutingIps(request);
      this.appendDiagnostic(
        "warning",
        "Selected process-name routing is using dynamic process-IP PAC rules. Non-matching traffic stays direct, but already-open target app sockets may need reconnect; strict per-process enforcement still requires WFP/TUN."
      );
    } else {
      this.processRoutingIps.clear();
      this.processRoutingLastSignature = "";
    }
    const effectiveRules = buildSelectedRulesWithProcessIps(request.routingRules, this.currentProcessRoutingIps());
    const result = await this.systemProxy.apply({
      mode: request.routingMode,
      rules: effectiveRules,
      proxyDomains: request.routingProxyDomains,
      directDomains: request.routingDirectDomains,
      socksHost: socksEndpoint.host,
      socksPort: socksEndpoint.port
    });
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
      `Selected routing prepared: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}, learnedProcessIps=${this.processRoutingIps.size}.`
    );
  }

  private startProcessRoutingMonitor(request: ConnectRequest, socksEndpoint: { host: string; port: number }): void {
    this.stopProcessRoutingMonitor();
    if (!supportsDynamicProcessRouting(request)) {
      return;
    }

    this.processRoutingMonitor = setInterval(() => {
      void this.refreshProcessRouting(request, socksEndpoint);
    }, PROCESS_ROUTE_REFRESH_INTERVAL_MS);
    this.processRoutingMonitor.unref();
  }

  private stopProcessRoutingMonitor(): void {
    if (!this.processRoutingMonitor) {
      return;
    }
    clearInterval(this.processRoutingMonitor);
    this.processRoutingMonitor = undefined;
  }

  private async refreshProcessRouting(request: ConnectRequest, socksEndpoint: { host: string; port: number }): Promise<void> {
    const changed = await this.learnProcessRoutingIps(request);
    if (!changed) {
      return;
    }

    const effectiveRules = buildSelectedRulesWithProcessIps(request.routingRules, this.currentProcessRoutingIps());
    const result = await this.systemProxy.apply({
      mode: request.routingMode,
      rules: effectiveRules,
      proxyDomains: request.routingProxyDomains,
      directDomains: request.routingDirectDomains,
      socksHost: socksEndpoint.host,
      socksPort: socksEndpoint.port
    });
    this.appendDiagnostic(
      result.applied ? "info" : "warning",
      `Process-name routing updated: learnedProcessIps=${this.processRoutingIps.size}. ${result.message}`
    );
  }

  private async learnProcessRoutingIps(request: ConnectRequest): Promise<boolean> {
    if (!supportsDynamicProcessRouting(request)) {
      return false;
    }

    try {
      const processNames = enabledProcessRuleNames(request.routingRules);
      const connections = await listWindowsProcessConnections();
      const now = Date.now();
      const expiresBefore = now - PROCESS_ROUTE_TTL_MS;
      const nextIps = new Map([...this.processRoutingIps].filter((entry) => entry[1] >= expiresBefore));
      for (const connection of connections) {
        const processName = normalizeRuleValue("process.name", connection.processName);
        if (processNames.has(processName)) {
          nextIps.set(connection.remoteAddress, now);
        }
      }

      const nextSignature = [...nextIps.keys()].sort().join(",");
      const changed = nextSignature !== this.processRoutingLastSignature;
      this.processRoutingIps = nextIps;
      this.processRoutingLastSignature = nextSignature;
      return changed;
    } catch (error) {
      if (!this.processRoutingWarningEmitted) {
        this.processRoutingWarningEmitted = true;
        this.appendDiagnostic(
          "warning",
          `Process-name routing monitor failed: ${error instanceof Error ? error.message : String(error)}`
        );
      }
      return false;
    }
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

function isNonRetryableConnectError(message: string): boolean {
  return /SSH authentication failed|SSH private key|password auth rejected|private-key auth rejected|no auth method available|is unavailable|host key/i.test(message);
}

export function describeUnsupportedSelectedRouting(request: ConnectRequest, platform: NodeJS.Platform = process.platform): string | undefined {
  void request;
  void platform;
  return undefined;
}

export function buildSelectedRulesWithProcessIps(rules: RoutingRule[], processIps: ReadonlySet<string>): RoutingRule[] {
  if (processIps.size === 0) {
    return rules;
  }

  const existingIpRules = new Set(
    rules.filter((rule) => rule.enabled && rule.type === "ip").map((rule) => normalizeRuleValue("ip", rule.value).toLowerCase())
  );
  const now = new Date(0).toISOString();
  const dynamicRules = [...processIps]
    .map((ip) => ip.trim())
    .filter(Boolean)
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

  return [...rules, ...dynamicRules];
}

function supportsDynamicProcessRouting(request: ConnectRequest, platform: NodeJS.Platform = process.platform): boolean {
  return platform === "win32" && request.routingMode === "selected-rules" && enabledProcessRuleNames(request.routingRules).size > 0;
}

function enabledProcessRuleNames(rules: RoutingRule[]): Set<string> {
  return new Set(
    rules
      .filter((rule) => rule.enabled && rule.type === "process.name")
      .map((rule) => normalizeRuleValue("process.name", rule.value))
      .filter(Boolean)
  );
}
