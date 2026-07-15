import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { access, chmod, mkdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { checkSocks5Connect, parseEndpoint } from "../core/network/socks5-check.js";
import { RoutingMatcher } from "../core/routing/routing-matcher.js";
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
}

const PROCESS_ROUTE_TTL_MS = 5 * 60 * 1000;
const PROCESS_ROUTE_REFRESH_INTERVAL_MS = 10 * 1000;
const PROCESS_ROUTE_DISCOVERY_DELAYS_MS = [1_000, 2_000, 4_000, 8_000] as const;
const PROCESS_ROUTE_DNS_REFRESH_MS = 5 * 60 * 1000;
const PROCESS_ROUTE_DNS_MIN_REFRESH_MS = 1_000;
const PROCESS_ROUTE_DNS_RETRY_BASE_MS = 10_000;
const MAX_XRAY_PROCESS_LOG_LINES = 80;
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
  private processLogLines = 0;
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
    this.processLogLines = 0;
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

    try {
      this.appendDiagnostic("info", `Xray tunnel check requested for ${endpoint}.`);
      const startedAt = Date.now();
      await checkSocks5Connect(this.socksEndpoint, parseEndpoint(endpoint));
      const result = { endpoint, ok: true, at, message: `SOCKS tunnel check succeeded for ${endpoint} in ${Date.now() - startedAt} ms.` };
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
    return this.enqueueMutation(() => this.disconnectInternal(generation));
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

  private appendProcessLog(level: DiagnosticsEntry["level"], chunk: string): boolean {
    if (this.processLogLines >= MAX_XRAY_PROCESS_LOG_LINES) {
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
      this.processLogLines += 1;
      if (this.processLogLines === MAX_XRAY_PROCESS_LOG_LINES) {
        this.appendDiagnostic("info", "Further Xray runtime diagnostics are suppressed for this session.");
        return false;
      }
      const boundedLine = line.length > MAX_XRAY_PROCESS_LOG_LINE_CHARACTERS
        ? `${line.slice(0, MAX_XRAY_PROCESS_LOG_LINE_CHARACTERS)}…`
        : line;
      this.appendDiagnostic(level, `Xray: ${boundedLine}`);
    }
    return true;
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
