import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { access, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { checkSocks5Connect, parseEndpoint } from "../core/network/socks5-check.js";
import { RoutingMatcher } from "../core/routing/routing-matcher.js";
import { listWindowsProcessConnections } from "../core/network/windows-process-connections.js";
import { WindowsSystemProxyManager } from "../core/network/windows-system-proxy.js";
import { buildXrayConfig } from "../core/proxy/xray-config.js";
import type { ServiceEvent } from "../shared/ipc.js";
import type { DiagnosticsEntry, ProxyConnectRequest, RoutingRule, RoutingUpdateRequest, RuntimeStatus, TunnelCheckResult } from "../shared/types.js";
import { normalizeRuleValue } from "../shared/validation.js";
import { buildSelectedRulesWithProcessIps } from "./live-ssh-service.js";
import { reserveLocalTcpPort, terminateProcess, waitForProcessStartup, type XrayProcess } from "./xray/process-utils.js";

export interface XrayServiceBridgeOptions {
  pacDirectory?: string;
  runtimeDirectory: string;
  executablePath?: string;
}

const PROCESS_ROUTE_TTL_MS = 5 * 60 * 1000;
const PROCESS_ROUTE_REFRESH_INTERVAL_MS = 30 * 1000;

export class XrayServiceBridge {
  private readonly events = new EventEmitter();
  private readonly systemProxy: WindowsSystemProxyManager;
  private readonly runtimeDirectory: string;
  private readonly executablePath: string | undefined;
  private status: RuntimeStatus;
  private process: XrayProcess | undefined;
  private socksEndpoint: { host: string; port: number } | undefined;
  private httpEndpoint: { host: string; port: number } | undefined;
  private lastRequest: ProxyConnectRequest | undefined;
  private disconnectRequested = false;
  private reconnectTimer: NodeJS.Timeout | undefined;
  private routingRules: RoutingRule[] = [];
  private processRoutingMonitor: NodeJS.Timeout | undefined;
  private processRoutingIps = new Map<string, number>();
  private processRoutingLastSignature = "";
  private processRoutingWarningEmitted = false;
  private processLogLines = 0;
  private stoppingProcess = false;

  constructor(initialStatus: RuntimeStatus, options: XrayServiceBridgeOptions) {
    this.systemProxy = new WindowsSystemProxyManager({ pacDirectory: options.pacDirectory });
    this.runtimeDirectory = options.runtimeDirectory;
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
        `Routing rules changed while Xray transport is connected: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}. Re-applying routing.`
      );
      await this.applySystemRouting(request, this.socksEndpoint);
      this.lastRequest = request;
      return;
    }
    this.appendDiagnostic(
      "info",
      `Routing rules prepared for Xray transport: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`
    );
  }

  async updateRouting(update: RoutingUpdateRequest): Promise<void> {
    this.routingRules = update.routingRules;
    if (this.lastRequest) {
      this.lastRequest = {
        ...this.lastRequest,
        routingMode: update.routingMode,
        routingRules: update.routingRules,
        checkEndpoint: update.checkEndpoint
      };
    }
    const summary = new RoutingMatcher(update.routingMode, update.routingRules).summary();
    if (this.status.state === "Connected" && this.lastRequest && this.socksEndpoint) {
      this.appendDiagnostic(
        "info",
        `Routing mode changed while Xray transport is connected: mode=${update.routingMode}, enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}. Re-applying routing without Xray restart.`
      );
      await this.applySystemRouting(this.lastRequest, this.socksEndpoint);
      return;
    }
    this.appendDiagnostic(
      "info",
      `Routing prepared for Xray transport: mode=${update.routingMode}, enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`
    );
  }

  async connect(request: ProxyConnectRequest): Promise<void> {
    this.clearReconnectTimer();
    this.lastRequest = request;
    this.routingRules = request.routingRules;
    this.disconnectRequested = false;
    this.processLogLines = 0;
    this.processRoutingIps.clear();
    this.processRoutingLastSignature = "";
    this.processRoutingWarningEmitted = false;
    await this.stopRouting();
    await this.stopXrayProcess();

    this.setStatus({
      state: "Connecting",
      activeConfigId: request.profile.id,
      connectedAt: undefined,
      realTunnelAvailable: false,
      message: `Starting ${request.profile.protocol.toUpperCase()} profile ${request.profile.name}.`
    });
    this.appendDiagnostic(
      "info",
      `Xray connect requested for ${request.profile.protocol.toUpperCase()} ${request.profile.host}:${request.profile.port}, transport=${request.profile.transport}, security=${request.profile.security}, routing=${request.routingMode}.`
    );

    try {
      const executablePath = await this.requireExecutablePath();
      const socksEndpoint = await reserveLocalTcpPort();
      const httpEndpoint = await reserveLocalTcpPort();
      const configPath = path.join(this.runtimeDirectory, "xray-config.json");
      await mkdir(this.runtimeDirectory, { recursive: true });
      await writeFile(
        configPath,
        buildXrayConfig({
          rawUri: request.secrets.rawUri,
          socksHost: socksEndpoint.host,
          socksPort: socksEndpoint.port,
          httpHost: httpEndpoint.host,
          httpPort: httpEndpoint.port
        }),
        "utf8"
      );
      const processHandle = spawn(executablePath, ["run", "-config", configPath], {
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true
      });
      this.process = processHandle;
      processHandle.stdout.setEncoding("utf8");
      processHandle.stderr.setEncoding("utf8");
      processHandle.stdout.on("data", (data: string) => this.appendProcessLog("info", data));
      processHandle.stderr.on("data", (data: string) => this.appendProcessLog("warning", data));
      processHandle.once("close", (code, signal) => {
        this.process = undefined;
        void this.handleXrayClose(code, signal);
      });
      await waitForProcessStartup(processHandle);
      this.socksEndpoint = socksEndpoint;
      this.httpEndpoint = httpEndpoint;
      this.setStatus({
        state: "Connected",
        activeConfigId: request.profile.id,
        connectedAt: new Date().toISOString(),
        reconnectAttempt: 0,
        realTunnelAvailable: true,
        message: `Connected to ${request.profile.name}. Xray HTTP proxy ${httpEndpoint.host}:${httpEndpoint.port} and SOCKS proxy ${socksEndpoint.host}:${socksEndpoint.port} are live.`
      });
      this.appendDiagnostic("info", `Xray runtime started for ${request.profile.protocol.toUpperCase()} ${request.profile.host}:${request.profile.port}.`);
      await this.applySystemRouting(request, socksEndpoint);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await this.stopRouting();
      await this.stopXrayProcess();
      this.setStatus({
        state: "Error",
        activeConfigId: request.profile.id,
        realTunnelAvailable: false,
        message
      });
      this.appendDiagnostic("error", message);
    }
  }

  async disconnect(): Promise<void> {
    this.disconnectRequested = true;
    this.clearReconnectTimer();
    await this.stopRouting();
    await this.stopXrayProcess();
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

  async dispose(): Promise<void> {
    this.disconnectRequested = true;
    this.clearReconnectTimer();
    await this.stopRouting();
    await this.stopXrayProcess();
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

  private async handleXrayClose(code: number | null, signal: NodeJS.Signals | null): Promise<void> {
    await this.stopRouting();
    this.socksEndpoint = undefined;
    if (this.stoppingProcess) {
      this.stoppingProcess = false;
      this.httpEndpoint = undefined;
      return;
    }
    if (this.disconnectRequested) {
      return;
    }
    const reason = `Xray runtime exited${code === null ? "" : ` with code ${code}`}${signal ? ` signal ${signal}` : ""}.`;
    this.appendDiagnostic("error", reason);
    this.httpEndpoint = undefined;
    this.scheduleReconnect(reason);
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
      message: `Restarting Xray transport after failure: ${reason}`
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

  private async stopRouting(): Promise<void> {
    this.stopProcessRoutingMonitor();
    this.processRoutingIps.clear();
    this.processRoutingLastSignature = "";
    try {
      await this.systemProxy.restore();
    } catch (error) {
      this.appendDiagnostic("warning", `Windows proxy restore failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    this.socksEndpoint = undefined;
    this.httpEndpoint = undefined;
  }

  private async stopXrayProcess(): Promise<void> {
    const processHandle = this.process;
    if (!processHandle) {
      return;
    }
    this.process = undefined;
    this.stoppingProcess = true;
    try {
      await terminateProcess(processHandle);
    } finally {
      await rm(path.join(this.runtimeDirectory, "xray-config.json"), { force: true }).catch(() => undefined);
    }
  }

  private async applySystemRouting(request: ProxyConnectRequest, socksEndpoint: { host: string; port: number }): Promise<void> {
    this.stopProcessRoutingMonitor();
    const httpEndpoint = this.httpEndpoint ?? socksEndpoint;
    const summary = new RoutingMatcher(request.routingMode, request.routingRules).summary();
    const hasProcessRouting = supportsDynamicProcessRouting(request.routingMode, request.routingRules);
    if (hasProcessRouting) {
      await this.learnProcessRoutingIps(request.routingRules);
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
      socksHost: httpEndpoint.host,
      socksPort: httpEndpoint.port,
      proxyProtocol: "http"
    });
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
      `Selected routing prepared for Xray transport: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}, learnedProcessIps=${this.processRoutingIps.size}.`
    );
  }

  private startProcessRoutingMonitor(request: ProxyConnectRequest, socksEndpoint: { host: string; port: number }): void {
    this.stopProcessRoutingMonitor();
    if (!supportsDynamicProcessRouting(request.routingMode, request.routingRules)) {
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

  private async refreshProcessRouting(request: ProxyConnectRequest, socksEndpoint: { host: string; port: number }): Promise<void> {
    const changed = await this.learnProcessRoutingIps(request.routingRules);
    if (!changed) {
      return;
    }

    const effectiveRules = buildSelectedRulesWithProcessIps(request.routingRules, this.currentProcessRoutingIps());
    const result = await this.systemProxy.apply({
      mode: request.routingMode,
      rules: effectiveRules,
      socksHost: (this.httpEndpoint ?? socksEndpoint).host,
      socksPort: (this.httpEndpoint ?? socksEndpoint).port,
      proxyProtocol: "http"
    });
    this.appendDiagnostic(
      result.applied ? "info" : "warning",
      `Process-name routing updated for Xray transport: learnedProcessIps=${this.processRoutingIps.size}. ${result.message}`
    );
  }

  private async learnProcessRoutingIps(rules: RoutingRule[]): Promise<boolean> {
    if (!supportsDynamicProcessRouting("selected-rules", rules)) {
      return false;
    }

    try {
      const processNames = enabledProcessRuleNames(rules);
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
      transport: "xray",
      platformTarget: this.status.platformTarget
    };
    this.emit({ type: "status-changed", status: this.getStatus() });
  }

  private appendProcessLog(level: DiagnosticsEntry["level"], chunk: string): void {
    if (this.processLogLines >= 80) {
      return;
    }
    for (const line of chunk.split(/\r?\n/u).map((entry) => entry.trim()).filter(Boolean)) {
      this.processLogLines += 1;
      if (this.processLogLines === 80) {
        this.appendDiagnostic("info", "Further Xray runtime diagnostics are suppressed for this session.");
        return;
      }
      this.appendDiagnostic(level, `Xray: ${line}`);
    }
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
}

function supportsDynamicProcessRouting(mode: string, rules: RoutingRule[], platform: NodeJS.Platform = process.platform): boolean {
  return platform === "win32" && mode === "selected-rules" && enabledProcessRuleNames(rules).size > 0;
}

function enabledProcessRuleNames(rules: RoutingRule[]): Set<string> {
  return new Set(
    rules
      .filter((rule) => rule.enabled && rule.type === "process.name")
      .map((rule) => normalizeRuleValue("process.name", rule.value))
      .filter(Boolean)
  );
}

function redactSecrets(message: string): string {
  return message.replace(/(password|passphrase|private key|proxy uri|uri)\s*[:=]\s*\S+/giu, "$1=<redacted>");
}
