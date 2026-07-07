import { EventEmitter } from "node:events";
import net from "node:net";
import { randomUUID } from "node:crypto";
import { RoutingMatcher } from "../core/routing/routing-matcher.js";
import { negotiateAlgorithms } from "../core/ssh/algorithms.js";
import { transportKeyLengthsFor } from "../core/ssh/key-derivation.js";
import { DEFAULT_KEX_INIT } from "../core/ssh/messages.js";
import type { ConnectRequest, DiagnosticsEntry, RoutingRule, RoutingUpdateRequest, RuntimeStatus, SshConfig, TerminalLine, TunnelCheckResult } from "../shared/types.js";
import type { ServiceEvent } from "../shared/ipc.js";
import type { ServiceBridge } from "./service-bridge.js";

export class InProcessServiceBridge implements ServiceBridge {
  private readonly events = new EventEmitter();
  private status: RuntimeStatus;
  private disconnectRequested = false;

  constructor(initialStatus: RuntimeStatus) {
    this.status = initialStatus;
  }

  onEvent(listener: (event: ServiceEvent) => void): () => void {
    this.events.on("event", listener);
    return () => this.events.off("event", listener);
  }

  getStatus(): RuntimeStatus {
    return structuredClone(this.status);
  }

  async updateConfig(config: SshConfig): Promise<void> {
    this.appendDiagnostic("info", `Service config updated: ${config.name} (${config.host}:${config.port}), auth=${config.authType}.`);
  }

  async updateRoutingRules(rules: RoutingRule[]): Promise<void> {
    const summary = new RoutingMatcher("selected-rules", rules).summary();
    this.appendDiagnostic("info", `Service routing rules updated: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`);
  }

  async updateRouting(request: RoutingUpdateRequest): Promise<void> {
    const summary = new RoutingMatcher(request.routingMode, request.routingRules).summary();
    this.appendDiagnostic("info", `Service routing updated: mode=${request.routingMode}, enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}, proxyListDomains=${request.routingProxyDomains.length}, directListDomains=${request.routingDirectDomains.length}.`);
  }

  async connect(request: ConnectRequest): Promise<void> {
    this.disconnectRequested = false;
    this.setStatus({
      state: "Connecting",
      activeConfigId: request.config.id,
      message: `Connecting to ${request.config.name} with ${request.routingMode}.`,
      reconnectAttempt: 0,
      connectedAt: undefined
    });
    const routing = new RoutingMatcher(request.routingMode, request.routingRules).summary();
    const algorithms = negotiateAlgorithms(
      { cookie: Buffer.alloc(16), ...DEFAULT_KEX_INIT },
      { cookie: Buffer.alloc(16), ...DEFAULT_KEX_INIT }
    );
    const keyLengths = transportKeyLengthsFor(algorithms.encryptionClientToServer, algorithms.macClientToServer);
    this.appendDiagnostic("info", `Connect requested for ${request.config.name} (${request.config.host}:${request.config.port}), auth=${request.config.authType}, routing=${request.routingMode}, enabledRules=${routing.enabledRules}, proxyListDomains=${request.routingProxyDomains.length}, directListDomains=${request.routingDirectDomains.length}.`);
    this.appendDiagnostic("info", `Routing core prepared: domains=${routing.domainRules}, ips=${routing.ipRules}, processes=${routing.processRules}, invalid=${routing.invalidRules}.`);
    this.appendDiagnostic("info", `SSH core prepared: kex=${algorithms.kexAlgorithm}, hostKey=${algorithms.serverHostKeyAlgorithm}, cipher=${algorithms.encryptionClientToServer}, mac=${algorithms.macClientToServer}, keyBytes=${keyLengths.cipherKeyLength}.`);
    this.appendDiagnostic("info", `Service-side secrets resolved: password=${Boolean(request.secrets?.password)}, privateKey=${Boolean(request.secrets?.privateKey)}, passphraseProvided=${Boolean(request.secrets?.privateKeyPassphrase)}.`);

    await delay(600);
    if (this.disconnectRequested) {
      return;
    }

    this.setStatus({
      state: "Connected",
      activeConfigId: request.config.id,
      message: "Development service simulator is connected. Native tunnel core is pending.",
      connectedAt: new Date().toISOString(),
      reconnectAttempt: 0
    });
    this.appendDiagnostic("warning", "Native privileged service binary was not found; using simulator transport. No OS routing or SSH tunnel has been established.");
  }

  async disconnect(): Promise<void> {
    this.disconnectRequested = true;
    this.setStatus({
      state: "Disconnecting",
      message: "Disconnect requested.",
      connectedAt: this.status.connectedAt
    });
    await delay(250);
    this.setStatus({
      state: "Disconnected",
      activeConfigId: undefined,
      message: "Disconnected.",
      connectedAt: undefined,
      reconnectAttempt: 0
    });
    this.appendDiagnostic("info", "Disconnected by user.");
  }

  async checkTunnel(endpoint: string): Promise<TunnelCheckResult> {
    const result = await checkTcpEndpoint(endpoint);
    const tunnelResult: TunnelCheckResult = {
      ...result,
      message: result.ok
        ? `Direct endpoint check succeeded for ${endpoint}; SSH tunnel verification awaits native core.`
        : `Endpoint check failed for ${endpoint}: ${result.message}`
    };

    this.events.emit("event", { type: "tunnel-check-result", result: tunnelResult } satisfies ServiceEvent);
    this.appendDiagnostic(tunnelResult.ok ? "info" : "warning", `Tunnel check result for ${endpoint}: ${tunnelResult.ok ? "success" : "failure"}.`);
    return tunnelResult;
  }

  async openTerminal(): Promise<void> {
    if (this.status.state !== "Connected") {
      this.emitError("Terminal is available only while connected.");
      return;
    }
    this.appendTerminal("system", "Shell channel is waiting for native SSH core.\n$ ");
  }

  async closeTerminal(): Promise<void> {
    this.appendTerminal("system", "\nShell channel closed.\n");
  }

  async terminalInput(input: string): Promise<void> {
    void input;
    if (this.status.state !== "Connected") {
      this.emitError("Terminal input ignored because SSH is not connected.");
      return;
    }

    await delay(80);
    this.appendTerminal("system", "\n[simulator] Command was not sent because native SSH shell is not implemented yet.\n$ ");
  }

  private setStatus(patch: Partial<RuntimeStatus>): void {
    this.status = {
      ...this.status,
      ...patch
    };
    this.events.emit("event", { type: "status-changed", status: this.getStatus() } satisfies ServiceEvent);
  }

  private appendDiagnostic(level: DiagnosticsEntry["level"], message: string): void {
    this.events.emit("event", {
      type: "diagnostics-appended",
      entry: {
        id: randomUUID(),
        at: new Date().toISOString(),
        level,
        message
      }
    } satisfies ServiceEvent);
  }

  private appendTerminal(stream: TerminalLine["stream"], text: string): void {
    this.events.emit("event", {
      type: "terminal-output",
      line: {
        id: randomUUID(),
        at: new Date().toISOString(),
        stream,
        text
      }
    } satisfies ServiceEvent);
  }

  private emitError(message: string): void {
    this.events.emit("event", { type: "error", message } satisfies ServiceEvent);
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function checkTcpEndpoint(endpoint: string): Promise<TunnelCheckResult> {
  const parsed = parseEndpoint(endpoint);
  if (!parsed) {
    return {
      endpoint,
      ok: false,
      at: new Date().toISOString(),
      message: "Endpoint must be host:port."
    };
  }

  return new Promise((resolve) => {
    const socket = net.createConnection({ host: parsed.host, port: parsed.port, timeout: 4000 });
    let settled = false;
    const finish = (ok: boolean, message: string): void => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve({
        endpoint,
        ok,
        at: new Date().toISOString(),
        message
      });
    };

    socket.once("connect", () => finish(true, "connected"));
    socket.once("timeout", () => finish(false, "timeout"));
    socket.once("error", (error) => finish(false, error.message));
  });
}

function parseEndpoint(endpoint: string): { host: string; port: number } | undefined {
  const trimmed = endpoint.trim();
  const separator = trimmed.lastIndexOf(":");
  if (separator <= 0) {
    return undefined;
  }
  const host = trimmed.slice(0, separator);
  const port = Number(trimmed.slice(separator + 1));
  if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
    return undefined;
  }
  return { host, port };
}
