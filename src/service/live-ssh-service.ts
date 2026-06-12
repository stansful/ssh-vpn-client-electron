import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { RoutingMatcher } from "../core/routing/routing-matcher.js";
import { SshLiveClient, type SshLiveClientEvent } from "../core/ssh/live-client.js";
import type { ServiceEvent } from "../shared/ipc.js";
import type { ConnectRequest, DiagnosticsEntry, RoutingRule, RuntimeStatus, SshConfig, TerminalLine, TunnelCheckResult } from "../shared/types.js";
import type { ServiceBridge } from "./service-bridge.js";

export class LiveSshServiceBridge implements ServiceBridge {
  private readonly events = new EventEmitter();
  private status: RuntimeStatus;
  private client: SshLiveClient | undefined;
  private shellOpen = false;
  private disconnectRequested = false;
  private reconnectTimer: NodeJS.Timeout | undefined;
  private lastRequest: ConnectRequest | undefined;
  private routingRules: RoutingRule[] = [];

  constructor(initialStatus: RuntimeStatus) {
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
    this.appendDiagnostic(
      "info",
      `Routing rules prepared for live SSH service: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`
    );
  }

  async connect(request: ConnectRequest): Promise<void> {
    this.clearReconnectTimer();
    this.lastRequest = request;
    this.disconnectRequested = false;
    this.routingRules = request.routingRules;
    this.shellOpen = false;
    await this.client?.disconnect("Replacing SSH session.");
    this.client = undefined;

    this.setStatus({
      state: "Connecting",
      activeConfigId: request.config.id,
      message: `Connecting to ${request.config.host}:${request.config.port} over live SSH.`,
      connectedAt: undefined,
      realTunnelAvailable: false
    });

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
        operationTimeoutMs: 15000
      });
      this.client = client;
      client.onEvent((event) => this.handleClientEvent(event));
      this.setStatus({
        state: "Connected",
        activeConfigId: request.config.id,
        connectedAt: new Date().toISOString(),
        reconnectAttempt: 0,
        realTunnelAvailable: true,
        message: `Connected to ${request.config.name}. SSH direct-tcpip and shell channels are live.`
      });
      this.appendDiagnostic("info", `SSH session established for ${request.config.username}@${request.config.host}:${request.config.port}.`);
      this.appendRoutingDiagnostic(request);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.setStatus({
        state: "Error",
        activeConfigId: request.config.id,
        realTunnelAvailable: false,
        message
      });
      this.appendDiagnostic("error", message);
      this.scheduleReconnect(message);
    }
  }

  async disconnect(): Promise<void> {
    this.disconnectRequested = true;
    this.clearReconnectTimer();
    const client = this.client;
    this.client = undefined;
    this.shellOpen = false;
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
      this.emit({ type: "tunnel-check-result", result });
      return result;
    }

    try {
      await this.client.checkTunnel(endpoint);
      const result = { endpoint, ok: true, at, message: `SSH direct-tcpip check succeeded for ${endpoint}.` };
      this.emit({ type: "tunnel-check-result", result });
      return result;
    } catch (error) {
      const result = {
        endpoint,
        ok: false,
        at,
        message: error instanceof Error ? error.message : String(error)
      };
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

  async terminalInput(input: string): Promise<void> {
    if (!this.client || !this.shellOpen) {
      this.emitError("SSH shell channel is not open.");
      return;
    }
    await this.client.writeShell(input);
  }

  async dispose(): Promise<void> {
    this.clearReconnectTimer();
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
    if (event.type === "close" && !this.disconnectRequested) {
      this.scheduleReconnect("SSH transport closed.");
    }
  }

  private scheduleReconnect(reason: string): void {
    if (this.disconnectRequested || !this.lastRequest || this.reconnectTimer) {
      return;
    }
    const attempt = this.status.reconnectAttempt + 1;
    const delayMs = Math.min(30000, 1000 * 2 ** Math.min(attempt - 1, 5));
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

  private appendRoutingDiagnostic(request: ConnectRequest): void {
    const summary = new RoutingMatcher(request.routingMode, request.routingRules).summary();
    if (request.routingMode === "proxy-all") {
      this.appendDiagnostic("warning", "Proxy-all OS interception requires the privileged Windows routing driver. Live SSH tunnel is connected.");
      return;
    }
    this.appendDiagnostic(
      summary.enabledRules > 0 ? "info" : "warning",
      `Selected routing prepared: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`
    );
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
