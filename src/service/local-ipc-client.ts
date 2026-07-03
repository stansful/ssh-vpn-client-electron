import { EventEmitter } from "node:events";
import net from "node:net";
import { randomUUID } from "node:crypto";
import type { ServiceEvent } from "../shared/ipc.js";
import type { ConnectRequest, RoutingRule, RoutingUpdateRequest, RuntimeStatus, SshConfig, TunnelCheckResult } from "../shared/types.js";
import { decodeWireMessage, encodeWireMessage, type ServiceCommand, type ServiceResponsePayload } from "./local-ipc-protocol.js";
import type { ServiceBridge } from "./service-bridge.js";

type PendingRequest = {
  resolve: (payload: ServiceResponsePayload | undefined) => void;
  reject: (error: Error) => void;
};

export class LocalIpcServiceBridge implements ServiceBridge {
  private readonly events = new EventEmitter();
  private readonly pending = new Map<string, PendingRequest>();
  private readonly socket: net.Socket;
  private status: RuntimeStatus;
  private buffer = "";

  private constructor(socket: net.Socket, initialStatus: RuntimeStatus) {
    this.socket = socket;
    this.status = initialStatus;
    this.socket.on("data", (chunk) => this.handleData(chunk));
    this.socket.on("error", (error) => this.rejectAll(error));
    this.socket.on("close", () => {
      this.rejectAll(new Error("Local IPC service connection closed."));
      this.status = {
        ...this.status,
        state: "Error",
        message: "Local IPC service connection closed."
      };
      this.events.emit("event", { type: "status-changed", status: this.getStatus() } satisfies ServiceEvent);
    });
  }

  static async connect(endpoint: string, initialStatus: RuntimeStatus): Promise<LocalIpcServiceBridge> {
    const socket = net.createConnection(endpoint);
    await new Promise<void>((resolve, reject) => {
      socket.once("connect", resolve);
      socket.once("error", reject);
    });

    const bridge = new LocalIpcServiceBridge(socket, initialStatus);
    const status = await bridge.send<RuntimeStatus>({ id: randomUUID(), type: "get-status" });
    if (status) {
      bridge.status = status;
    }
    return bridge;
  }

  onEvent(listener: (event: ServiceEvent) => void): () => void {
    this.events.on("event", listener);
    return () => this.events.off("event", listener);
  }

  getStatus(): RuntimeStatus {
    return structuredClone(this.status);
  }

  async updateConfig(config: SshConfig): Promise<void> {
    await this.send({ id: randomUUID(), type: "update-config", payload: { config } });
  }

  async updateRoutingRules(rules: RoutingRule[]): Promise<void> {
    await this.send({ id: randomUUID(), type: "update-routing-rules", payload: { rules } });
  }

  async updateRouting(request: RoutingUpdateRequest): Promise<void> {
    await this.send({ id: randomUUID(), type: "update-routing", payload: request });
  }

  async connect(request: ConnectRequest): Promise<void> {
    await this.send({ id: randomUUID(), type: "connect", payload: request });
  }

  async disconnect(): Promise<void> {
    await this.send({ id: randomUUID(), type: "disconnect" });
  }

  async checkTunnel(endpoint: string): Promise<TunnelCheckResult> {
    const result = await this.send<TunnelCheckResult>({ id: randomUUID(), type: "check-tunnel", payload: { endpoint } });
    if (!result) {
      throw new Error("Service did not return a tunnel check result.");
    }
    return result;
  }

  async openTerminal(): Promise<void> {
    await this.send({ id: randomUUID(), type: "open-terminal" });
  }

  async closeTerminal(): Promise<void> {
    await this.send({ id: randomUUID(), type: "close-terminal" });
  }

  async terminalInput(input: string): Promise<void> {
    await this.send({ id: randomUUID(), type: "terminal-input", payload: { input } });
  }

  async dispose(): Promise<void> {
    await new Promise<void>((resolve) => {
      this.socket.end(resolve);
    });
  }

  private async send<TPayload extends ServiceResponsePayload>(command: ServiceCommand): Promise<TPayload | undefined> {
    return new Promise<TPayload | undefined>((resolve, reject) => {
      const authToken = process.env.SHADOW_SSH_SERVICE_TOKEN;
      const authenticatedCommand: ServiceCommand = authToken ? { ...command, authToken } : command;
      this.pending.set(command.id, {
        resolve: (payload) => resolve(payload as TPayload | undefined),
        reject
      });
      this.socket.write(encodeWireMessage(authenticatedCommand), "utf8", (error) => {
        if (error) {
          this.pending.delete(command.id);
          reject(error);
        }
      });
    });
  }

  private handleData(chunk: Buffer): void {
    this.buffer += chunk.toString("utf8");
    let newlineIndex = this.buffer.indexOf("\n");
    while (newlineIndex >= 0) {
      const rawLine = this.buffer.slice(0, newlineIndex).trim();
      this.buffer = this.buffer.slice(newlineIndex + 1);
      if (rawLine) {
        this.handleLine(rawLine);
      }
      newlineIndex = this.buffer.indexOf("\n");
    }
  }

  private handleLine(rawLine: string): void {
    const message = decodeWireMessage(rawLine);
    if ("kind" in message && message.kind === "event") {
      if (message.event.type === "status-changed") {
        this.status = message.event.status;
      }
      this.events.emit("event", message.event);
      return;
    }

    if ("kind" in message && message.kind === "response") {
      const pending = this.pending.get(message.id);
      if (!pending) {
        return;
      }
      this.pending.delete(message.id);
      if (message.ok) {
        pending.resolve(message.payload);
      } else {
        pending.reject(new Error(message.error));
      }
    }
  }

  private rejectAll(error: Error): void {
    for (const pending of this.pending.values()) {
      pending.reject(error);
    }
    this.pending.clear();
  }
}
