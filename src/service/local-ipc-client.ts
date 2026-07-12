import { EventEmitter } from "node:events";
import net from "node:net";
import { randomUUID } from "node:crypto";
import type { ServiceEvent } from "../shared/ipc.js";
import type { ConnectRequest, RoutingRule, RoutingUpdateRequest, RuntimeStatus, SshConfig, TunnelCheckResult } from "../shared/types.js";
import {
  encodeWireMessage,
  isNativeServiceHandshake,
  isRuntimeStatusPayload,
  isTunnelCheckResultPayload,
  MAX_SERVICE_ENDPOINT_WIRE_BYTES,
  MAX_SERVICE_PENDING_REQUESTS,
  requestTimeoutMs,
  SERVICE_CONNECT_TIMEOUT_MS,
  ServiceWireDecoder,
  writeWithBackpressure,
  type ServiceCommand,
  type NativeServiceCapabilities,
  type NativeServiceHandshake,
  type ServiceResponsePayload,
  type ServiceWireMessage
} from "./local-ipc-protocol.js";
import type { ServiceBridge } from "./service-bridge.js";

type PendingRequest = {
  resolve: (payload: ServiceResponsePayload | undefined) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
};

export class LocalIpcServiceBridge implements ServiceBridge {
  private readonly events = new EventEmitter();
  private readonly pending = new Map<string, PendingRequest>();
  private readonly socket: net.Socket;
  private readonly decoder = new ServiceWireDecoder();
  private status: RuntimeStatus;
  private writeQueue: Promise<void> = Promise.resolve();
  private disposed = false;
  private disposePromise: Promise<void> | undefined;
  private failed = false;
  private capabilities: NativeServiceCapabilities | undefined;

  private constructor(socket: net.Socket, initialStatus: RuntimeStatus) {
    this.socket = socket;
    this.status = initialStatus;
    this.socket.on("data", (chunk) => this.handleData(chunk));
    this.socket.on("error", (error) => this.handleFailure(error));
    this.socket.on("close", () => {
      if (this.disposed) {
        this.rejectAll(new Error("Local IPC service bridge disposed."));
        return;
      }
      this.handleFailure(new Error("Local IPC service connection closed."));
    });
  }

  static async connect(endpoint: string, initialStatus: RuntimeStatus): Promise<LocalIpcServiceBridge> {
    const socket = net.createConnection(endpoint);
    try {
      await waitForSocketConnect(socket, SERVICE_CONNECT_TIMEOUT_MS);
    } catch (error) {
      socket.destroy();
      throw error;
    }

    const bridge = new LocalIpcServiceBridge(socket, initialStatus);
    try {
      const handshake = await bridge.send<NativeServiceHandshake>({ id: randomUUID(), type: "get-capabilities" });
      if (!isNativeServiceHandshake(handshake)) {
        throw new Error("Local IPC service did not return a compatible capability handshake.");
      }
      bridge.capabilities = structuredClone(handshake.capabilities);
      const status = await bridge.send<RuntimeStatus>({ id: randomUUID(), type: "get-status" });
      if (!isRuntimeStatusPayload(status)) {
        throw new Error("Local IPC service returned a malformed runtime status.");
      }
      if (status.realTunnelAvailable && !handshake.capabilities.sshCoreLinked) {
        throw new Error("Local IPC service status contradicts its SSH capability handshake.");
      }
      bridge.status = status;
      return bridge;
    } catch (error) {
      socket.destroy();
      throw error;
    }
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
    this.requireSshCoreCapability("connect");
    await this.send({ id: randomUUID(), type: "connect", payload: request });
  }

  async disconnect(): Promise<void> {
    await this.send({ id: randomUUID(), type: "disconnect" });
  }

  async checkTunnel(endpoint: string): Promise<TunnelCheckResult> {
    const result = await this.send<TunnelCheckResult>({ id: randomUUID(), type: "check-tunnel", payload: { endpoint } });
    if (!isTunnelCheckResultPayload(result) || result.endpoint !== endpoint) {
      throw new Error("Service returned a malformed tunnel check result.");
    }
    return result;
  }

  async openTerminal(): Promise<void> {
    this.requireSshCoreCapability("open a terminal");
    await this.send({ id: randomUUID(), type: "open-terminal" });
  }

  async closeTerminal(): Promise<void> {
    await this.send({ id: randomUUID(), type: "close-terminal" });
  }

  async terminalInput(input: string): Promise<void> {
    this.requireSshCoreCapability("send terminal input");
    await this.send({ id: randomUUID(), type: "terminal-input", payload: { input } });
  }

  dispose(): Promise<void> {
    this.disposePromise ??= this.disposeInternal();
    return this.disposePromise;
  }

  private async disposeInternal(): Promise<void> {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.rejectAll(new Error("Local IPC service bridge disposed."));
    await closeSocket(this.socket, 1_000);
  }

  private async send<TPayload extends ServiceResponsePayload>(command: ServiceCommand): Promise<TPayload | undefined> {
    if (this.disposed || this.failed || this.socket.destroyed || !this.socket.writable) {
      throw new Error("Local IPC service connection is not running.");
    }
    if (this.pending.size >= MAX_SERVICE_PENDING_REQUESTS) {
      throw new Error(`Local IPC pending request limit ${MAX_SERVICE_PENDING_REQUESTS} exceeded.`);
    }

    const authToken = process.env.SHADOW_SSH_SERVICE_TOKEN;
    const authenticatedCommand: ServiceCommand = authToken ? { ...command, authToken } : command;
    const encoded = encodeWireMessage(authenticatedCommand);
    if (Buffer.byteLength(encoded, "utf8") > MAX_SERVICE_ENDPOINT_WIRE_BYTES) {
      throw new Error(`Local IPC command exceeds the endpoint limit of ${MAX_SERVICE_ENDPOINT_WIRE_BYTES} bytes.`);
    }
    return new Promise<TPayload | undefined>((resolve, reject) => {
      const timer = setTimeout(() => {
        const error = new Error(`Local IPC ${command.type} request timed out.`);
        this.rejectPending(command.id, error);
        this.handleFailure(error);
      }, requestTimeoutMs(command.type));
      timer.unref();
      this.pending.set(command.id, {
        resolve: (payload) => resolve(payload as TPayload | undefined),
        reject,
        timer
      });
      void this.enqueueWrite(encoded).catch((error: unknown) => {
        const normalized = error instanceof Error ? error : new Error(String(error));
        this.rejectPending(command.id, normalized);
        this.handleFailure(normalized);
      });
    });
  }

  private handleData(chunk: Buffer): void {
    try {
      for (const message of this.decoder.push(chunk)) {
        this.handleMessage(message);
      }
    } catch (error) {
      this.handleFailure(error instanceof Error ? error : new Error(String(error)));
    }
  }

  private handleMessage(message: ServiceWireMessage): void {
    if ("kind" in message && message.kind === "event") {
      if (message.event.type === "status-changed") {
        this.assertStatusCompatible(message.event.status);
        this.status = message.event.status;
      }
      this.events.emit("event", message.event);
      return;
    }

    if ("kind" in message && message.kind === "response") {
      if (message.ok && isRuntimeStatusPayload(message.payload)) {
        this.assertStatusCompatible(message.payload);
      }
      const pending = this.pending.get(message.id);
      if (!pending) {
        return;
      }
      this.pending.delete(message.id);
      clearTimeout(pending.timer);
      if (message.ok) {
        pending.resolve(message.payload);
      } else {
        pending.reject(new Error(message.error));
      }
    }
  }

  private enqueueWrite(encoded: string): Promise<void> {
    const write = this.writeQueue.then(() => writeWithBackpressure(this.socket, encoded));
    this.writeQueue = write.catch(() => undefined);
    return write;
  }

  private rejectPending(id: string, error: Error): void {
    const pending = this.pending.get(id);
    if (!pending) {
      return;
    }
    this.pending.delete(id);
    clearTimeout(pending.timer);
    pending.reject(error);
  }

  private rejectAll(error: Error): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  private handleFailure(error: Error): void {
    this.rejectAll(error);
    if (this.disposed || this.failed) {
      return;
    }
    this.failed = true;
    this.socket.destroy(error);
    this.status = {
      ...this.status,
      state: "Error",
      message: error.message
    };
    this.events.emit("event", { type: "status-changed", status: this.getStatus() } satisfies ServiceEvent);
  }

  private assertStatusCompatible(status: RuntimeStatus): void {
    if (status.realTunnelAvailable && this.capabilities?.sshCoreLinked !== true) {
      throw new Error("Local IPC service reported a real tunnel without an SSH core capability.");
    }
  }

  private requireSshCoreCapability(operation: string): void {
    if (this.capabilities?.sshCoreLinked !== true) {
      throw new Error(`Local IPC service cannot ${operation} because its SSH core capability is unavailable.`);
    }
  }
}

function waitForSocketConnect(socket: net.Socket, timeoutMs: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`Local IPC service connect timed out after ${timeoutMs} ms.`));
    }, timeoutMs);
    timer.unref();
    const cleanup = (): void => {
      clearTimeout(timer);
      socket.off("connect", onConnect);
      socket.off("error", onError);
    };
    const onConnect = (): void => {
      cleanup();
      resolve();
    };
    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };
    socket.once("connect", onConnect);
    socket.once("error", onError);
  });
}

async function closeSocket(socket: net.Socket, timeoutMs: number): Promise<void> {
  if (socket.destroyed) {
    return;
  }
  await new Promise<void>((resolve) => {
    let settled = false;
    const finish = (): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve();
    };
    const timer = setTimeout(finish, timeoutMs);
    timer.unref();
    socket.end(finish);
  });
}
