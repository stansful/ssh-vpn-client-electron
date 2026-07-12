import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import type { ServiceEvent } from "../shared/ipc.js";
import type { ConnectRequest, RoutingRule, RoutingUpdateRequest, RuntimeStatus, SshConfig, TunnelCheckResult } from "../shared/types.js";
import {
  BoundedUtf8LineDecoder,
  encodeWireMessage,
  MAX_SERVICE_PENDING_REQUESTS,
  MAX_SERVICE_STDERR_LINE_BYTES,
  isNativeServiceHandshake,
  isRuntimeStatusPayload,
  isTunnelCheckResultPayload,
  requestTimeoutMs,
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

// The native side gives each routing rollback up to five seconds. A rejected
// shutdown command is followed by EOF so its deferred cleanup can retry once;
// keep enough headroom for both bounded attempts before forced termination.
const NATIVE_SHUTDOWN_GRACE_MS = 12_000;

export class NativeProcessServiceBridge implements ServiceBridge {
  private readonly events = new EventEmitter();
  private readonly pending = new Map<string, PendingRequest>();
  private readonly decoder = new ServiceWireDecoder();
  private readonly stderrDecoder = new BoundedUtf8LineDecoder(MAX_SERVICE_STDERR_LINE_BYTES, "Native service stderr line");
  private writeQueue: Promise<void> = Promise.resolve();
  private disposing = false;
  private disposed = false;
  private disposePromise: Promise<void> | undefined;
  private failed = false;
  private status: RuntimeStatus;
  private capabilities: NativeServiceCapabilities | undefined;

  private constructor(
    private readonly child: ChildProcessWithoutNullStreams,
    initialStatus: RuntimeStatus
  ) {
    this.status = initialStatus;
    this.child.stdout.on("data", (chunk) => this.handleData(chunk));
    this.child.stderr.on("data", (chunk) => this.handleStderr(chunk));
    this.child.stdin.on("error", (error) => this.handleFailure(error));
    this.child.on("error", (error) => this.handleFailure(error));
    this.child.on("exit", (code, signal) => this.handleExit(code, signal));
  }

  static async start(executablePath: string, initialStatus: RuntimeStatus): Promise<NativeProcessServiceBridge> {
    const child = spawn(executablePath, ["--stdio"], {
      env: process.env,
      stdio: "pipe",
      windowsHide: true
    });

    const bridge = new NativeProcessServiceBridge(child, initialStatus);
    try {
      const handshake = await bridge.send<NativeServiceHandshake>({ id: randomUUID(), type: "get-capabilities" });
      if (!isNativeServiceHandshake(handshake)) {
        throw new Error("Native service did not return a compatible capability handshake.");
      }
      bridge.capabilities = structuredClone(handshake.capabilities);
      const status = await bridge.send<RuntimeStatus>({ id: randomUUID(), type: "get-status" });
      if (!isRuntimeStatusPayload(status)) {
        throw new Error("Native service returned a malformed runtime status.");
      }
      if (status.realTunnelAvailable && !handshake.capabilities.sshCoreLinked) {
        throw new Error("Native service status contradicts its SSH capability handshake.");
      }
      bridge.status = status;
      return bridge;
    } catch (error) {
      bridge.abortStart(error instanceof Error ? error : new Error(String(error)));
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

  getCapabilities(): NativeServiceCapabilities {
    if (!this.capabilities) {
      throw new Error("Native service capabilities are unavailable.");
    }
    return structuredClone(this.capabilities);
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
      throw new Error("Native service returned a malformed tunnel check result.");
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
    this.disposing = true;
    const startedAt = Date.now();

    try {
      await Promise.race([
        this.send({ id: randomUUID(), type: "shutdown" }),
        delay(NATIVE_SHUTDOWN_GRACE_MS)
      ]);
    } catch {
      // A failed shutdown response can mean that the first routing rollback
      // failed. Closing stdin lets the native process enter its deferred
      // cleanup path and retry before we resort to terminating it.
    }

    if (this.child.exitCode === null && !this.child.killed) {
      this.child.stdin.end();
      await waitForChildExit(
        this.child,
        Math.max(0, NATIVE_SHUTDOWN_GRACE_MS - (Date.now() - startedAt))
      );
    }
    if (this.child.exitCode === null && !this.child.killed) {
      this.child.kill();
    }
    this.disposed = true;
    this.disposing = false;
    this.rejectAll(new Error("Native service process bridge disposed."));
  }

  private async send<TPayload extends ServiceResponsePayload>(command: ServiceCommand): Promise<TPayload | undefined> {
    if (this.disposed || this.failed || this.child.exitCode !== null || this.child.killed) {
      throw new Error("Native service process is not running.");
    }
    if (this.pending.size >= MAX_SERVICE_PENDING_REQUESTS) {
      throw new Error(`Native service pending request limit ${MAX_SERVICE_PENDING_REQUESTS} exceeded.`);
    }

    const authToken = process.env.SHADOW_SSH_SERVICE_TOKEN;
    const authenticatedCommand: ServiceCommand = authToken ? { ...command, authToken } : command;
    const encoded = encodeWireMessage(authenticatedCommand);
    return new Promise<TPayload | undefined>((resolve, reject) => {
      const timer = setTimeout(() => {
        const error = new Error(`Native service ${command.type} request timed out.`);
        this.rejectPending(command.id, error);
        this.handleFailure(error);
      }, requestTimeoutMs(command.type));
      timer.unref();
      this.pending.set(command.id, {
        resolve: (payload) => {
          this.maybeUpdateStatus(payload);
          resolve(payload as TPayload | undefined);
        },
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

  private handleStderr(chunk: Buffer): void {
    try {
      for (const line of this.stderrDecoder.push(chunk)) {
        this.emitStderrLine(line);
      }
    } catch (error) {
      this.handleFailure(error instanceof Error ? error : new Error(String(error)));
    }
  }

  private handleExit(code: number | null, signal: NodeJS.Signals | null): void {
    try {
      for (const line of this.stderrDecoder.end()) {
        this.emitStderrLine(line);
      }
    } catch {
      // The process is already gone; the exit error below is authoritative.
    }
    const error = new Error(`Native service process exited (${signal ?? code ?? "unknown"}).`);
    this.rejectAll(error);
    if (this.disposed || this.disposing) {
      return;
    }
    this.handleFailure(error);
  }

  private maybeUpdateStatus(payload: ServiceResponsePayload | undefined): void {
    if (isRuntimeStatusPayload(payload)) {
      this.status = payload;
    }
  }

  private assertStatusCompatible(status: RuntimeStatus): void {
    if (status.realTunnelAvailable && this.capabilities?.sshCoreLinked !== true) {
      throw new Error("Native service reported a real tunnel without an SSH core capability.");
    }
  }

  private requireSshCoreCapability(operation: string): void {
    if (this.capabilities?.sshCoreLinked !== true) {
      throw new Error(`Native service cannot ${operation} because its SSH core capability is unavailable.`);
    }
  }

  private rejectAll(error: Error): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  private enqueueWrite(encoded: string): Promise<void> {
    const write = this.writeQueue.then(() => writeWithBackpressure(this.child.stdin, encoded));
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

  private emitStderrLine(line: string): void {
    const rawLine = line.trim();
    if (!rawLine) {
      return;
    }
    this.events.emit("event", {
      type: "diagnostics-appended",
      entry: {
        id: randomUUID(),
        at: new Date().toISOString(),
        level: "warning",
        message: `Native service stderr: ${rawLine}`
      }
    } satisfies ServiceEvent);
  }

  private handleFailure(error: Error): void {
    this.rejectAll(error);
    if (this.disposed || this.disposing || this.failed) {
      return;
    }
    this.failed = true;
    if (this.child.exitCode === null && !this.child.killed) {
      this.child.kill();
    }
    this.status = {
      ...this.status,
      state: "Error",
      message: error.message
    };
    this.events.emit("event", { type: "status-changed", status: this.getStatus() } satisfies ServiceEvent);
  }

  private abortStart(error: Error): void {
    this.disposed = true;
    this.rejectAll(error);
    this.child.stdin.destroy();
    if (this.child.exitCode === null && !this.child.killed) {
      this.child.kill();
    }
  }
}

function waitForChildExit(child: ChildProcessWithoutNullStreams, timeoutMs: number): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null || timeoutMs <= 0) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => finish(), timeoutMs);
    timer.unref();
    const onExit = (): void => finish();
    const finish = (): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      child.off("exit", onExit);
      resolve();
    };
    child.once("exit", onExit);
    if (child.exitCode !== null || child.signalCode !== null) {
      finish();
    }
  });
}

async function delay(ms: number): Promise<void> {
  await new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref();
  });
}
