import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import type { ServiceEvent } from "../shared/ipc.js";
import type { ConnectRequest, RoutingRule, RuntimeStatus, SshConfig, TunnelCheckResult } from "../shared/types.js";
import { decodeWireMessage, encodeWireMessage, type ServiceCommand, type ServiceResponsePayload } from "./local-ipc-protocol.js";
import type { ServiceBridge } from "./service-bridge.js";

type PendingRequest = {
  resolve: (payload: ServiceResponsePayload | undefined) => void;
  reject: (error: Error) => void;
};

export class NativeProcessServiceBridge implements ServiceBridge {
  private readonly events = new EventEmitter();
  private readonly pending = new Map<string, PendingRequest>();
  private buffer = "";
  private stderrBuffer = "";
  private disposed = false;
  private status: RuntimeStatus;

  private constructor(
    private readonly child: ChildProcessWithoutNullStreams,
    initialStatus: RuntimeStatus
  ) {
    this.status = initialStatus;
    this.child.stdout.on("data", (chunk) => this.handleData(chunk));
    this.child.stderr.on("data", (chunk) => this.handleStderr(chunk));
    this.child.on("error", (error) => this.rejectAll(error));
    this.child.on("exit", (code, signal) => this.handleExit(code, signal));
  }

  static async start(executablePath: string, initialStatus: RuntimeStatus): Promise<NativeProcessServiceBridge> {
    const child = spawn(executablePath, ["--stdio"], {
      env: process.env,
      stdio: "pipe",
      windowsHide: true
    });

    const bridge = new NativeProcessServiceBridge(child, initialStatus);
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
    if (this.disposed) {
      return;
    }
    this.disposed = true;

    try {
      await Promise.race([
        this.send({ id: randomUUID(), type: "shutdown" }),
        delay(500)
      ]);
    } catch {
      // The process may already be exiting; the kill path below is the cleanup guarantee.
    }

    if (this.child.exitCode === null && !this.child.killed) {
      this.child.kill();
    }
  }

  private async send<TPayload extends ServiceResponsePayload>(command: ServiceCommand): Promise<TPayload | undefined> {
    if (this.child.exitCode !== null || this.child.killed) {
      throw new Error("Native service process is not running.");
    }

    return new Promise<TPayload | undefined>((resolve, reject) => {
      const authToken = process.env.SHADOW_SSH_SERVICE_TOKEN;
      const authenticatedCommand: ServiceCommand = authToken ? { ...command, authToken } : command;
      this.pending.set(command.id, {
        resolve: (payload) => {
          this.maybeUpdateStatus(payload);
          resolve(payload as TPayload | undefined);
        },
        reject
      });
      this.child.stdin.write(encodeWireMessage(authenticatedCommand), "utf8", (error) => {
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

  private handleStderr(chunk: Buffer): void {
    this.stderrBuffer += chunk.toString("utf8");
    let newlineIndex = this.stderrBuffer.indexOf("\n");
    while (newlineIndex >= 0) {
      const rawLine = this.stderrBuffer.slice(0, newlineIndex).trim();
      this.stderrBuffer = this.stderrBuffer.slice(newlineIndex + 1);
      if (rawLine) {
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
      newlineIndex = this.stderrBuffer.indexOf("\n");
    }
  }

  private handleExit(code: number | null, signal: NodeJS.Signals | null): void {
    this.rejectAll(new Error(`Native service process exited (${signal ?? code ?? "unknown"}).`));
    if (this.disposed) {
      return;
    }
    this.status = {
      ...this.status,
      state: "Error",
      message: `Native service process exited (${signal ?? code ?? "unknown"}).`
    };
    this.events.emit("event", { type: "status-changed", status: this.getStatus() } satisfies ServiceEvent);
  }

  private maybeUpdateStatus(payload: ServiceResponsePayload | undefined): void {
    if (isRuntimeStatus(payload)) {
      this.status = payload;
    }
  }

  private rejectAll(error: Error): void {
    for (const pending of this.pending.values()) {
      pending.reject(error);
    }
    this.pending.clear();
  }
}

function isRuntimeStatus(payload: ServiceResponsePayload | undefined): payload is RuntimeStatus {
  return typeof payload === "object" && payload !== null && "state" in payload && "platformTarget" in payload;
}

async function delay(ms: number): Promise<void> {
  await new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref();
  });
}
