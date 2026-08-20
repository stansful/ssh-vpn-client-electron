import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  BoundedUtf8LineDecoder,
  encodeWireMessage,
  isNativeServiceHandshake,
  MAX_SERVICE_STDERR_LINE_BYTES,
  parseNativeProcessConnections,
  requestTimeoutMs,
  ServiceWireDecoder,
  writeWithBackpressure,
  type DataplaneStartRequest,
  type NativeProcessConnection,
  type NativeServiceHandshake,
  type ServiceCommand,
  type ServiceResponsePayload,
  type ServiceWireMessage
} from "./local-ipc-protocol.js";

/**
 * A request/response client for one native helper process over its stdio pipe.
 *
 * Two independent consumers need this: per-connection process attribution,
 * which is advisory and may be restarted freely, and the TUN dataplane, which
 * owns an adapter and the machine's routing table and must not be. They each
 * run their own helper process for exactly that reason - an attribution
 * hiccup restarting the helper would otherwise tear down the dataplane with
 * it - and share only this transport.
 */
export interface NativeHelperClientOptions {
  /** Receives each stderr line the helper writes. */
  onStderrLine?: (line: string) => void;
  /** Called once when the helper stops answering, for any reason. */
  onClosed?: (error: Error) => void;
}

export class NativeHelperClient {
  private readonly decoder = new ServiceWireDecoder();
  private readonly stderrDecoder = new BoundedUtf8LineDecoder(MAX_SERVICE_STDERR_LINE_BYTES, "Native helper stderr line");
  private readonly pending = new Map<
    string,
    { resolve: (payload: ServiceResponsePayload | undefined) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }
  >();
  private writeQueue: Promise<void> = Promise.resolve();
  private failed = false;
  private disposed = false;
  private capabilities: NativeServiceHandshake | undefined;

  private constructor(
    private readonly child: ChildProcessWithoutNullStreams,
    private readonly options: NativeHelperClientOptions
  ) {
    this.child.stdout.on("data", (chunk: Buffer) => this.handleData(chunk));
    this.child.stderr.on("data", (chunk: Buffer) => this.handleStderr(chunk));
    this.child.stdin.on("error", (error: Error) => this.fail(error));
    this.child.on("error", (error: Error) => this.fail(error));
    this.child.on("exit", (code, signal) => this.fail(new Error(`Native helper exited (${signal ?? code ?? "unknown"}).`)));
  }

  /**
   * Spawns the helper and completes its capability handshake. A helper that
   * starts but reports an incompatible protocol is treated as unusable rather
   * than as usable-with-surprises.
   */
  static async start(executablePath: string, options: NativeHelperClientOptions = {}): Promise<NativeHelperClient> {
    const child = spawn(executablePath, ["--stdio"], { env: process.env, stdio: "pipe", windowsHide: true });
    const client = new NativeHelperClient(child, options);
    try {
      const handshake = await client.send<NativeServiceHandshake>({ id: randomUUID(), type: "get-capabilities" });
      if (!isNativeServiceHandshake(handshake)) {
        throw new Error("Native helper did not return a compatible capability handshake.");
      }
      client.capabilities = handshake;
      return client;
    } catch (error) {
      await client.dispose();
      throw error;
    }
  }

  /** The handshake taken at start. */
  get handshake(): NativeServiceHandshake | undefined {
    return this.capabilities;
  }

  /** True while the helper is running and answering. */
  get running(): boolean {
    return !this.disposed && !this.failed && this.child.exitCode === null && !this.child.killed;
  }

  async listProcessConnections(): Promise<NativeProcessConnection[]> {
    const payload = await this.send({ id: randomUUID(), type: "list-process-connections" });
    return parseNativeProcessConnections(payload);
  }

  async startDataplane(request: DataplaneStartRequest): Promise<void> {
    await this.send({ id: randomUUID(), type: "start-dataplane", payload: request });
  }

  async stopDataplane(): Promise<void> {
    await this.send({ id: randomUUID(), type: "stop-dataplane" });
  }

  async dispose(): Promise<void> {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.rejectAll(new Error("Native helper disposed."));
    this.child.stdin.end();
    if (this.child.exitCode === null && !this.child.killed) {
      this.child.kill();
    }
  }

  private send<TPayload extends ServiceResponsePayload>(command: ServiceCommand): Promise<TPayload | undefined> {
    if (!this.running) {
      return Promise.reject(new Error("Native helper process is not running."));
    }
    const encoded = encodeWireMessage(authenticated(command));
    return new Promise<TPayload | undefined>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.rejectPending(command.id, new Error(`Native helper ${command.type} request timed out.`));
      }, requestTimeoutMs(command.type));
      timer.unref();
      this.pending.set(command.id, {
        resolve: (payload) => resolve(payload as TPayload | undefined),
        reject,
        timer
      });
      const write = this.writeQueue.then(() => writeWithBackpressure(this.child.stdin, encoded));
      this.writeQueue = write.catch(() => undefined);
      void write.catch((error: unknown) => {
        this.rejectPending(command.id, error instanceof Error ? error : new Error(String(error)));
      });
    });
  }

  private handleData(chunk: Buffer): void {
    let messages: ServiceWireMessage[];
    try {
      messages = this.decoder.push(chunk);
    } catch (error) {
      this.fail(error instanceof Error ? error : new Error(String(error)));
      return;
    }
    for (const message of messages) {
      if (!("kind" in message) || message.kind !== "response") {
        continue;
      }
      const pending = this.pending.get(message.id);
      if (!pending) {
        continue;
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
    let lines: string[];
    try {
      lines = this.stderrDecoder.push(chunk);
    } catch {
      this.fail(new Error("Native helper stderr overflowed."));
      return;
    }
    if (!this.options.onStderrLine) {
      return;
    }
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed) {
        this.options.onStderrLine(trimmed);
      }
    }
  }

  private fail(error: Error): void {
    if (this.failed) {
      return;
    }
    this.failed = true;
    this.rejectAll(error);
    if (this.child.exitCode === null && !this.child.killed) {
      this.child.kill();
    }
    this.options.onClosed?.(error);
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
}

function authenticated(command: ServiceCommand): ServiceCommand {
  const authToken = process.env.SHADOW_SSH_SERVICE_TOKEN;
  return authToken ? { ...command, authToken } : command;
}
