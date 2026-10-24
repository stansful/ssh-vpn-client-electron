import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import type { ServiceEvent } from "../shared/ipc.js";
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
  /**
   * Receives the events the helper sends beside its responses - the
   * diagnostics a command produced, such as "TUN dataplane started.".
   */
  onEvent?: (event: ServiceEvent) => void;
  /** Extra environment for the spawned helper, merged over this process's own. */
  env?: NodeJS.ProcessEnv;
  /**
   * Lets the helper outlive this process. On Windows every other child is
   * put in a job that is killed the moment Electron exits, which cut short
   * whatever a helper was still undoing - a quit that passed its deadline
   * mid-teardown left routes behind. A detached helper reads the end of its
   * input instead and finishes its teardown on its own.
   */
  detached?: boolean;
}

export interface NativeHelperDisposeOptions {
  /**
   * How long the helper may take to exit on its own once its input is
   * closed, before it is killed. A helper that sees its input end tears
   * down whatever it still owns - a dataplane, its routes - and killing it
   * at once cuts that short. Zero kills at once.
   */
  exitGraceMs?: number;
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
    this.child.on("exit", (code, signal) => {
      const error = new Error(`Native helper exited (${signal ?? code ?? "unknown"}).`);
      // A helper that exits on purpose says why on its last stderr line, and
      // the exit can be reported before that line has been read.
      this.afterStderrDrained(() => this.fail(error));
    });
  }

  /**
   * Spawns the helper and completes its capability handshake. A helper that
   * starts but reports an incompatible protocol is treated as unusable rather
   * than as usable-with-surprises.
   */
  static async start(executablePath: string, options: NativeHelperClientOptions = {}): Promise<NativeHelperClient> {
    const child = spawn(executablePath, ["--stdio"], {
      env: options.env ? { ...process.env, ...options.env } : process.env,
      stdio: "pipe",
      windowsHide: true,
      detached: options.detached === true
    });
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

  /** The handshake taken at start, or by the latest {@link refreshCapabilities}. */
  get handshake(): NativeServiceHandshake | undefined {
    return this.capabilities;
  }

  /**
   * Asks the helper again what it can do. Its answer about the adapter
   * changes while it runs - `wintun.dll` can be put in place after it started
   * - and the handshake taken at start would keep saying it cannot.
   */
  async refreshCapabilities(): Promise<NativeServiceHandshake> {
    const handshake = await this.send<NativeServiceHandshake>({ id: randomUUID(), type: "get-capabilities" });
    if (!isNativeServiceHandshake(handshake)) {
      throw new Error("Native helper did not return a compatible capability handshake.");
    }
    this.capabilities = handshake;
    return handshake;
  }

  /** True while the helper is running and answering. */
  get running(): boolean {
    return !this.disposed && !this.failed && this.child.exitCode === null && !this.child.killed;
  }

  async listProcessConnections(): Promise<NativeProcessConnection[]> {
    const payload = await this.send({ id: randomUUID(), type: "list-process-connections" });
    return parseNativeProcessConnections(payload);
  }

  /**
   * `signal` stops waiting for the answer. The helper is not told - it serves
   * one command at a time and finishes this one - and its late answer is
   * dropped.
   */
  async startDataplane(request: DataplaneStartRequest, signal?: AbortSignal): Promise<void> {
    await this.send({ id: randomUUID(), type: "start-dataplane", payload: request }, signal);
  }

  async stopDataplane(): Promise<void> {
    await this.send({ id: randomUUID(), type: "stop-dataplane" });
  }

  /**
   * Undoes the routing changes a helper that was killed left in the journal.
   * Only for a helper whose handshake advertises `routeRecovery`.
   */
  async recoverRoutes(journalPath: string): Promise<number> {
    const payload = await this.send({ id: randomUUID(), type: "recover-routes", payload: { journalPath } });
    const recovered = (payload as { recovered?: unknown } | undefined)?.recovered;
    return typeof recovered === "number" && Number.isInteger(recovered) && recovered >= 0 ? recovered : 0;
  }

  async dispose(options: NativeHelperDisposeOptions = {}): Promise<void> {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.rejectAll(new Error("Native helper disposed."));
    this.child.stdin.end();
    const exitGraceMs = options.exitGraceMs ?? 0;
    if (exitGraceMs > 0 && this.child.exitCode === null && !this.child.killed) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, exitGraceMs);
        timer.unref();
        this.child.once("exit", () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
    if (this.child.exitCode === null && !this.child.killed) {
      this.child.kill();
    }
  }

  private send<TPayload extends ServiceResponsePayload>(command: ServiceCommand, signal?: AbortSignal): Promise<TPayload | undefined> {
    if (!this.running) {
      return Promise.reject(new Error("Native helper process is not running."));
    }
    if (signal?.aborted) {
      return Promise.reject(abandoned(command));
    }
    const encoded = encodeWireMessage(authenticated(command));
    return new Promise<TPayload | undefined>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.rejectPending(command.id, new Error(`Native helper ${command.type} request timed out.`));
      }, requestTimeoutMs(command.type));
      timer.unref();
      const onAbort = (): void => this.rejectPending(command.id, abandoned(command));
      signal?.addEventListener("abort", onAbort, { once: true });
      this.pending.set(command.id, {
        resolve: (payload) => {
          signal?.removeEventListener("abort", onAbort);
          resolve(payload as TPayload | undefined);
        },
        reject: (error) => {
          signal?.removeEventListener("abort", onAbort);
          reject(error);
        },
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
      if ("kind" in message && message.kind === "event") {
        try {
          this.options.onEvent?.(message.event);
        } catch {
          // An event is informational; a listener that fails must not cost
          // the responses in the same chunk.
        }
        continue;
      }
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

  private afterStderrDrained(callback: () => void): void {
    const stderr = this.child.stderr;
    if (stderr.readableEnded || stderr.destroyed) {
      callback();
      return;
    }
    let finished = false;
    const finish = (): void => {
      if (finished) {
        return;
      }
      finished = true;
      clearTimeout(timer);
      stderr.off("end", finish);
      stderr.off("close", finish);
      callback();
    };
    const timer = setTimeout(finish, STDERR_DRAIN_AFTER_EXIT_MS);
    timer.unref();
    stderr.once("end", finish);
    stderr.once("close", finish);
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

function abandoned(command: ServiceCommand): Error {
  return new Error(`Native helper ${command.type} request was abandoned.`);
}

/** How long an exit waits for the helper's remaining stderr to be read. */
const STDERR_DRAIN_AFTER_EXIT_MS = 250;

function authenticated(command: ServiceCommand): ServiceCommand {
  const authToken = process.env.SHADOW_SSH_SERVICE_TOKEN;
  return authToken ? { ...command, authToken } : command;
}
