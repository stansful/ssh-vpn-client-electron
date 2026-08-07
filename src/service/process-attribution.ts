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
  type NativeServiceHandshake,
  type ServiceCommand,
  type ServiceResponsePayload,
  type ServiceWireMessage
} from "./local-ipc-protocol.js";
import { normalizeWindowsProcessName } from "../core/network/windows-process-connections.js";

export interface ProcessAttribution {
  /**
   * Reports whether attribution can currently answer lookups. Routing decides
   * between local per-process enforcement and the PAC-learning fallback on this
   * answer, so it must be settled before the system proxy is applied.
   */
  isAvailable(): Promise<boolean>;
  /**
   * Resolves the process that owns the given local TCP port, or `undefined`
   * when the owner cannot be determined.
   */
  resolveProcessName(localPort: number): Promise<string | undefined>;
  dispose(): Promise<void>;
}

export interface NativeProcessAttributionOptions {
  executablePath: string;
  /** Injection seam for tests; defaults to spawning the native helper. */
  snapshotProvider?: () => Promise<Map<number, string>>;
  onDiagnostic?: (level: "info" | "warning", message: string) => void;
}

/** Consecutive snapshot failures after which attribution stops being retried. */
const MAX_SNAPSHOT_FAILURES = 5;
/** Bounds the retry loop inside a single resolve call. */
const MAX_SNAPSHOT_ATTEMPTS = 2;

/**
 * Resolves the owning process of a loopback connection through the native
 * helper's `GetExtendedTcpTable` snapshot.
 *
 * Per-connection attribution has to run on the hot path of every new proxied
 * socket, which rules out spawning `powershell.exe` per lookup. The native
 * helper answers from a single syscall over the existing stdio protocol, so a
 * lookup costs a fraction of a millisecond. The helper is only asked for the
 * TCP table; it never carries tunnel traffic.
 */
export class NativeProcessAttribution implements ProcessAttribution {
  private snapshot = new Map<number, string>();
  // Freshness is tracked on the monotonic clock, not on wall time: several
  // sockets are routinely accepted within the same millisecond, and a
  // millisecond-resolution timestamp cannot tell whether a snapshot was taken
  // before or after the socket being resolved existed.
  private snapshotAt = 0n;
  private running: { startedAt: bigint; promise: Promise<void> } | undefined;
  private queued: Promise<void> | undefined;
  private consecutiveFailures = 0;
  private disposed = false;
  private helper: NativeAttributionHelper | undefined;

  constructor(private readonly options: NativeProcessAttributionOptions) {}

  async isAvailable(): Promise<boolean> {
    if (this.disposed || this.consecutiveFailures >= MAX_SNAPSHOT_FAILURES) {
      return false;
    }
    // Take a real snapshot rather than only starting the helper: a binary that
    // starts but cannot read the TCP table must not be reported as usable, or
    // routing would send every connection to a proxy that then refuses to
    // recognise any process.
    await this.refreshAfter(process.hrtime.bigint());
    return !this.disposed && this.consecutiveFailures === 0;
  }

  async resolveProcessName(localPort: number): Promise<string | undefined> {
    if (this.disposed || !Number.isInteger(localPort) || localPort <= 0 || localPort > 65_535) {
      return undefined;
    }
    if (this.consecutiveFailures >= MAX_SNAPSHOT_FAILURES) {
      return undefined;
    }

    // A socket that has only just been accepted is by definition newer than any
    // snapshot taken before it existed, so require a snapshot captured after the
    // lookup began. Concurrent lookups from the same burst join one refresh.
    const requestedAt = process.hrtime.bigint();
    for (let attempt = 0; attempt < MAX_SNAPSHOT_ATTEMPTS && this.snapshotAt < requestedAt; attempt += 1) {
      await this.refreshAfter(requestedAt);
      if (this.disposed) {
        return undefined;
      }
    }
    return this.snapshot.get(localPort);
  }

  async dispose(): Promise<void> {
    this.disposed = true;
    const helper = this.helper;
    this.helper = undefined;
    this.snapshot = new Map();
    await helper?.dispose();
  }

  /**
   * Returns once a snapshot whose capture began after `requestedAt` is in
   * place.
   *
   * A browser can hand the proxy dozens of sockets in the same tick. Starting a
   * syscall per socket would be wasteful, but reusing a snapshot older than the
   * socket would misattribute it. Callers that arrive while a capture is in
   * flight therefore share a single follow-up capture, which bounds a burst of
   * any size to at most two snapshots while keeping every answer valid.
   */
  private refreshAfter(requestedAt: bigint): Promise<void> {
    const running = this.running;
    if (running && running.startedAt >= requestedAt) {
      return running.promise;
    }
    if (!running) {
      return this.startRefresh();
    }
    this.queued ??= running.promise
      .catch(() => undefined)
      .then(() => {
        this.queued = undefined;
        return this.startRefresh();
      });
    return this.queued;
  }

  private startRefresh(): Promise<void> {
    const startedAt = process.hrtime.bigint();
    const promise = this.captureSnapshot(startedAt).finally(() => {
      if (this.running?.promise === promise) {
        this.running = undefined;
      }
    });
    this.running = { startedAt, promise };
    return promise;
  }

  private async captureSnapshot(startedAt: bigint): Promise<void> {
    try {
      const snapshot = await (this.options.snapshotProvider ?? (() => this.nativeSnapshot()))();
      if (this.disposed) {
        return;
      }
      this.snapshot = snapshot;
      this.consecutiveFailures = 0;
    } catch (error) {
      this.consecutiveFailures += 1;
      // Advance the timestamp even on failure so the caller's bounded retry loop
      // terminates instead of spinning on an unreachable helper.
      if (this.consecutiveFailures === MAX_SNAPSHOT_FAILURES) {
        this.options.onDiagnostic?.(
          "warning",
          `Process attribution is disabled after ${MAX_SNAPSHOT_FAILURES} failed native snapshots: ${errorMessage(error)}`
        );
      } else if (this.consecutiveFailures === 1) {
        this.options.onDiagnostic?.("warning", `Native process attribution snapshot failed: ${errorMessage(error)}`);
      }
      await this.helper?.dispose().catch(() => undefined);
      this.helper = undefined;
    } finally {
      if (startedAt > this.snapshotAt) {
        this.snapshotAt = startedAt;
      }
    }
  }

  private async nativeSnapshot(): Promise<Map<number, string>> {
    this.helper ??= await NativeAttributionHelper.start(this.options.executablePath);
    const rows = await this.helper.listProcessConnections();
    const snapshot = new Map<number, string>();
    for (const row of rows) {
      // The table lists listeners and both address families. Later rows for the
      // same port describe the same owner, so the first one wins.
      if (!snapshot.has(row.localPort)) {
        snapshot.set(row.localPort, normalizeWindowsProcessName(row.processName));
      }
    }
    return snapshot;
  }
}

/** Minimal stdio client for the native helper's read-only commands. */
class NativeAttributionHelper {
  private readonly decoder = new ServiceWireDecoder();
  private readonly stderrDecoder = new BoundedUtf8LineDecoder(MAX_SERVICE_STDERR_LINE_BYTES, "Native helper stderr line");
  private readonly pending = new Map<string, { resolve: (payload: ServiceResponsePayload | undefined) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }>();
  private writeQueue: Promise<void> = Promise.resolve();
  private failed = false;
  private disposed = false;

  private constructor(private readonly child: ChildProcessWithoutNullStreams) {
    this.child.stdout.on("data", (chunk: Buffer) => this.handleData(chunk));
    // stderr is drained but discarded: the helper is advisory here, and its
    // diagnostics must not be mistaken for tunnel diagnostics.
    this.child.stderr.on("data", (chunk: Buffer) => {
      try {
        this.stderrDecoder.push(chunk);
      } catch {
        this.fail(new Error("Native helper stderr overflowed."));
      }
    });
    this.child.stdin.on("error", (error: Error) => this.fail(error));
    this.child.on("error", (error: Error) => this.fail(error));
    this.child.on("exit", (code, signal) => this.fail(new Error(`Native helper exited (${signal ?? code ?? "unknown"}).`)));
  }

  static async start(executablePath: string): Promise<NativeAttributionHelper> {
    const child = spawn(executablePath, ["--stdio"], { env: process.env, stdio: "pipe", windowsHide: true });
    const helper = new NativeAttributionHelper(child);
    try {
      const handshake = await helper.send<NativeServiceHandshake>({ id: randomUUID(), type: "get-capabilities" });
      if (!isNativeServiceHandshake(handshake)) {
        throw new Error("Native helper did not return a compatible capability handshake.");
      }
      if (!handshake.capabilities.processConnectionAttribution) {
        throw new Error("Native helper does not support process connection attribution.");
      }
      return helper;
    } catch (error) {
      await helper.dispose();
      throw error;
    }
  }

  async listProcessConnections(): Promise<ReturnType<typeof parseNativeProcessConnections>> {
    const payload = await this.send({ id: randomUUID(), type: "list-process-connections" });
    return parseNativeProcessConnections(payload);
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
    if (this.disposed || this.failed || this.child.exitCode !== null || this.child.killed) {
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

  private fail(error: Error): void {
    if (this.failed) {
      return;
    }
    this.failed = true;
    this.rejectAll(error);
    if (this.child.exitCode === null && !this.child.killed) {
      this.child.kill();
    }
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

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
