import { NativeHelperClient } from "./native-helper-client.js";
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
  private helper: NativeHelperClient | undefined;

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
    this.helper ??= await startAttributionHelper(this.options.executablePath);
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

/**
 * Starts a helper dedicated to attribution and checks that it can actually
 * answer. A binary that starts but does not support the TCP table must not be
 * reported as usable: routing would then send every connection to a listener
 * that recognises no process at all.
 */
async function startAttributionHelper(executablePath: string): Promise<NativeHelperClient> {
  const client = await NativeHelperClient.start(executablePath);
  if (!client.handshake?.capabilities.processConnectionAttribution) {
    await client.dispose();
    throw new Error("Native helper does not support process connection attribution.");
  }
  return client;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
