import { execFile, type ChildProcessByStdio, type ExecFileException } from "node:child_process";
import { stat } from "node:fs/promises";
import net from "node:net";
import type { Readable } from "node:stream";

export type XrayProcess = ChildProcessByStdio<null, Readable, Readable>;
export interface LocalTcpEndpoint {
  host: string;
  port: number;
}

export interface WaitForProcessStartupOptions {
  timeoutMs?: number;
  retryIntervalMs?: number;
  connectTimeoutMs?: number;
  signal?: AbortSignal;
}

const DEFAULT_STARTUP_TIMEOUT_MS = 10_000;
const DEFAULT_RETRY_INTERVAL_MS = 50;
const DEFAULT_CONNECT_TIMEOUT_MS = 250;
const MAX_PORT_RESERVATION_ATTEMPTS = 32;
const PROCESS_TERMINATE_GRACE_MS = 1500;
const PROCESS_TERMINATE_DEADLINE_MS = 3000;
/** `xray version` answers at once; the slack is for a first run under an antivirus scan. */
const DEFAULT_VERSION_TIMEOUT_MS = 3_000;
const MAX_VERSION_OUTPUT_BYTES = 64 * 1024;

/** What one `<executable> version` run produced. */
export interface XrayVersionRun {
  /** Whatever the command printed on stdout, possibly nothing. */
  output: string;
  /**
   * Whether the binary ran to its own exit, whatever its exit code. False when
   * it could not be started (ENOENT, EACCES, EAGAIN, EMFILE...) or was cut off
   * by the timeout: that says something about the moment, not the binary.
   */
  completed: boolean;
}

export interface XrayVersionDetectorOptions {
  timeoutMs?: number;
  /** Runs `<executable> version`. Injection seam for tests. */
  run?: (executablePath: string, timeoutMs: number) => Promise<XrayVersionRun>;
  /** Injection seam for tests. */
  stat?: (executablePath: string) => Promise<{ mtimeMs: number; size: number }>;
}

/**
 * Asks an Xray binary for its version ("26.3.27"), once per binary: the
 * answer is cached per path and asked again only when the file's size or
 * modification time changes, so a connect costs a stat, not a spawn.
 *
 * Only a run that completed is kept, even one whose banner is not Xray's. A
 * run that could not start or timed out - a machine out of processes or file
 * handles, a first launch held up by an antivirus scan - is asked again on
 * the next connect, rather than pinning the bundled shape until the binary
 * changes.
 *
 * Never throws: a binary that cannot say yields undefined, and the config
 * builder then falls back to the shape of the bundled release.
 */
export class XrayVersionDetector {
  private readonly cache = new Map<string, XrayVersionCacheEntry>();
  private readonly timeoutMs: number;
  private readonly run: (executablePath: string, timeoutMs: number) => Promise<XrayVersionRun>;
  private readonly stat: (executablePath: string) => Promise<{ mtimeMs: number; size: number }>;

  constructor(options: XrayVersionDetectorOptions = {}) {
    this.timeoutMs = positiveNumber(options.timeoutMs, DEFAULT_VERSION_TIMEOUT_MS);
    this.run = options.run ?? runXrayVersionCommand;
    this.stat = options.stat ?? stat;
  }

  async detect(executablePath: string): Promise<string | undefined> {
    let signature: string;
    try {
      const file = await this.stat(executablePath);
      signature = `${file.size}:${file.mtimeMs}`;
    } catch {
      return undefined;
    }
    const cached = this.cache.get(executablePath);
    if (cached?.signature === signature) {
      return cached.version;
    }
    // The promise is cached, not the answer, so concurrent connects share one
    // spawn; a run that did not complete then takes its entry back out.
    const entry: XrayVersionCacheEntry = { signature, version: Promise.resolve(undefined) };
    const forget = (): void => {
      if (this.cache.get(executablePath) === entry) {
        this.cache.delete(executablePath);
      }
    };
    entry.version = Promise.resolve()
      .then(() => this.run(executablePath, this.timeoutMs))
      .then((run) => {
        if (!run.completed) {
          forget();
        }
        return parseXrayVersion(run.output);
      })
      .catch(() => {
        forget();
        return undefined;
      });
    this.cache.set(executablePath, entry);
    return entry.version;
  }
}

interface XrayVersionCacheEntry {
  signature: string;
  version: Promise<string | undefined>;
}

const sharedXrayVersionDetector = new XrayVersionDetector();

/** The running app's shared {@link XrayVersionDetector}. */
export function detectXrayVersion(executablePath: string): Promise<string | undefined> {
  return sharedXrayVersionDetector.detect(executablePath);
}

/** Reads "26.3.27" out of "Xray 26.3.27 (Xray, Penetrates Everything.) ...". */
export function parseXrayVersion(output: string): string | undefined {
  return /^\s*Xray\s+v?(\d+\.\d+\.\d+)/imu.exec(output)?.[1];
}

export async function reserveLocalTcpPort(): Promise<{ host: string; port: number }> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  if (typeof address !== "object" || !address) {
    throw new Error("Unable to reserve a local TCP port for Xray.");
  }
  return { host: "127.0.0.1", port: address.port };
}

export async function reserveDistinctLocalTcpPorts(
  count: number,
  reserve: () => Promise<LocalTcpEndpoint> = reserveLocalTcpPort
): Promise<LocalTcpEndpoint[]> {
  if (!Number.isInteger(count) || count <= 0) {
    throw new Error("Local TCP port reservation count must be positive.");
  }
  const endpoints: LocalTcpEndpoint[] = [];
  for (let attempt = 0; endpoints.length < count && attempt < MAX_PORT_RESERVATION_ATTEMPTS; attempt += 1) {
    const endpoint = await reserve();
    if (!endpoints.some((candidate) => candidate.host === endpoint.host && candidate.port === endpoint.port)) {
      endpoints.push(endpoint);
    }
  }
  if (endpoints.length !== count) {
    throw new Error(`Unable to reserve ${count} distinct local TCP ports for Xray.`);
  }
  return endpoints;
}

export async function waitForProcessStartup(
  processHandle: XrayProcess,
  endpoints: readonly LocalTcpEndpoint[],
  options: WaitForProcessStartupOptions = {}
): Promise<void> {
  if (endpoints.length === 0) {
    throw new Error("At least one Xray listener endpoint is required.");
  }
  if (processHandle.exitCode !== null || processHandle.signalCode !== null) {
    throw startupExitError(processHandle.exitCode, processHandle.signalCode);
  }

  const timeoutMs = positiveNumber(options.timeoutMs, DEFAULT_STARTUP_TIMEOUT_MS);
  const retryIntervalMs = positiveNumber(options.retryIntervalMs, DEFAULT_RETRY_INTERVAL_MS);
  const connectTimeoutMs = positiveNumber(options.connectTimeoutMs, DEFAULT_CONNECT_TIMEOUT_MS);
  const controller = new AbortController();
  let rejectProcessFailure!: (error: Error) => void;
  const processFailure = new Promise<never>((_resolve, reject) => {
    rejectProcessFailure = reject;
  });
  const onError = (error: Error): void => rejectProcessFailure(error);
  const onExit = (code: number | null, signal: NodeJS.Signals | null): void => {
    rejectProcessFailure(startupExitError(code, signal));
  };
  const onAbort = (): void => rejectProcessFailure(new Error("Xray startup was cancelled."));
  processHandle.once("error", onError);
  processHandle.once("exit", onExit);
  options.signal?.addEventListener("abort", onAbort, { once: true });

  try {
    if (options.signal?.aborted) {
      throw new Error("Xray startup was cancelled.");
    }
    await Promise.race([
      waitForTcpListeners(endpoints, timeoutMs, retryIntervalMs, connectTimeoutMs, controller.signal),
      processFailure
    ]);
  } finally {
    controller.abort();
    processHandle.off("error", onError);
    processHandle.off("exit", onExit);
    options.signal?.removeEventListener("abort", onAbort);
  }
}

export async function terminateProcess(processHandle: XrayProcess): Promise<void> {
  if (processHandle.exitCode !== null || processHandle.signalCode !== null) {
    return;
  }
  await new Promise<void>((resolve) => {
    let settled = false;
    const finish = (): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(forceTimer);
      clearTimeout(deadlineTimer);
      processHandle.off("close", finish);
      resolve();
    };
    const forceTimer = setTimeout(() => {
      try {
        processHandle.kill("SIGKILL");
      } catch {
        // The absolute deadline below still releases shutdown.
      }
    }, PROCESS_TERMINATE_GRACE_MS);
    forceTimer.unref();
    const deadlineTimer = setTimeout(finish, PROCESS_TERMINATE_DEADLINE_MS);
    deadlineTimer.unref();
    processHandle.once("close", finish);
    try {
      processHandle.kill("SIGTERM");
    } catch {
      finish();
    }
  });
}

async function waitForTcpListeners(
  endpoints: readonly LocalTcpEndpoint[],
  timeoutMs: number,
  retryIntervalMs: number,
  connectTimeoutMs: number,
  signal: AbortSignal
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!signal.aborted) {
    const ready = await Promise.all(endpoints.map((endpoint) => canConnect(endpoint, connectTimeoutMs, signal)));
    if (ready.every(Boolean)) {
      return;
    }
    if (Date.now() >= deadline) {
      const listeners = endpoints.map((endpoint) => `${endpoint.host}:${endpoint.port}`).join(", ");
      throw new Error(`Xray listeners did not become ready within ${timeoutMs} ms: ${listeners}.`);
    }
    await abortableDelay(Math.min(retryIntervalMs, Math.max(1, deadline - Date.now())), signal);
  }
  throw new Error("Xray startup was cancelled.");
}

function canConnect(endpoint: LocalTcpEndpoint, timeoutMs: number, signal: AbortSignal): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: endpoint.host, port: endpoint.port });
    let settled = false;
    const finish = (ready: boolean): void => {
      if (settled) {
        return;
      }
      settled = true;
      signal.removeEventListener("abort", onAbort);
      socket.destroy();
      resolve(ready);
    };
    const onAbort = (): void => finish(false);
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.once("timeout", () => finish(false));
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
    }
  });
}

function abortableDelay(delayMs: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(finish, delayMs);
    timer.unref();
    const onAbort = (): void => finish();
    function finish(): void {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      resolve();
    }
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      finish();
    }
  });
}

/** Resolves with whatever the command printed, and whether it ran to its own exit. Never rejects. */
function runXrayVersionCommand(executablePath: string, timeoutMs: number): Promise<XrayVersionRun> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (output: string, completed: boolean): void => {
      if (!settled) {
        settled = true;
        clearTimeout(deadline);
        resolve({ output, completed });
      }
    };
    // execFile kills the child at timeoutMs, but still waits for its pipes to
    // close; this settles even if something keeps them open.
    const deadline = setTimeout(() => finish("", false), timeoutMs + 500);
    deadline.unref();
    const startedAt = Date.now();
    try {
      execFile(
        executablePath,
        ["version"],
        { encoding: "utf8", timeout: timeoutMs, maxBuffer: MAX_VERSION_OUTPUT_BYTES, windowsHide: true },
        (error, stdout) => finish(
          typeof stdout === "string" ? stdout : "",
          // Past the timeout the child was signalled, even if it then chose
          // to exit cleanly.
          ranToExit(error) && Date.now() - startedAt < timeoutMs
        )
      );
    } catch {
      finish("", false);
    }
  });
}

/**
 * Whether execFile's error still means the binary ran and exited by itself:
 * no error, a non-zero exit code, or more output than the cap. A spawn
 * failure carries a system code instead ("ENOENT", "EAGAIN"), and a child
 * killed at the timeout or by a signal never finished saying anything.
 */
function ranToExit(error: ExecFileException | null): boolean {
  if (!error) {
    return true;
  }
  if (error.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
    return true;
  }
  return typeof error.code === "number" && error.killed !== true;
}

function startupExitError(code: number | null, signal: NodeJS.Signals | null): Error {
  return new Error(`Xray runtime exited during startup${code === null ? "" : ` with code ${code}`}${signal ? ` signal ${signal}` : ""}.`);
}

function positiveNumber(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) && Number(value) > 0 ? Number(value) : fallback;
}
