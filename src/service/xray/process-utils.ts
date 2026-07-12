import { type ChildProcessByStdio } from "node:child_process";
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

function startupExitError(code: number | null, signal: NodeJS.Signals | null): Error {
  return new Error(`Xray runtime exited during startup${code === null ? "" : ` with code ${code}`}${signal ? ` signal ${signal}` : ""}.`);
}

function positiveNumber(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) && Number(value) > 0 ? Number(value) : fallback;
}
