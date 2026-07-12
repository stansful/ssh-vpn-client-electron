import { EventEmitter } from "node:events";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { XrayProcess } from "../src/service/xray/process-utils.js";

const network = vi.hoisted(() => ({
  outcomes: [] as boolean[],
  createConnection: vi.fn(() => {
    const listeners = new Map<string, (...args: unknown[]) => void>();
    const socket = {
      setTimeout: vi.fn(),
      destroy: vi.fn(),
      once: vi.fn((event: string, listener: (...args: unknown[]) => void) => {
        listeners.set(event, listener);
        return socket;
      })
    };
    queueMicrotask(() => {
      const ready = network.outcomes.shift() ?? false;
      listeners.get(ready ? "connect" : "error")?.(ready ? undefined : new Error("refused"));
    });
    return socket;
  }),
  createServer: vi.fn()
}));

vi.mock("node:net", () => ({
  default: {
    createConnection: network.createConnection,
    createServer: network.createServer
  }
}));

const { reserveDistinctLocalTcpPorts, terminateProcess, waitForProcessStartup } = await import("../src/service/xray/process-utils.js");

describe("Xray process startup utilities", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    network.outcomes.length = 0;
  });

  it("retries duplicate reservations until it has distinct endpoints", async () => {
    const reserve = vi.fn()
      .mockResolvedValueOnce({ host: "127.0.0.1", port: 30000 })
      .mockResolvedValueOnce({ host: "127.0.0.1", port: 30000 })
      .mockResolvedValueOnce({ host: "127.0.0.1", port: 30001 });

    await expect(reserveDistinctLocalTcpPorts(2, reserve)).resolves.toEqual([
      { host: "127.0.0.1", port: 30000 },
      { host: "127.0.0.1", port: 30001 }
    ]);
    expect(reserve).toHaveBeenCalledTimes(3);
  });

  it("resolves only after every requested listener accepts connections", async () => {
    network.outcomes.push(true, true);
    const processHandle = new FakeProcess();

    await expect(waitForProcessStartup(processHandle as unknown as XrayProcess, [
      { host: "127.0.0.1", port: 30000 },
      { host: "127.0.0.1", port: 30001 }
    ], {
      timeoutMs: 500,
      retryIntervalMs: 5,
      connectTimeoutMs: 50
    })).resolves.toBeUndefined();
    expect(network.createConnection).toHaveBeenCalledTimes(2);
  });

  it("rejects and names listeners that never become ready", async () => {
    network.outcomes.push(false, false, false, false, false, false, false, false);
    const processHandle = new FakeProcess();

    await expect(waitForProcessStartup(processHandle as unknown as XrayProcess, [
      { host: "127.0.0.1", port: 30002 }
    ], {
      timeoutMs: 10,
      retryIntervalMs: 2,
      connectTimeoutMs: 1
    })).rejects.toThrow("127.0.0.1:30002");
  });

  it("cancels listener polling through an external lifecycle signal", async () => {
    network.outcomes.push(false);
    const processHandle = new FakeProcess();
    const controller = new AbortController();
    const waiting = waitForProcessStartup(processHandle as unknown as XrayProcess, [
      { host: "127.0.0.1", port: 30003 }
    ], { timeoutMs: 10_000, signal: controller.signal });

    controller.abort();
    await expect(waiting).rejects.toThrow("cancelled");
  });

  it("stops waiting at an absolute deadline when a child never emits close", async () => {
    vi.useFakeTimers();
    try {
      const processHandle = new FakeProcess();
      const terminating = terminateProcess(processHandle as unknown as XrayProcess);

      await vi.advanceTimersByTimeAsync(3000);
      await expect(terminating).resolves.toBeUndefined();
      expect(processHandle.kill).toHaveBeenNthCalledWith(1, "SIGTERM");
      expect(processHandle.kill).toHaveBeenNthCalledWith(2, "SIGKILL");
      expect(processHandle.listenerCount("close")).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

class FakeProcess extends EventEmitter {
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  readonly kill = vi.fn(() => true);
}
