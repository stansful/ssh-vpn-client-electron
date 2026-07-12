import { EventEmitter } from "node:events";
import { rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WindowsSystemProxyManager } from "../src/core/network/windows-system-proxy.js";
import type { ProxyConnectRequest, RuntimeStatus } from "../src/shared/types.js";

const runtime = vi.hoisted(() => ({
  reserveDistinctLocalTcpPorts: vi.fn(),
  terminateProcess: vi.fn(),
  waitForProcessStartup: vi.fn()
}));
const childProcess = vi.hoisted(() => ({ spawn: vi.fn() }));

vi.mock("../src/service/xray/process-utils.js", () => runtime);
vi.mock("node:child_process", () => ({ execFile: vi.fn(), spawn: childProcess.spawn }));

import { XrayServiceBridge } from "../src/service/xray-service.js";

const runtimeDirectories = new Set<string>();

describe("Xray service lifecycle", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    runtime.reserveDistinctLocalTcpPorts.mockResolvedValue([
      { host: "127.0.0.1", port: 32000 },
      { host: "127.0.0.1", port: 32001 }
    ]);
    runtime.waitForProcessStartup.mockResolvedValue(undefined);
    runtime.terminateProcess.mockResolvedValue(undefined);
  });

  afterEach(async () => {
    await Promise.all([...runtimeDirectories].map((directory) => rm(directory, { recursive: true, force: true })));
    runtimeDirectories.clear();
  });

  it("terminates a process acquired after disconnect was requested", async () => {
    const startup = deferred<void>();
    const processHandle = new FakeXrayProcess();
    runtime.waitForProcessStartup.mockReturnValueOnce(startup.promise);
    childProcess.spawn.mockReturnValueOnce(processHandle);
    const service = createService("disconnect-pending");

    const connecting = service.connect(proxyRequest("pending"));
    await vi.waitFor(() => expect(runtime.waitForProcessStartup).toHaveBeenCalledWith(processHandle, [
      { host: "127.0.0.1", port: 32000 },
      { host: "127.0.0.1", port: 32001 }
    ], expect.objectContaining({ signal: expect.any(AbortSignal) })));
    const disconnecting = service.disconnect();
    expect(service.getStatus()).toMatchObject({ state: "Disconnecting", realTunnelAvailable: false });
    startup.resolve(undefined);

    await Promise.all([connecting, disconnecting]);

    expect(runtime.terminateProcess).toHaveBeenCalledWith(processHandle);
    expect(service.getStatus()).toMatchObject({ state: "Disconnected", realTunnelAvailable: false });
  });

  it("ignores a late close callback from the process replaced by a newer connect", async () => {
    const firstProcess = new FakeXrayProcess();
    const secondProcess = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(firstProcess).mockReturnValueOnce(secondProcess);
    const service = createService("late-close");

    await service.connect(proxyRequest("first"));
    await service.connect(proxyRequest("second"));
    expect(service.getStatus()).toMatchObject({ state: "Connected", activeConfigId: "second", realTunnelAvailable: true });

    firstProcess.emit("close", 1, null);
    await Promise.resolve();

    expect(service.getStatus()).toMatchObject({ state: "Connected", activeConfigId: "second", realTunnelAvailable: true });
    expect(runtime.terminateProcess).not.toHaveBeenCalledWith(secondProcess);
    await service.dispose();
  });

  it("waits for both listeners before applying PAC and reporting Connected", async () => {
    const startup = deferred<void>();
    const processHandle = new FakeXrayProcess();
    const systemProxy = fakeSystemProxy();
    runtime.waitForProcessStartup.mockReturnValueOnce(startup.promise);
    childProcess.spawn.mockReturnValueOnce(processHandle);
    const service = createService("listener-readiness", systemProxy);

    const connecting = service.connect(proxyRequest("listeners"));
    await vi.waitFor(() => expect(runtime.waitForProcessStartup).toHaveBeenCalled());
    expect(service.getStatus()).toMatchObject({ state: "Connecting", realTunnelAvailable: false });
    expect(systemProxy.apply).not.toHaveBeenCalled();

    startup.resolve(undefined);
    await connecting;

    expect(systemProxy.apply).toHaveBeenCalledTimes(1);
    expect(service.getStatus()).toMatchObject({ state: "Connected", realTunnelAvailable: true });
    await service.dispose();
  });

  it("cancels listener polling immediately when disconnect supersedes startup", async () => {
    const processHandle = new FakeXrayProcess();
    runtime.waitForProcessStartup.mockImplementationOnce(async (_process, _endpoints, options) =>
      new Promise<void>((_resolve, reject) => {
        options.signal.addEventListener("abort", () => reject(new Error("cancelled")), { once: true });
      })
    );
    childProcess.spawn.mockReturnValueOnce(processHandle);
    const service = createService("listener-cancel");

    const connecting = service.connect(proxyRequest("cancel"));
    await vi.waitFor(() => expect(runtime.waitForProcessStartup).toHaveBeenCalled());
    const disconnecting = service.disconnect();
    await Promise.all([connecting, disconnecting]);

    expect(runtime.terminateProcess).toHaveBeenCalledWith(processHandle);
    expect(service.getStatus()).toMatchObject({ state: "Disconnected", realTunnelAvailable: false });
  });

  it("cleans up the process and routing when listener readiness fails", async () => {
    const processHandle = new FakeXrayProcess();
    const systemProxy = fakeSystemProxy();
    runtime.waitForProcessStartup.mockRejectedValueOnce(new Error("listeners timed out"));
    childProcess.spawn.mockReturnValueOnce(processHandle);
    const service = createService("listener-timeout", systemProxy);

    await service.connect(proxyRequest("timeout"));

    expect(runtime.terminateProcess).toHaveBeenCalledWith(processHandle);
    expect(systemProxy.apply).not.toHaveBeenCalled();
    expect(systemProxy.restore).toHaveBeenCalled();
    expect(service.getStatus()).toMatchObject({ state: "Error", realTunnelAvailable: false });
    await service.dispose();
  });

  it("invalidates runtime availability before asynchronously cleaning up a failed process", async () => {
    const processHandle = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(processHandle);
    const systemProxy = fakeSystemProxy();
    const service = createService("runtime-close", systemProxy);
    await service.connect(proxyRequest("runtime"));
    vi.mocked(systemProxy.restore).mockClear();

    processHandle.emit("close", 9, null);

    expect(service.getStatus()).toMatchObject({ state: "Error", realTunnelAvailable: false });
    await vi.waitFor(() => expect(service.getStatus().state).toBe("Reconnecting"));
    expect(systemProxy.restore).toHaveBeenCalled();
    expect(runtime.terminateProcess).toHaveBeenCalledWith(processHandle);
    await service.dispose();
  });

  it("learns a late process connection during the discovery burst and reapplies PAC routing", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    vi.useFakeTimers();
    const processHandle = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(processHandle);
    const systemProxy = fakeSystemProxy();
    const processConnectionsProvider = vi.fn()
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{
        processName: "Telegram.exe",
        remoteAddress: "149.154.167.41",
        remotePort: 443,
        state: "Established"
      }]);
    const runtimeDirectory = path.join(os.tmpdir(), `shadow-ssh-xray-lifecycle-${process.pid}-process-routing`);
    runtimeDirectories.add(runtimeDirectory);
    const service = new XrayServiceBridge(initialStatus(), {
      executablePath: process.execPath,
      runtimeDirectory,
      systemProxy,
      processConnectionsProvider,
      processRoutingRefreshIntervalMs: () => 30_000
    });
    const request: ProxyConnectRequest = {
      ...proxyRequest("process-routing"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "telegram",
        type: "process.name",
        value: "telegram",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };

    try {
      await service.connect(request);
      expect(systemProxy.apply).toHaveBeenCalledTimes(1);
      expect([...processConnectionsProvider.mock.calls[0][0]]).toEqual(["telegram.exe"]);

      await vi.advanceTimersByTimeAsync(1_000);

      expect(systemProxy.apply).toHaveBeenCalledTimes(2);
      expect(vi.mocked(systemProxy.apply).mock.calls[1][0]).toMatchObject({
        proxyProtocol: "http",
        forcePacEndpointRotation: true,
        rules: expect.arrayContaining([
          expect.objectContaining({ type: "ip", value: "149.154.167.41", enabled: true })
        ])
      });
    } finally {
      try {
        await service.dispose();
      } finally {
        vi.useRealTimers();
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("bounds runtime log work and keeps suppressed child pipes draining", async () => {
    const processHandle = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(processHandle);
    const service = createService("log-drain");
    const diagnostics: string[] = [];
    const off = service.onEvent((event) => {
      if (event.type === "diagnostics-appended") {
        diagnostics.push(event.entry.message);
      }
    });
    await service.connect(proxyRequest("logs"));

    processHandle.stdout.emit("data", `${"x".repeat(10_000)}\n`);
    processHandle.stderr.emit(
      "data",
      Array.from({ length: 100 }, (_, index) => `warning-${index}`).join("\n")
    );

    const xrayLines = diagnostics.filter((message) => message.startsWith("Xray: "));
    expect(xrayLines[0]?.length).toBeLessThanOrEqual(4103);
    expect(xrayLines).toHaveLength(79);
    expect(diagnostics.filter((message) => message.includes("Further Xray runtime diagnostics"))).toHaveLength(1);
    expect(processHandle.stdout.listenerCount("data")).toBe(0);
    expect(processHandle.stderr.listenerCount("data")).toBe(0);
    expect(processHandle.stdout.resume).toHaveBeenCalled();
    expect(processHandle.stderr.resume).toHaveBeenCalled();

    const countAfterSuppression = diagnostics.length;
    processHandle.stderr.emit("data", "not-parsed\n");
    expect(diagnostics).toHaveLength(countAfterSuppression);
    off();
    await service.dispose();
  });

  it("removes process log parsers during normal lifecycle cleanup", async () => {
    const processHandle = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(processHandle);
    const service = createService("log-cleanup");
    await service.connect(proxyRequest("cleanup"));

    expect(processHandle.stdout.listenerCount("data")).toBe(1);
    expect(processHandle.stderr.listenerCount("data")).toBe(1);
    await service.dispose();

    expect(processHandle.stdout.listenerCount("data")).toBe(0);
    expect(processHandle.stderr.listenerCount("data")).toBe(0);
    expect(processHandle.stdout.resume).toHaveBeenCalled();
    expect(processHandle.stderr.resume).toHaveBeenCalled();
  });
});

class FakeOutput extends EventEmitter {
  readonly resume = vi.fn(() => this);

  setEncoding(): this {
    return this;
  }
}

class FakeXrayProcess extends EventEmitter {
  readonly stdout = new FakeOutput();
  readonly stderr = new FakeOutput();
  readonly stdin = null;
  readonly kill = vi.fn(() => true);
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
}

function createService(name: string, systemProxy = fakeSystemProxy()): XrayServiceBridge {
  const runtimeDirectory = path.join(os.tmpdir(), `shadow-ssh-xray-lifecycle-${process.pid}-${name}`);
  runtimeDirectories.add(runtimeDirectory);
  return new XrayServiceBridge(initialStatus(), {
    executablePath: process.execPath,
    runtimeDirectory,
    systemProxy
  });
}

function fakeSystemProxy(): WindowsSystemProxyManager {
  return {
    apply: vi.fn(async () => ({ applied: true, message: "applied" })),
    restore: vi.fn(async () => undefined)
  } as unknown as WindowsSystemProxyManager;
}

function proxyRequest(id: string): ProxyConnectRequest {
  return {
    profile: {
      id,
      name: id,
      protocol: "vless",
      host: "example.com",
      port: 443,
      transport: "tcp",
      security: "tls",
      flow: "",
      source: "manual",
      rawUriSecretId: "secret",
      fingerprint: id,
      isSelected: true,
      isPinned: false,
      isStale: false,
      lastTestStatus: "unknown",
      createdAt: "",
      updatedAt: "",
      lastSeenAt: ""
    },
    routingMode: "proxy-all",
    routingRules: [],
    routingProxyDomains: [],
    routingDirectDomains: [],
    checkEndpoint: "example.com:443",
    secrets: {
      rawUri: "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=tcp&security=tls#test"
    }
  };
}

function initialStatus(): RuntimeStatus {
  return {
    state: "Disconnected",
    message: "",
    reconnectAttempt: 0,
    transport: "xray",
    platformTarget: {
      platform: "unknown",
      arch: "unknown",
      serviceExecutableName: "",
      serviceRelativePath: "",
      supportsPrivilegedService: false
    },
    realTunnelAvailable: false
  };
}

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((innerResolve) => {
    resolve = innerResolve;
  });
  return { promise, resolve };
}
