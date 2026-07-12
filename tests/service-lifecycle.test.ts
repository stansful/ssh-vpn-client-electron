import { afterEach, describe, expect, it, vi } from "vitest";
import { Socks5Proxy } from "../src/core/network/socks5-proxy.js";
import type { WindowsSystemProxyManager } from "../src/core/network/windows-system-proxy.js";
import { SshLiveClient, type SshLiveClientEvent } from "../src/core/ssh/live-client.js";
import { LiveSshServiceBridge } from "../src/service/live-ssh-service.js";
import type { ConnectRequest, RuntimeStatus } from "../src/shared/types.js";

describe("live SSH service lifecycle", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("closes a superseded client before the latest connect becomes active", async () => {
    const firstConnect = deferred<SshLiveClient>();
    const firstClient = new FakeSshClient();
    const secondClient = new FakeSshClient();
    vi.spyOn(SshLiveClient, "connect")
      .mockReturnValueOnce(firstConnect.promise)
      .mockResolvedValueOnce(secondClient.asClient());
    vi.spyOn(Socks5Proxy.prototype, "start").mockResolvedValue({ host: "127.0.0.1", port: 31080 });
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const service = createService();

    const first = service.connect(connectRequest("first"));
    await vi.waitFor(() => expect(SshLiveClient.connect).toHaveBeenCalledTimes(1));
    const second = service.connect(connectRequest("second"));
    firstConnect.resolve(firstClient.asClient());

    await Promise.all([first, second]);

    expect(firstClient.disconnect).toHaveBeenCalledWith("SSH connection was superseded.");
    expect(secondClient.disconnect).not.toHaveBeenCalled();
    expect(Socks5Proxy.prototype.start).toHaveBeenCalledTimes(1);
    expect(service.getStatus()).toMatchObject({ state: "Connected", activeConfigId: "second", realTunnelAvailable: true });
    await service.dispose();
  });

  it("does not publish or orphan a client acquired after disconnect was requested", async () => {
    const pendingConnect = deferred<SshLiveClient>();
    const client = new FakeSshClient();
    vi.spyOn(SshLiveClient, "connect").mockReturnValue(pendingConnect.promise);
    vi.spyOn(Socks5Proxy.prototype, "start").mockResolvedValue({ host: "127.0.0.1", port: 31081 });
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const service = createService();

    const connecting = service.connect(connectRequest("pending"));
    await vi.waitFor(() => expect(SshLiveClient.connect).toHaveBeenCalledTimes(1));
    const disconnecting = service.disconnect();
    expect(service.getStatus()).toMatchObject({ state: "Disconnecting", realTunnelAvailable: false });
    pendingConnect.resolve(client.asClient());

    await Promise.all([connecting, disconnecting]);

    expect(client.disconnect).toHaveBeenCalledWith("SSH connection was superseded.");
    expect(Socks5Proxy.prototype.start).not.toHaveBeenCalled();
    expect(service.getStatus()).toMatchObject({ state: "Disconnected", realTunnelAvailable: false });
  });

  it("invalidates a failed runtime immediately and restores routing before reconnect", async () => {
    const order: string[] = [];
    const client = new FakeSshClient(order);
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
    vi.spyOn(Socks5Proxy.prototype, "start").mockResolvedValue({ host: "127.0.0.1", port: 31082 });
    vi.spyOn(Socks5Proxy.prototype, "stop").mockImplementation(async () => {
      order.push("stop-proxy");
    });
    const service = createService(order);
    await service.connect(connectRequest("runtime"));
    order.length = 0;

    client.emit({ type: "error", error: new Error("transport failed") });

    expect(service.getStatus()).toMatchObject({ state: "Error", realTunnelAvailable: false });
    await vi.waitFor(() => expect(service.getStatus().state).toBe("Reconnecting"));
    expect(order).toEqual(["restore-routing", "stop-proxy", "disconnect-client"]);
    await service.dispose();
  });

  it("does not retry an explicitly pinned host fingerprint mismatch", async () => {
    const mismatchError = new Error("SSH server fingerprint mismatch.");
    vi.spyOn(SshLiveClient, "connect").mockRejectedValue(mismatchError);
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const service = createService();

    await service.connect(connectRequest("untrusted"));

    expect(service.getStatus()).toMatchObject({ state: "Error", realTunnelAvailable: false });
    expect((service as unknown as { reconnectTimer?: NodeJS.Timeout }).reconnectTimer).toBeUndefined();
    await service.dispose();
  });

  it("serializes terminal open/close and opens only one SSH session channel", async () => {
    const client = new FakeSshClient();
    const shellOpening = deferred<undefined>();
    client.openShell.mockImplementation(() => shellOpening.promise);
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
    vi.spyOn(Socks5Proxy.prototype, "start").mockResolvedValue({ host: "127.0.0.1", port: 31083 });
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const service = createService();
    await service.connect(connectRequest("terminal"));

    const firstOpen = service.openTerminal();
    const secondOpen = service.openTerminal();
    await vi.waitFor(() => expect(client.openShell).toHaveBeenCalledTimes(1));
    const closeDuringOpen = service.closeTerminal();
    shellOpening.resolve(undefined);

    await Promise.all([firstOpen, secondOpen, closeDuringOpen]);
    expect(client.openShell).toHaveBeenCalledTimes(1);
    expect(client.closeShell).toHaveBeenCalledTimes(1);
    expect((service as unknown as { shellOpen: boolean }).shellOpen).toBe(false);
    await service.dispose();
  });

  it("does not publish Connected until system routing succeeds and cleans up routing failures", async () => {
    const client = new FakeSshClient();
    const routing = deferred<{ applied: boolean; message: string }>();
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
    vi.spyOn(Socks5Proxy.prototype, "start").mockResolvedValue({ host: "127.0.0.1", port: 31084 });
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const systemProxy = {
      apply: vi.fn(() => routing.promise),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const service = new LiveSshServiceBridge(initialStatus(), { systemProxy });

    const connecting = service.connect(connectRequest("routing"));
    await vi.waitFor(() => expect(systemProxy.apply).toHaveBeenCalledTimes(1));
    expect(service.getStatus()).toMatchObject({ state: "Connecting", realTunnelAvailable: false });

    routing.reject(new Error("routing apply failed"));
    await connecting;

    expect(service.getStatus()).not.toMatchObject({ state: "Connected" });
    expect(service.getStatus().realTunnelAvailable).toBe(false);
    expect(Socks5Proxy.prototype.stop).toHaveBeenCalled();
    expect(client.disconnect).toHaveBeenCalledWith("SSH connection setup failed.");
    await service.dispose();
  });

  it("resets terminal state after a remote close so the shell can be reopened", async () => {
    const client = new FakeSshClient();
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
    vi.spyOn(Socks5Proxy.prototype, "start").mockResolvedValue({ host: "127.0.0.1", port: 31085 });
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const service = createService();
    await service.connect(connectRequest("remote-shell-close"));

    await service.openTerminal();
    expect(client.openShell).toHaveBeenCalledTimes(1);
    client.emit({ type: "terminal-close" });
    expect((service as unknown as { shellOpen: boolean }).shellOpen).toBe(false);

    await service.openTerminal();
    expect(client.openShell).toHaveBeenCalledTimes(2);
    await service.dispose();
  });

  it("re-reads the energy-aware process routing interval and retains IPs for three cycles", () => {
    let refreshIntervalMs = 60_000;
    const systemProxy = {
      apply: vi.fn(async () => ({ applied: true, message: "applied" })),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy,
      processRoutingRefreshIntervalMs: () => refreshIntervalMs
    });
    const internals = service as unknown as {
      currentProcessRoutingRefreshIntervalMs(): number;
      currentProcessRoutingTtlMs(): number;
      nextProcessRoutingRefreshIntervalMs(): number;
    };

    expect(internals.currentProcessRoutingRefreshIntervalMs()).toBe(60_000);
    expect(internals.currentProcessRoutingTtlMs()).toBe(5 * 60_000);
    expect([
      internals.nextProcessRoutingRefreshIntervalMs(),
      internals.nextProcessRoutingRefreshIntervalMs(),
      internals.nextProcessRoutingRefreshIntervalMs(),
      internals.nextProcessRoutingRefreshIntervalMs(),
      internals.nextProcessRoutingRefreshIntervalMs()
    ]).toEqual([1_000, 2_000, 4_000, 8_000, 60_000]);
    refreshIntervalMs = 120_000;
    expect(internals.currentProcessRoutingRefreshIntervalMs()).toBe(120_000);
    expect(internals.currentProcessRoutingTtlMs()).toBe(360_000);
  });

  it("learns a late process connection during the discovery burst and reapplies routing", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    vi.useFakeTimers();
    const client = new FakeSshClient();
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
    vi.spyOn(Socks5Proxy.prototype, "start").mockResolvedValue({ host: "127.0.0.1", port: 31086 });
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const systemProxy = {
      apply: vi.fn()
        .mockResolvedValue({ applied: true, message: "applied" })
        .mockResolvedValueOnce({ applied: true, message: "initial" })
        .mockRejectedValueOnce(new Error("temporary PAC publish failure")),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const processConnectionsProvider = vi.fn()
      .mockResolvedValue([{
        processName: "Telegram.exe",
        remoteAddress: "149.154.167.41",
        remotePort: 443,
        state: "Established"
      }])
      .mockResolvedValueOnce([]);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy,
      processConnectionsProvider,
      processRoutingRefreshIntervalMs: () => 30_000
    });
    const request: ConnectRequest = {
      ...connectRequest("process-routing"),
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
      await vi.advanceTimersByTimeAsync(2_000);

      expect(systemProxy.apply).toHaveBeenCalledTimes(3);
      expect(vi.mocked(systemProxy.apply).mock.calls[2][0]).toMatchObject({
        mode: "selected-rules",
        socksHost: "127.0.0.1",
        socksPort: 31086,
        forcePacEndpointRotation: true,
        rules: expect.arrayContaining([
          expect.objectContaining({ type: "process.name", value: "telegram", enabled: true }),
          expect.objectContaining({ type: "ip", value: "149.154.167.41", enabled: true })
        ])
      });
      await vi.advanceTimersByTimeAsync(4_000);
      expect(systemProxy.apply).toHaveBeenCalledTimes(3);
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

  it("drops learned IPs immediately when the selected process target changes", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const systemProxy = {
      apply: vi.fn(async () => ({ applied: true, message: "applied" })),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const processConnectionsProvider = vi.fn(async (names: Iterable<string>) => {
      const processName = [...names][0];
      return processName === "telegram.exe"
        ? [{ processName, remoteAddress: "149.154.167.41", remotePort: 443, state: "Established" }]
        : [{ processName: "chrome.exe", remoteAddress: "142.250.74.110", remotePort: 443, state: "Established" }];
    });
    const service = new LiveSshServiceBridge(initialStatus(), { systemProxy, processConnectionsProvider });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
    };
    const processRequest = (value: string): ConnectRequest => ({
      ...connectRequest(value),
      routingMode: "selected-rules",
      routingRules: [{ id: value, type: "process.name", value, enabled: true, createdAt: "", updatedAt: "" }]
    });

    try {
      await internals.learnProcessRoutingIps(processRequest("telegram"));
      expect(internals.currentProcessRoutingIps()).toEqual(new Set(["149.154.167.41"]));

      await internals.learnProcessRoutingIps(processRequest("chrome"));
      expect(internals.currentProcessRoutingIps()).toEqual(new Set(["142.250.74.110"]));
    } finally {
      try {
        await service.dispose();
      } finally {
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("retries a failed connected target change without restoring the removed process IP", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    vi.useFakeTimers();
    const client = new FakeSshClient();
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
    vi.spyOn(Socks5Proxy.prototype, "start").mockResolvedValue({ host: "127.0.0.1", port: 31087 });
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const systemProxy = {
      apply: vi.fn()
        .mockResolvedValue({ applied: true, message: "applied" })
        .mockResolvedValueOnce({ applied: true, message: "initial" })
        .mockRejectedValueOnce(new Error("temporary target PAC failure")),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const processConnectionsProvider = vi.fn(async (names: Iterable<string>) => {
      const target = [...names][0];
      return target === "telegram.exe"
        ? [{ processName: target, remoteAddress: "149.154.167.41", remotePort: 443, state: "Established" }]
        : [{ processName: "chrome.exe", remoteAddress: "142.250.74.110", remotePort: 443, state: "Established" }];
    });
    const service = new LiveSshServiceBridge(initialStatus(), { systemProxy, processConnectionsProvider });
    const processRule = (value: string) => ({
      id: value,
      type: "process.name" as const,
      value,
      enabled: true,
      createdAt: "",
      updatedAt: ""
    });
    const initialRequest: ConnectRequest = {
      ...connectRequest("target-change"),
      routingMode: "selected-rules",
      routingRules: [processRule("telegram")]
    };

    try {
      await service.connect(initialRequest);
      await expect(service.updateRoutingRules([processRule("chrome")])).rejects.toThrow("temporary target PAC failure");
      expect(systemProxy.apply).toHaveBeenCalledTimes(2);

      await vi.advanceTimersByTimeAsync(1_000);

      expect(systemProxy.apply).toHaveBeenCalledTimes(3);
      const retriedRules = vi.mocked(systemProxy.apply).mock.calls[2][0].rules;
      expect(vi.mocked(systemProxy.apply).mock.calls[2][0].forcePacEndpointRotation).toBe(true);
      expect(retriedRules).toEqual(expect.arrayContaining([
        expect.objectContaining({ type: "process.name", value: "chrome" }),
        expect.objectContaining({ type: "ip", value: "142.250.74.110" })
      ]));
      expect(retriedRules).not.toEqual(expect.arrayContaining([
        expect.objectContaining({ type: "ip", value: "149.154.167.41" })
      ]));
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
});

class FakeSshClient {
  private listener: ((event: SshLiveClientEvent) => void) | undefined;
  readonly disconnect = vi.fn(async () => {
    this.order?.push("disconnect-client");
  });
  readonly openShell = vi.fn(async () => undefined);
  readonly closeShell = vi.fn(async () => undefined);
  readonly writeShell = vi.fn(async () => undefined);
  readonly checkTunnel = vi.fn(async () => undefined);

  constructor(private readonly order?: string[]) {}

  onEvent(listener: (event: SshLiveClientEvent) => void): () => void {
    this.listener = listener;
    return () => {
      if (this.listener === listener) {
        this.listener = undefined;
      }
    };
  }

  emit(event: SshLiveClientEvent): void {
    this.listener?.(event);
  }

  asClient(): SshLiveClient {
    return this as unknown as SshLiveClient;
  }
}

function createService(order?: string[]): LiveSshServiceBridge {
  const systemProxy = {
    apply: vi.fn(async () => ({ applied: true, message: "applied" })),
    restore: vi.fn(async () => {
      order?.push("restore-routing");
    })
  } as unknown as WindowsSystemProxyManager;
  return new LiveSshServiceBridge(initialStatus(), { systemProxy });
}

function connectRequest(id: string): ConnectRequest {
  return {
    config: {
      id,
      name: id,
      host: `${id}.example.com`,
      port: 22,
      username: "user",
      authType: "password",
      expectedServerFingerprint: "SHA256:test",
      keepaliveIntervalSec: 30,
      note: "",
      createdAt: "",
      updatedAt: ""
    },
    routingMode: "proxy-all",
    routingRules: [],
    routingProxyDomains: [],
    routingDirectDomains: [],
    checkEndpoint: "example.com:443",
    secrets: { password: "secret" }
  };
}

function initialStatus(): RuntimeStatus {
  return {
    state: "Disconnected",
    message: "",
    reconnectAttempt: 0,
    transport: "live-ssh",
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

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void; reject(error: Error): void } {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((innerResolve, innerReject) => {
    resolve = innerResolve;
    reject = innerReject;
  });
  return { promise, resolve, reject };
}
