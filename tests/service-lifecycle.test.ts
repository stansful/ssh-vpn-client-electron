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

  it("publishes a literal process IP before DNS enrichment and then adds the hostname route", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const client = new FakeSshClient();
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
    vi.spyOn(Socks5Proxy.prototype, "start").mockResolvedValue({ host: "127.0.0.1", port: 31087 });
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const systemProxy = {
      apply: vi.fn(async () => ({ applied: true, message: "applied" })),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const address = "8.8.4.4";
    const domain = "media.generic-client.example";
    const dnsEnrichment = deferred<Array<{ address: string; domain: string; ttlSeconds: number }>>();
    let dnsResolved = false;
    const processDnsEntriesProvider = vi.fn(() => dnsEnrichment.promise);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy,
      processConnectionsProvider: vi.fn(async () => [{
        processName: "generic-client.exe",
        remoteAddress: address,
        remotePort: 443,
        state: "Established"
      }]),
      processDnsEntriesProvider
    });
    const request: ConnectRequest = {
      ...connectRequest("literal-ip-before-dns"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "generic-client",
        type: "process.name",
        value: "generic-client.exe",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };
    const connecting = service.connect(request);

    try {
      await vi.waitFor(() => expect(processDnsEntriesProvider).toHaveBeenCalledTimes(1));
      expect(systemProxy.apply).toHaveBeenCalledTimes(1);
      const literalIpPublish = vi.mocked(systemProxy.apply).mock.calls[0][0];
      expect(literalIpPublish.rules).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: `process-ip:${address}`, type: "ip", value: address, enabled: true })
      ]));
      expect(literalIpPublish.rules).not.toEqual(expect.arrayContaining([
        expect.objectContaining({ id: `process-domain:${domain}` })
      ]));

      dnsResolved = true;
      dnsEnrichment.resolve([{ address, domain, ttlSeconds: 60 }]);
      await connecting;

      expect(systemProxy.apply).toHaveBeenCalledTimes(2);
      expect(vi.mocked(systemProxy.apply).mock.calls[1][0].rules).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: `process-domain:${domain}`, type: "domain", value: domain, enabled: true })
      ]));
    } finally {
      if (!dnsResolved) {
        dnsEnrichment.resolve([]);
        await connecting;
      }
      try {
        await service.dispose();
      } finally {
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("does not publish an interim process IP when explicit direct domains are configured", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const address = "8.8.8.8";
    const dnsEnrichment = deferred<Array<{ address: string; domain: string; ttlSeconds: number }>>();
    let dnsResolved = false;
    const processDnsEntriesProvider = vi.fn(() => dnsEnrichment.promise);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy: {
        apply: vi.fn(async () => ({ applied: true, message: "applied" })),
        restore: vi.fn(async () => undefined)
      } as unknown as WindowsSystemProxyManager,
      processConnectionsProvider: vi.fn(async () => [{
        processName: "generic-direct-client.exe",
        remoteAddress: address,
        remotePort: 443,
        state: "Established"
      }]),
      processDnsEntriesProvider
    });
    const publishLiteralIpSnapshot = vi.fn(async () => undefined);
    const request: ConnectRequest = {
      ...connectRequest("direct-domain-no-interim-ip"),
      routingMode: "selected-rules",
      routingDirectDomains: [".direct.example"],
      routingRules: [{
        id: "generic-direct-client",
        type: "process.name",
        value: "generic-direct-client.exe",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };
    const learning = (service as unknown as {
      learnProcessRoutingIps(
        request: ConnectRequest,
        generation: undefined,
        publish: (signature: string) => Promise<void>
      ): Promise<boolean>;
    }).learnProcessRoutingIps(request, undefined, publishLiteralIpSnapshot);

    try {
      await vi.waitFor(() => expect(processDnsEntriesProvider).toHaveBeenCalledTimes(1));
      expect(publishLiteralIpSnapshot).not.toHaveBeenCalled();
      dnsResolved = true;
      dnsEnrichment.resolve([{ address, domain: "media.direct.example", ttlSeconds: 60 }]);
      await learning;
    } finally {
      if (!dnsResolved) {
        dnsEnrichment.resolve([]);
        await learning;
      }
      try {
        await service.dispose();
      } finally {
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("hot-adds a process rule and learns its next connection without reconnecting SSH", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    vi.useFakeTimers();
    const client = new FakeSshClient();
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
    vi.spyOn(Socks5Proxy.prototype, "start").mockResolvedValue({ host: "127.0.0.1", port: 31089 });
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const systemProxy = {
      apply: vi.fn(async () => ({ applied: true, message: "applied" })),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const processConnectionsProvider = vi.fn()
      .mockResolvedValueOnce([])
      .mockResolvedValue([{
        processName: "Chrome.exe",
        remoteAddress: "142.250.74.110",
        remotePort: 443,
        state: "Established"
      }]);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy,
      processConnectionsProvider,
      processRoutingRefreshIntervalMs: () => 30_000
    });
    const initialRequest: ConnectRequest = {
      ...connectRequest("hot-add-process"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "bootstrap-domain",
        type: "domain",
        value: "bootstrap.example",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };
    const chromeRule = {
      id: "chrome",
      type: "process.name" as const,
      value: "chrome.exe",
      enabled: true,
      createdAt: "",
      updatedAt: ""
    };

    try {
      await service.connect(initialRequest);
      expect(SshLiveClient.connect).toHaveBeenCalledTimes(1);
      expect(processConnectionsProvider).not.toHaveBeenCalled();

      await service.updateRouting({
        routingMode: "selected-rules",
        routingRules: [...initialRequest.routingRules, chromeRule],
        routingProxyDomains: [],
        routingDirectDomains: [],
        checkEndpoint: initialRequest.checkEndpoint
      });

      expect(systemProxy.apply).toHaveBeenCalledTimes(2);
      expect([...processConnectionsProvider.mock.calls[0][0]]).toEqual(["chrome.exe"]);
      expect(vi.mocked(systemProxy.apply).mock.calls[1][0]).toMatchObject({
        forcePacEndpointRotation: true,
        rules: expect.arrayContaining([
          expect.objectContaining({ type: "process.name", value: "chrome.exe", enabled: true })
        ])
      });
      expect(vi.mocked(systemProxy.apply).mock.calls[1][0].rules).not.toEqual(expect.arrayContaining([
        expect.objectContaining({ type: "ip", value: "142.250.74.110" })
      ]));

      await vi.advanceTimersByTimeAsync(1_000);

      expect(systemProxy.apply).toHaveBeenCalledTimes(3);
      expect(vi.mocked(systemProxy.apply).mock.calls[2][0]).toMatchObject({
        forcePacEndpointRotation: true,
        rules: expect.arrayContaining([
          expect.objectContaining({ type: "process.name", value: "chrome.exe", enabled: true }),
          expect.objectContaining({ type: "ip", value: "142.250.74.110", enabled: true })
        ])
      });
      expect(SshLiveClient.connect).toHaveBeenCalledTimes(1);
      expect(client.disconnect).not.toHaveBeenCalled();
      expect(service.getStatus()).toMatchObject({ state: "Connected", activeConfigId: "hot-add-process" });
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

  it("continues the bounded discovery burst after finding the first process endpoint", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    vi.useFakeTimers();
    const client = new FakeSshClient();
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
    vi.spyOn(Socks5Proxy.prototype, "start").mockResolvedValue({ host: "127.0.0.1", port: 31088 });
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const systemProxy = {
      apply: vi.fn(async () => ({ applied: true, message: "applied" })),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const processConnectionsProvider = vi.fn(async () => [{
      processName: "multi-endpoint.exe",
      remoteAddress: "203.0.113.10",
      remotePort: 443,
      state: "Established"
    }]);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy,
      processConnectionsProvider,
      processRoutingRefreshIntervalMs: () => 30_000
    });
    const request: ConnectRequest = {
      ...connectRequest("process-discovery-after-first"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "multi-endpoint",
        type: "process.name",
        value: "multi-endpoint.exe",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };

    try {
      await service.connect(request);
      expect(processConnectionsProvider).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(1_000);
      await vi.advanceTimersByTimeAsync(2_000);
      await vi.advanceTimersByTimeAsync(4_000);
      await vi.advanceTimersByTimeAsync(8_000);

      expect(processConnectionsProvider).toHaveBeenCalledTimes(5);
      expect(systemProxy.apply).toHaveBeenCalledTimes(1);
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

  it("publishes an additive exact session lease immediately and keeps it after self-observation", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const systemProxy = {
      apply: vi.fn(async () => ({ applied: true, message: "applied" })),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const address = "8.8.4.4";
    const domain = "gateway.custom-app.example";
    const connection = [{
      processName: "custom-app.exe",
      remoteAddress: address,
      remotePort: 443,
      state: "Established"
    }];
    const processConnectionsProvider = vi.fn()
      .mockResolvedValueOnce(connection)
      .mockResolvedValueOnce(connection)
      .mockResolvedValue([]);
    const processDnsEntriesProvider = vi.fn(async () => [
      { address, domain, ttlSeconds: 30 },
      { address, domain, ttlSeconds: 60 }
    ]);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy,
      processConnectionsProvider,
      processDnsEntriesProvider
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
      processRoutingSessionLeases: Map<string, unknown>;
    };
    const request: ConnectRequest = {
      ...connectRequest("session-domain-lease"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "custom-app",
        type: "process.name",
        value: "custom-app.exe",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);

    try {
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));
      expect(internals.processRoutingSessionLeases.size).toBe(1);

      now.mockReturnValue(1_001_000);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(false);
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(1);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));
      expect(internals.processRoutingSessionLeases.size).toBe(1);

      now.mockReturnValue(1_601_001);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set());
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(1);

      now.mockReturnValue(1_602_001);
      await expect(internals.learnProcessRoutingIps({
        ...request,
        routingDirectDomains: [".custom-app.example"]
      })).resolves.toBe(true);
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set());
      expect(internals.processRoutingSessionLeases.size).toBe(0);
    } finally {
      try {
        await service.dispose();
      } finally {
        now.mockRestore();
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("keeps a PAC route when the only high-confidence process socket disappears before the second scan", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const address = "8.8.8.8";
    const domain = "api.short-lived-app.example";
    const processConnectionsProvider = vi.fn()
      .mockResolvedValueOnce([{
        processName: "short-lived-app.exe",
        remoteAddress: address,
        remotePort: 443,
        state: "Established"
      }])
      .mockResolvedValueOnce([]);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy: {
        apply: vi.fn(async () => ({ applied: true, message: "applied" })),
        restore: vi.fn(async () => undefined)
      } as unknown as WindowsSystemProxyManager,
      processConnectionsProvider,
      processDnsEntriesProvider: vi.fn(async () => [{ address, domain, ttlSeconds: 60 }])
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
    };
    const request: ConnectRequest = {
      ...connectRequest("short-lived-process-route"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "short-lived-app",
        type: "process.name",
        value: "short-lived-app.exe",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };
    const now = vi.spyOn(Date, "now").mockReturnValue(5_000_000);

    try {
      await internals.learnProcessRoutingIps(request);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));

      now.mockReturnValue(5_001_000);
      await internals.learnProcessRoutingIps(request);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));
    } finally {
      try {
        await service.dispose();
      } finally {
        now.mockRestore();
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("keeps additive IP and TTL routes when the session-lease bootstrap probe becomes ambiguous", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const address = "8.8.8.8";
    const firstDomain = "api.ambiguous-app.example";
    const secondDomain = "cdn.ambiguous-app.example";
    const connection = [{
      processName: "ambiguous-app.exe",
      remoteAddress: address,
      remotePort: 443,
      state: "Established"
    }];
    const processDnsEntriesProvider = vi.fn()
      .mockResolvedValueOnce([{ address, domain: firstDomain, ttlSeconds: 60 }])
      .mockResolvedValueOnce([
        { address, domain: firstDomain, ttlSeconds: 60 },
        { address, domain: secondDomain, ttlSeconds: 60 }
      ]);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy: {
        apply: vi.fn(async () => ({ applied: true, message: "applied" })),
        restore: vi.fn(async () => undefined)
      } as unknown as WindowsSystemProxyManager,
      processConnectionsProvider: vi.fn(async () => connection),
      processDnsEntriesProvider
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
      processRoutingSessionLeases: Map<string, unknown>;
    };
    const request: ConnectRequest = {
      ...connectRequest("ambiguous-session-domain"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "ambiguous-app",
        type: "process.name",
        value: "ambiguous-app.exe",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };
    const now = vi.spyOn(Date, "now").mockReturnValue(2_000_000);

    try {
      await internals.learnProcessRoutingIps(request);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([firstDomain]));
      expect(internals.processRoutingSessionLeases.size).toBe(1);

      now.mockReturnValue(2_010_000);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([firstDomain, secondDomain]));
      expect(internals.processRoutingSessionLeases.size).toBe(1);
    } finally {
      try {
        await service.dispose();
      } finally {
        now.mockRestore();
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("restores IP fallback when a leased-address DNS probe fails or changes tuple", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const address = "4.2.2.2";
    const leasedDomain = "api.probed-app.example";
    const addedDomain = "cdn.probed-app.example";
    const processDnsEntriesProvider = vi.fn()
      .mockResolvedValueOnce([{ address, domain: leasedDomain, ttlSeconds: 120 }])
      .mockRejectedValueOnce(new Error("DNS cache unavailable"))
      .mockResolvedValueOnce([
        { address, domain: leasedDomain, ttlSeconds: 120 },
        { address, domain: addedDomain, ttlSeconds: 120 }
      ]);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy: {
        apply: vi.fn(async () => ({ applied: true, message: "applied" })),
        restore: vi.fn(async () => undefined)
      } as unknown as WindowsSystemProxyManager,
      processConnectionsProvider: vi.fn(async () => [{
        processName: "probed-app.exe",
        remoteAddress: address,
        remotePort: 443,
        state: "Established"
      }]),
      processDnsEntriesProvider
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
      processRoutingSessionLeases: Map<string, unknown>;
    };
    const request: ConnectRequest = {
      ...connectRequest("leased-address-probe"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "probed-app",
        type: "process.name",
        value: "probed-app.exe",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };
    const now = vi.spyOn(Date, "now").mockReturnValue(3_000_000);

    try {
      await internals.learnProcessRoutingIps(request);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([leasedDomain]));
      expect(internals.processRoutingSessionLeases.size).toBe(1);

      now.mockReturnValue(3_001_000);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(false);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([leasedDomain]));

      now.mockReturnValue(3_011_000);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(false);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([leasedDomain]));
      expect(internals.processRoutingSessionLeases.size).toBe(1);

      now.mockReturnValue(3_021_000);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([leasedDomain, addedDomain]));
      expect(internals.processRoutingSessionLeases.size).toBe(1);
    } finally {
      try {
        await service.dispose();
      } finally {
        now.mockRestore();
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("uses ordinary fallback for a public address shared by selected unprofiled processes", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const address = "1.1.1.1";
    const domain = "shared.selected-apps.example";
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy: {
        apply: vi.fn(async () => ({ applied: true, message: "applied" })),
        restore: vi.fn(async () => undefined)
      } as unknown as WindowsSystemProxyManager,
      processConnectionsProvider: vi.fn(async () => [
        { processName: "first-app.exe", remoteAddress: address, remotePort: 443, state: "Established" },
        { processName: "second-app.exe", remoteAddress: address, remotePort: 443, state: "Established" }
      ]),
      processDnsEntriesProvider: vi.fn(async () => [{ address, domain, ttlSeconds: 60 }])
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
      processRoutingSessionLeases: Map<string, unknown>;
    };
    const request: ConnectRequest = {
      ...connectRequest("shared-process-address"),
      routingMode: "selected-rules",
      routingRules: ["first-app.exe", "second-app.exe"].map((value) => ({
        id: value,
        type: "process.name" as const,
        value,
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }))
    };

    try {
      await internals.learnProcessRoutingIps(request);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));
      expect(internals.processRoutingSessionLeases.size).toBe(0);
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

  it("does not lease or learn a domain covered by the explicit direct list", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const address = "9.9.9.9";
    const domain = "api.direct-app.example";
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy: {
        apply: vi.fn(async () => ({ applied: true, message: "applied" })),
        restore: vi.fn(async () => undefined)
      } as unknown as WindowsSystemProxyManager,
      processConnectionsProvider: vi.fn(async () => [{
        processName: "direct-app.exe",
        remoteAddress: address,
        remotePort: 443,
        state: "Established"
      }]),
      processDnsEntriesProvider: vi.fn(async () => [{ address, domain, ttlSeconds: 60 }])
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
      processRoutingSessionLeases: Map<string, unknown>;
    };
    const request: ConnectRequest = {
      ...connectRequest("direct-conflict"),
      routingMode: "selected-rules",
      routingDirectDomains: [".direct-app.example"],
      routingRules: [{
        id: "direct-app",
        type: "process.name",
        value: "direct-app.exe",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };

    try {
      await internals.learnProcessRoutingIps(request);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set());
      expect(internals.processRoutingSessionLeases.size).toBe(0);
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

  it("caps immediate session leases at 256 while keeping additive IP and TTL fallback", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const initialAddresses = Array.from({ length: 257 }, (_unused, index) =>
      index < 254 ? `11.0.0.${index + 1}` : `11.0.1.${index - 253}`
    );
    const overflowAddress = "11.0.1.4";
    let connections = initialAddresses.map((remoteAddress) => ({
      processName: "many-endpoints.exe",
      remoteAddress,
      remotePort: 443,
      state: "Established"
    }));
    const processDnsEntriesProvider = vi.fn(async (addresses: Iterable<string>) => [...addresses].map((address) => ({
      address,
      domain: `endpoint-${address.replace(/\./gu, "-")}.many-endpoints.example`,
      ttlSeconds: 60
    })));
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy: {
        apply: vi.fn(async () => ({ applied: true, message: "applied" })),
        restore: vi.fn(async () => undefined)
      } as unknown as WindowsSystemProxyManager,
      processConnectionsProvider: vi.fn(async () => connections),
      processDnsEntriesProvider
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
      processRoutingSessionLeases: Map<string, unknown>;
    };
    const request: ConnectRequest = {
      ...connectRequest("bounded-session-domains"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "many-endpoints",
        type: "process.name",
        value: "many-endpoints.exe",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };
    const now = vi.spyOn(Date, "now").mockReturnValue(4_000_000);

    try {
      await internals.learnProcessRoutingIps(request);
      expect(internals.processRoutingSessionLeases.size).toBe(256);
      expect(internals.currentProcessRoutingIps().size).toBe(257);
      expect(internals.currentProcessRoutingDomains().size).toBe(257);

      now.mockReturnValue(4_001_000);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(false);
      expect(internals.processRoutingSessionLeases.size).toBe(256);
      expect(internals.currentProcessRoutingIps().size).toBe(257);
      expect(internals.currentProcessRoutingDomains().size).toBe(257);

      connections = [...connections, {
        processName: "many-endpoints.exe",
        remoteAddress: overflowAddress,
        remotePort: 443,
        state: "Established"
      }];
      now.mockReturnValue(4_002_000);
      await internals.learnProcessRoutingIps(request);
      expect(internals.processRoutingSessionLeases.size).toBe(256);
      expect(internals.currentProcessRoutingIps().has(overflowAddress)).toBe(true);
      expect(internals.currentProcessRoutingDomains().has(
        "endpoint-11-0-1-4.many-endpoints.example"
      )).toBe(true);
    } finally {
      try {
        await service.dispose();
      } finally {
        now.mockRestore();
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("learns stable DNS hostnames for arbitrary multi-endpoint processes", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const systemProxy = {
      apply: vi.fn(async () => ({ applied: true, message: "applied" })),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const connection = [{
        processName: "custom-app.exe",
        remoteAddress: "203.0.113.44",
        remotePort: 443,
        state: "Established"
      }];
    const processConnectionsProvider = vi.fn()
      .mockResolvedValueOnce(connection)
      .mockResolvedValueOnce(connection)
      .mockResolvedValueOnce(connection)
      .mockResolvedValue([]);
    let dnsCalls = 0;
    const processDnsEntriesProvider = vi.fn(async (addresses: Iterable<string>) => {
      void addresses;
      dnsCalls += 1;
      return dnsCalls === 1
        ? []
        : [{
            address: "203.0.113.44",
            domain: "gateway.custom.example",
            ttlSeconds: 120
          }];
    });
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy,
      processConnectionsProvider,
      processDnsEntriesProvider
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
    };
    const request: ConnectRequest = {
      ...connectRequest("dns-process-routing"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "custom-app",
        type: "process.name",
        value: "custom-app.exe",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);

    try {
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set(["203.0.113.44"]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set());
      expect([...(processDnsEntriesProvider.mock.calls[0]?.[0] ?? [])]).toEqual(["203.0.113.44"]);

      now.mockReturnValue(1_009_000);
      await internals.learnProcessRoutingIps(request);
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(1);

      now.mockReturnValue(1_010_000);
      await internals.learnProcessRoutingIps(request);
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(2);
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set(["gateway.custom.example"]));

      now.mockReturnValue(1_131_000);
      await internals.learnProcessRoutingIps(request);
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set());
    } finally {
      try {
        await service.dispose();
      } finally {
        now.mockRestore();
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("refreshes a generic exact DNS hostname at its TTL without route churn", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const systemProxy = {
      apply: vi.fn(async () => ({ applied: true, message: "applied" })),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const address = "203.0.113.45";
    const domain = "edge.custom.example";
    const processConnectionsProvider = vi.fn(async () => [{
      processName: "custom-app.exe",
      remoteAddress: address,
      remotePort: 443,
      state: "Established"
    }]);
    const dnsTtls = [30, 60, 60];
    const processDnsEntriesProvider = vi.fn(async () => [{
      address,
      domain,
      ttlSeconds: dnsTtls.shift() ?? 60
    }]);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy,
      processConnectionsProvider,
      processDnsEntriesProvider
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
    };
    const request: ConnectRequest = {
      ...connectRequest("generic-dns-ttl-refresh"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "custom-app",
        type: "process.name",
        value: "custom-app.exe",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);

    try {
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));

      now.mockReturnValue(1_030_000);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(false);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));

      now.mockReturnValue(1_090_000);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(false);
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(3);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));
    } finally {
      try {
        await service.dispose();
      } finally {
        now.mockRestore();
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("expires stale process routes when the next connection snapshot rejects", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const systemProxy = {
      apply: vi.fn(async () => ({ applied: true, message: "applied" })),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const address = "203.0.113.46";
    const domain = "expired.custom.example";
    const processConnectionsProvider = vi.fn()
      .mockResolvedValueOnce([{
        processName: "custom-app.exe",
        remoteAddress: address,
        remotePort: 443,
        state: "Established"
      }])
      .mockRejectedValueOnce(new Error("process snapshot unavailable"));
    const processDnsEntriesProvider = vi.fn(async () => [{
      address,
      domain,
      ttlSeconds: 60
    }]);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy,
      processConnectionsProvider,
      processDnsEntriesProvider
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
    };
    const request: ConnectRequest = {
      ...connectRequest("process-snapshot-expiry"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "custom-app",
        type: "process.name",
        value: "custom-app.exe",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);

    try {
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));

      now.mockReturnValue(1_300_001);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set());
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set());
    } finally {
      try {
        await service.dispose();
      } finally {
        now.mockRestore();
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("seeds Discord host families before connections and avoids a shared Cloudflare IP rule", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const systemProxy = {
      apply: vi.fn(async () => ({ applied: true, message: "applied" })),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const processConnectionsProvider = vi.fn(async () => [
      {
        processName: "Discord.exe",
        remoteAddress: "162.159.138.232",
        remotePort: 443,
        state: "Established"
      },
      {
        processName: "Discord.exe",
        remoteAddress: "198.51.100.77",
        remotePort: 443,
        state: "Established"
      }
    ]);
    const processDnsEntriesProvider = vi.fn()
      .mockResolvedValueOnce([
        {
          address: "162.159.138.232",
          domain: "gateway.discord.gg",
          ttlSeconds: 60
        },
        ...Array.from({ length: 520 }, (_unused, index) => ({
          address: "162.159.138.232",
          domain: `shared-alias-${index}.example.com`,
          ttlSeconds: 60
        }))
      ])
      .mockResolvedValueOnce([{
        address: "162.159.138.232",
        domain: "unrelated.cloudflare.example",
        ttlSeconds: 60
      }]);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy,
      processConnectionsProvider,
      processDnsEntriesProvider
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
    };
    const request: ConnectRequest = {
      ...connectRequest("discord-process-routing"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "discord",
        type: "process.name",
        value: "discord.exe",
        enabled: true,
        createdAt: "",
        updatedAt: ""
      }]
    };
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);

    try {
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set(["198.51.100.77"]));
      const domains = internals.currentProcessRoutingDomains();
      expect([...domains]).toEqual(expect.arrayContaining([
        "discord.com",
        "*.discord.com",
        "*.discord.gg",
        "*.discord.media"
      ]));
      expect(domains.has("gateway.discord.gg")).toBe(false);
      expect([...domains].some((domain) => domain.startsWith("shared-alias-"))).toBe(false);
      expect(domains.size).toBe(10);

      now.mockReturnValue(1_060_001);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(false);
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(2);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set(["198.51.100.77"]));
      expect(internals.currentProcessRoutingDomains().has("unrelated.cloudflare.example")).toBe(false);
    } finally {
      try {
        await service.dispose();
      } finally {
        now.mockRestore();
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("suppresses a formerly shared IP once only the profiled process still owns it", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const systemProxy = {
      apply: vi.fn(async () => ({ applied: true, message: "applied" })),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const sharedAddress = "162.159.138.232";
    const discordConnection = {
      processName: "Discord.exe",
      remoteAddress: sharedAddress,
      remotePort: 443,
      state: "Established"
    };
    const processConnectionsProvider = vi.fn()
      .mockResolvedValueOnce([
        discordConnection,
        {
          processName: "custom-app.exe",
          remoteAddress: sharedAddress,
          remotePort: 443,
          state: "Established"
        }
      ])
      .mockResolvedValueOnce([discordConnection]);
    const processDnsEntriesProvider = vi.fn(async () => [{
      address: sharedAddress,
      domain: "gateway.discord.gg",
      ttlSeconds: 60
    }]);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy,
      processConnectionsProvider,
      processDnsEntriesProvider
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
    };
    const request: ConnectRequest = {
      ...connectRequest("mixed-to-profiled-process-routing"),
      routingMode: "selected-rules",
      routingRules: [
        {
          id: "discord",
          type: "process.name",
          value: "discord.exe",
          enabled: true,
          createdAt: "",
          updatedAt: ""
        },
        {
          id: "custom-app",
          type: "process.name",
          value: "custom-app.exe",
          enabled: true,
          createdAt: "",
          updatedAt: ""
        }
      ]
    };
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);

    try {
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([sharedAddress]));
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(1);

      now.mockReturnValue(1_001_000);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set());
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(1);
    } finally {
      try {
        await service.dispose();
      } finally {
        now.mockRestore();
        if (platform) {
          Object.defineProperty(process, "platform", platform);
        }
      }
    }
  });

  it("retains a shared profiled and generic process IP across an empty snapshot until TTL", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const systemProxy = {
      apply: vi.fn(async () => ({ applied: true, message: "applied" })),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const sharedAddress = "162.159.138.232";
    const processConnectionsProvider = vi.fn()
      .mockResolvedValueOnce([
        {
          processName: "Discord.exe",
          remoteAddress: sharedAddress,
          remotePort: 443,
          state: "Established"
        },
        {
          processName: "custom-app.exe",
          remoteAddress: sharedAddress,
          remotePort: 443,
          state: "Established"
        }
      ])
      .mockResolvedValue([]);
    const processDnsEntriesProvider = vi.fn(async () => [{
      address: sharedAddress,
      domain: "gateway.discord.gg",
      ttlSeconds: 60
    }]);
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy,
      processConnectionsProvider,
      processDnsEntriesProvider
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
    };
    const request: ConnectRequest = {
      ...connectRequest("mixed-process-routing"),
      routingMode: "selected-rules",
      routingRules: [
        {
          id: "discord",
          type: "process.name",
          value: "discord.exe",
          enabled: true,
          createdAt: "",
          updatedAt: ""
        },
        {
          id: "custom-app",
          type: "process.name",
          value: "custom-app.exe",
          enabled: true,
          createdAt: "",
          updatedAt: ""
        }
      ]
    };
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);

    try {
      await internals.learnProcessRoutingIps(request);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([sharedAddress]));
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(1);

      now.mockReturnValue(1_001_000);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(false);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([sharedAddress]));
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(1);

      now.mockReturnValue(1_300_001);
      await expect(internals.learnProcessRoutingIps(request)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set());
    } finally {
      try {
        await service.dispose();
      } finally {
        now.mockRestore();
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
