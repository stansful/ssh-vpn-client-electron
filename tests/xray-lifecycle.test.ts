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
      .mockResolvedValue([{
        processName: "Telegram.exe",
        remoteAddress: "149.154.167.41",
        remotePort: 443,
        state: "Established"
      }]);
    const processDnsEntriesProvider = vi.fn(async () => [{
      address: "149.154.167.41",
      domain: "api.telegram.org",
      ttlSeconds: 120
    }]);
    const runtimeDirectory = path.join(os.tmpdir(), `shadow-ssh-xray-lifecycle-${process.pid}-process-routing`);
    runtimeDirectories.add(runtimeDirectory);
    const service = new XrayServiceBridge(initialStatus(), {
      executablePath: process.execPath,
      runtimeDirectory,
      systemProxy,
      processConnectionsProvider,
      processDnsEntriesProvider,
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

      expect(systemProxy.apply).toHaveBeenCalledTimes(3);
      const literalIpRequest = vi.mocked(systemProxy.apply).mock.calls[1][0];
      expect(literalIpRequest).toMatchObject({
        proxyProtocol: "http",
        forcePacEndpointRotation: true,
        rules: expect.arrayContaining([
          expect.objectContaining({ type: "ip", value: "149.154.167.41", enabled: true })
        ])
      });
      expect(literalIpRequest.rules).not.toEqual(expect.arrayContaining([
        expect.objectContaining({ type: "domain", value: "api.telegram.org" })
      ]));
      const enrichedRequest = vi.mocked(systemProxy.apply).mock.calls[2][0];
      expect(enrichedRequest).toMatchObject({
        proxyProtocol: "http",
        forcePacEndpointRotation: true,
        rules: expect.arrayContaining([
          expect.objectContaining({ type: "ip", value: "149.154.167.41", enabled: true }),
          expect.objectContaining({ type: "domain", value: "api.telegram.org", enabled: true })
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

  it("publishes a literal process IP before DNS enrichment and then adds the Xray hostname route", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const processHandle = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(processHandle);
    const systemProxy = fakeSystemProxy();
    const address = "8.8.4.4";
    const domain = "media.generic-xray-client.example";
    const dnsEnrichment = deferred<Array<{ address: string; domain: string; ttlSeconds: number }>>();
    let dnsResolved = false;
    const processDnsEntriesProvider = vi.fn(() => dnsEnrichment.promise);
    const runtimeDirectory = path.join(
      os.tmpdir(),
      `shadow-ssh-xray-lifecycle-${process.pid}-literal-ip-before-dns`
    );
    runtimeDirectories.add(runtimeDirectory);
    const service = new XrayServiceBridge(initialStatus(), {
      executablePath: process.execPath,
      runtimeDirectory,
      systemProxy,
      processConnectionsProvider: vi.fn(async () => [{
        processName: "generic-xray-client.exe",
        remoteAddress: address,
        remotePort: 443,
        state: "Established"
      }]),
      processDnsEntriesProvider
    });
    const request: ProxyConnectRequest = {
      ...proxyRequest("literal-ip-before-dns"),
      routingMode: "selected-rules",
      routingRules: [{
        id: "generic-xray-client",
        type: "process.name",
        value: "generic-xray-client.exe",
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
      expect(literalIpPublish).toMatchObject({ proxyProtocol: "http" });
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

  it("does not publish an interim Xray process IP when explicit direct domains are configured", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const address = "8.8.8.8";
    const dnsEnrichment = deferred<Array<{ address: string; domain: string; ttlSeconds: number }>>();
    let dnsResolved = false;
    const processDnsEntriesProvider = vi.fn(() => dnsEnrichment.promise);
    const runtimeDirectory = path.join(
      os.tmpdir(),
      `shadow-ssh-xray-lifecycle-${process.pid}-direct-domain-no-interim-ip`
    );
    runtimeDirectories.add(runtimeDirectory);
    const service = new XrayServiceBridge(initialStatus(), {
      executablePath: process.execPath,
      runtimeDirectory,
      systemProxy: fakeSystemProxy(),
      processConnectionsProvider: vi.fn(async () => [{
        processName: "generic-direct-xray-client.exe",
        remoteAddress: address,
        remotePort: 443,
        state: "Established"
      }]),
      processDnsEntriesProvider
    });
    const publishLiteralIpSnapshot = vi.fn(async () => undefined);
    const rules: ProxyConnectRequest["routingRules"] = [{
      id: "generic-direct-xray-client",
      type: "process.name",
      value: "generic-direct-xray-client.exe",
      enabled: true,
      createdAt: "",
      updatedAt: ""
    }];
    const learning = (service as unknown as {
      learnProcessRoutingIps(
        rules: ProxyConnectRequest["routingRules"],
        directDomains: string[],
        generation: undefined,
        publish: (signature: string) => Promise<void>
      ): Promise<boolean>;
    }).learnProcessRoutingIps(
      rules,
      [".direct.example"],
      undefined,
      publishLiteralIpSnapshot
    );

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

  it("hot-adds a process rule and learns its next connection without restarting Xray", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    vi.useFakeTimers();
    const processHandle = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(processHandle);
    const systemProxy = fakeSystemProxy();
    const processConnectionsProvider = vi.fn()
      .mockResolvedValueOnce([])
      .mockResolvedValue([{
        processName: "Chrome.exe",
        remoteAddress: "142.250.74.110",
        remotePort: 443,
        state: "Established"
      }]);
    const runtimeDirectory = path.join(
      os.tmpdir(),
      `shadow-ssh-xray-lifecycle-${process.pid}-hot-add-process`
    );
    runtimeDirectories.add(runtimeDirectory);
    const service = new XrayServiceBridge(initialStatus(), {
      executablePath: process.execPath,
      runtimeDirectory,
      systemProxy,
      processConnectionsProvider,
      processRoutingRefreshIntervalMs: () => 30_000
    });
    const initialRequest: ProxyConnectRequest = {
      ...proxyRequest("hot-add-process"),
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
      expect(childProcess.spawn).toHaveBeenCalledTimes(1);
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
        proxyProtocol: "http",
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
        proxyProtocol: "http",
        forcePacEndpointRotation: true,
        rules: expect.arrayContaining([
          expect.objectContaining({ type: "process.name", value: "chrome.exe", enabled: true }),
          expect.objectContaining({ type: "ip", value: "142.250.74.110", enabled: true })
        ])
      });
      expect(childProcess.spawn).toHaveBeenCalledTimes(1);
      expect(runtime.terminateProcess).not.toHaveBeenCalled();
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

  it("refreshes generic DNS TTLs and prunes Xray routes after a snapshot failure", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const address = "203.0.113.47";
    const domain = "edge.xray-custom.example";
    const connection = [{
      processName: "custom-app.exe",
      remoteAddress: address,
      remotePort: 443,
      state: "Established"
    }];
    const processConnectionsProvider = vi.fn()
      .mockResolvedValueOnce(connection)
      .mockResolvedValueOnce(connection)
      .mockResolvedValueOnce(connection)
      .mockRejectedValueOnce(new Error("process snapshot unavailable"));
    const dnsTtls = [30, 60, 60];
    const processDnsEntriesProvider = vi.fn(async () => [{
      address,
      domain,
      ttlSeconds: dnsTtls.shift() ?? 60
    }]);
    const runtimeDirectory = path.join(
      os.tmpdir(),
      `shadow-ssh-xray-lifecycle-${process.pid}-generic-dns-ttl`
    );
    runtimeDirectories.add(runtimeDirectory);
    const service = new XrayServiceBridge(initialStatus(), {
      executablePath: process.execPath,
      runtimeDirectory,
      systemProxy: fakeSystemProxy(),
      processConnectionsProvider,
      processDnsEntriesProvider
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(rules: ProxyConnectRequest["routingRules"]): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
    };
    const rules: ProxyConnectRequest["routingRules"] = [{
      id: "custom-app",
      type: "process.name",
      value: "custom-app.exe",
      enabled: true,
      createdAt: "",
      updatedAt: ""
    }];
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);

    try {
      await expect(internals.learnProcessRoutingIps(rules)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));

      now.mockReturnValue(1_030_000);
      await expect(internals.learnProcessRoutingIps(rules)).resolves.toBe(false);
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));

      now.mockReturnValue(1_090_000);
      await expect(internals.learnProcessRoutingIps(rules)).resolves.toBe(false);
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(3);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));

      now.mockReturnValue(1_390_001);
      await expect(internals.learnProcessRoutingIps(rules)).resolves.toBe(true);
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

  it("keeps a DNS-covered Discord IP excluded across consecutive process scans", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const sharedAddress = "162.159.138.232";
    const processConnectionsProvider = vi.fn(async () => [{
      processName: "Discord.exe",
      remoteAddress: sharedAddress,
      remotePort: 443,
      state: "Established"
    }]);
    const processDnsEntriesProvider = vi.fn()
      .mockResolvedValueOnce([
        {
          address: sharedAddress,
          domain: "gateway.discord.gg",
          ttlSeconds: 60
        },
        {
          address: sharedAddress,
          domain: "unrelated.cloudflare.example",
          ttlSeconds: 60
        }
      ])
      .mockResolvedValueOnce([{
        address: sharedAddress,
        domain: "unrelated.cloudflare.example",
        ttlSeconds: 60
      }]);
    const runtimeDirectory = path.join(
      os.tmpdir(),
      `shadow-ssh-xray-lifecycle-${process.pid}-discord-consecutive`
    );
    runtimeDirectories.add(runtimeDirectory);
    const service = new XrayServiceBridge(initialStatus(), {
      executablePath: process.execPath,
      runtimeDirectory,
      systemProxy: fakeSystemProxy(),
      processConnectionsProvider,
      processDnsEntriesProvider
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(rules: ProxyConnectRequest["routingRules"]): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
    };
    const rules: ProxyConnectRequest["routingRules"] = [{
      id: "discord",
      type: "process.name",
      value: "discord.exe",
      enabled: true,
      createdAt: "",
      updatedAt: ""
    }];
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);

    try {
      await expect(internals.learnProcessRoutingIps(rules)).resolves.toBe(true);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set());
      expect(internals.currentProcessRoutingDomains().has("unrelated.cloudflare.example")).toBe(false);

      now.mockReturnValue(1_060_001);
      await expect(internals.learnProcessRoutingIps(rules)).resolves.toBe(false);
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(2);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set());
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

  it("passes explicit direct domains into Xray session-evidence learning", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const address = "9.9.9.10";
    const domain = "api.xray-direct.example";
    const runtimeDirectory = path.join(
      os.tmpdir(),
      `shadow-ssh-xray-lifecycle-${process.pid}-direct-evidence`
    );
    runtimeDirectories.add(runtimeDirectory);
    const service = new XrayServiceBridge(initialStatus(), {
      executablePath: process.execPath,
      runtimeDirectory,
      systemProxy: fakeSystemProxy(),
      processConnectionsProvider: vi.fn(async () => [{
        processName: "custom-app.exe",
        remoteAddress: address,
        remotePort: 443,
        state: "Established"
      }]),
      processDnsEntriesProvider: vi.fn(async () => [{ address, domain, ttlSeconds: 60 }])
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(
        rules: ProxyConnectRequest["routingRules"],
        directDomains?: string[]
      ): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
      processRoutingSessionLeases: Map<string, unknown>;
    };
    const rules: ProxyConnectRequest["routingRules"] = [{
      id: "custom-app",
      type: "process.name",
      value: "custom-app.exe",
      enabled: true,
      createdAt: "",
      updatedAt: ""
    }];

    try {
      await internals.learnProcessRoutingIps(rules, [".xray-direct.example"]);
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

  it("keeps additive Xray routes when a high-confidence socket disappears after its first scan", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    const address = "8.8.4.4";
    const domain = "api.short-lived-xray-app.example";
    const processDnsEntriesProvider = vi.fn(async () => [{ address, domain, ttlSeconds: 60 }]);
    const runtimeDirectory = path.join(
      os.tmpdir(),
      `shadow-ssh-xray-lifecycle-${process.pid}-short-lived-evidence`
    );
    runtimeDirectories.add(runtimeDirectory);
    const service = new XrayServiceBridge(initialStatus(), {
      executablePath: process.execPath,
      runtimeDirectory,
      systemProxy: fakeSystemProxy(),
      processConnectionsProvider: vi.fn()
        .mockResolvedValueOnce([{
          processName: "short-lived-app.exe",
          remoteAddress: address,
          remotePort: 443,
          state: "Established"
        }])
        .mockResolvedValueOnce([]),
      processDnsEntriesProvider
    });
    const internals = service as unknown as {
      learnProcessRoutingIps(
        rules: ProxyConnectRequest["routingRules"],
        directDomains?: string[]
      ): Promise<boolean>;
      currentProcessRoutingIps(): Set<string>;
      currentProcessRoutingDomains(): Set<string>;
      processRoutingSessionLeases: Map<string, unknown>;
    };
    const rules: ProxyConnectRequest["routingRules"] = [{
      id: "short-lived-app",
      type: "process.name",
      value: "short-lived-app.exe",
      enabled: true,
      createdAt: "",
      updatedAt: ""
    }];
    const now = vi.spyOn(Date, "now").mockReturnValue(6_000_000);

    try {
      await internals.learnProcessRoutingIps(rules);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));
      expect(internals.processRoutingSessionLeases.size).toBe(1);

      now.mockReturnValue(6_001_000);
      await expect(internals.learnProcessRoutingIps(rules)).resolves.toBe(false);
      expect(internals.currentProcessRoutingIps()).toEqual(new Set([address]));
      expect(internals.currentProcessRoutingDomains()).toEqual(new Set([domain]));
      expect(internals.processRoutingSessionLeases.size).toBe(1);
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
