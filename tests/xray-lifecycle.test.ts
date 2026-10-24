import { EventEmitter } from "node:events";
import { existsSync } from "node:fs";
import { mkdir, readdir, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, onTestFinished, vi } from "vitest";
import type { WindowsSystemProxyManager } from "../src/core/network/windows-system-proxy.js";
import type { DataplaneStartRequest } from "../src/service/local-ipc-protocol.js";
import type { DataplaneController } from "../src/service/native-dataplane.js";
import type { ProcessRouteLearner } from "../src/service/process-route-learning.js";
import type { ProxyConnectRequest, RuntimeStatus } from "../src/shared/types.js";

const runtime = vi.hoisted(() => ({
  detectXrayVersion: vi.fn(),
  reserveDistinctLocalTcpPorts: vi.fn(),
  terminateProcess: vi.fn(),
  waitForProcessStartup: vi.fn()
}));
const childProcess = vi.hoisted(() => ({ spawn: vi.fn() }));

vi.mock("../src/service/xray/process-utils.js", () => runtime);
vi.mock("node:child_process", () => ({ execFile: vi.fn(), spawn: childProcess.spawn }));

import { bindRefusingLoopbackPorts, XrayServiceBridge } from "../src/service/xray-service.js";
import {
  forgetLocalProxyPort,
  forgetXrayInboundPorts,
  rememberLocalProxyPort
} from "../src/service/local-proxy-port.js";

const runtimeDirectories = new Set<string>();

describe("Xray service lifecycle", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // A default spawn left by one case must not hand a process to the next.
    childProcess.spawn.mockReset();
    forgetXrayInboundPorts();
    forgetLocalProxyPort();
    runtime.reserveDistinctLocalTcpPorts.mockResolvedValue([
      { host: "127.0.0.1", port: 32000 },
      { host: "127.0.0.1", port: 32001 }
    ]);
    runtime.waitForProcessStartup.mockResolvedValue(undefined);
    runtime.terminateProcess.mockResolvedValue(undefined);
    runtime.detectXrayVersion.mockResolvedValue("26.3.27");
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

  it("renames the running profile without a reconnect and keeps the new name for a restart", async () => {
    const processHandle = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(processHandle).mockReturnValueOnce(new FakeXrayProcess());
    const service = createService("rename");
    await service.connect(proxyRequest("profile"));
    const names: Array<string | undefined> = [];
    service.onEvent((event) => {
      if (event.type === "status-changed") {
        names.push(event.status.activeConfigName);
      }
    });

    service.renameActiveProfile("other", "Not this one");
    service.renameActiveProfile("profile", "Renamed");
    service.renameActiveProfile("profile", "Renamed");

    expect(names).toEqual(["Renamed"]);
    expect(service.getStatus()).toMatchObject({ state: "Connected", activeConfigId: "profile", activeConfigName: "Renamed" });
    expect(childProcess.spawn).toHaveBeenCalledTimes(1);

    processHandle.emit("close", 1, null);
    await vi.waitFor(() => expect(service.getStatus().state).toBe("Reconnecting"));
    service.wake("test");
    await vi.waitFor(() => expect(service.getStatus()).toMatchObject({ state: "Connected", activeConfigName: "Renamed" }));
    expect(childProcess.spawn).toHaveBeenCalledTimes(2);
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

    expect(service.getStatus()).toMatchObject({ state: "Error", realTunnelAvailable: false, localProxy: undefined });
    await vi.waitFor(() => expect(service.getStatus().state).toBe("Reconnecting"));
    expect(runtime.terminateProcess).toHaveBeenCalledWith(processHandle);
    // Routing is held for the restart, as the SSH transport holds it while it
    // reconnects, instead of being released at once.
    expect(systemProxy.restore).not.toHaveBeenCalled();
    await service.dispose();
    expect(systemProxy.restore).toHaveBeenCalled();
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
      processRoutes: ProcessRouteLearner;
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
      expect(internals.processRoutes.currentIps()).toEqual(new Set([address]));
      expect(internals.processRoutes.currentDomains()).toEqual(new Set([domain]));

      now.mockReturnValue(1_030_000);
      await expect(internals.learnProcessRoutingIps(rules)).resolves.toBe(false);
      expect(internals.processRoutes.currentDomains()).toEqual(new Set([domain]));

      now.mockReturnValue(1_090_000);
      await expect(internals.learnProcessRoutingIps(rules)).resolves.toBe(false);
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(3);
      expect(internals.processRoutes.currentIps()).toEqual(new Set([address]));
      expect(internals.processRoutes.currentDomains()).toEqual(new Set([domain]));

      now.mockReturnValue(1_390_001);
      await expect(internals.learnProcessRoutingIps(rules)).resolves.toBe(true);
      expect(internals.processRoutes.currentIps()).toEqual(new Set());
      expect(internals.processRoutes.currentDomains()).toEqual(new Set());
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
      processRoutes: ProcessRouteLearner;
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
      expect(internals.processRoutes.currentIps()).toEqual(new Set());
      expect(internals.processRoutes.currentDomains().has("unrelated.cloudflare.example")).toBe(false);

      now.mockReturnValue(1_060_001);
      await expect(internals.learnProcessRoutingIps(rules)).resolves.toBe(false);
      expect(processDnsEntriesProvider).toHaveBeenCalledTimes(2);
      expect(internals.processRoutes.currentIps()).toEqual(new Set());
      expect(internals.processRoutes.currentDomains().has("unrelated.cloudflare.example")).toBe(false);
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
      processRoutes: ProcessRouteLearner;
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
      expect(internals.processRoutes.currentIps()).toEqual(new Set([address]));
      expect(internals.processRoutes.currentDomains()).toEqual(new Set());
      expect(internals.processRoutes.sessionLeases.size).toBe(0);
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
      processRoutes: ProcessRouteLearner;
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
      expect(internals.processRoutes.currentIps()).toEqual(new Set([address]));
      expect(internals.processRoutes.currentDomains()).toEqual(new Set([domain]));
      expect(internals.processRoutes.sessionLeases.size).toBe(1);

      now.mockReturnValue(6_001_000);
      await expect(internals.learnProcessRoutingIps(rules)).resolves.toBe(false);
      expect(internals.processRoutes.currentIps()).toEqual(new Set([address]));
      expect(internals.processRoutes.currentDomains()).toEqual(new Set([domain]));
      expect(internals.processRoutes.sessionLeases.size).toBe(1);
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
    // Xray writes one of these per connection; a busy client produces hundreds
    // in a minute.
    processHandle.stdout.emit(
      "data",
      Array.from({ length: 400 }, (_, index) => `2026/08/28 [Info] proxy: accepted tcp:1.1.1.1:443 #${index}`).join("\n")
    );

    expect(diagnostics.filter((message) => message.includes("connection notices are suppressed"))).toHaveLength(1);
    const noticeCount = diagnostics.filter((message) => message.includes("accepted tcp:")).length;
    expect(noticeCount).toBeLessThan(60);

    // The whole point: a warning arriving after the chatter was capped still
    // reaches the log. Sharing one budget meant the line explaining a failed
    // outbound was thrown away with the noise that caused it.
    processHandle.stdout.emit("data", "2026/08/28 [Warning] core: failed to process outbound traffic\n");
    expect(diagnostics.some((message) => message.includes("failed to process outbound traffic"))).toBe(true);
    expect(processHandle.stdout.listenerCount("data")).toBe(1);

    const xrayLines = diagnostics.filter((message) => message.startsWith("Xray: "));
    expect(xrayLines[0]?.length).toBeLessThanOrEqual(4103);

    // Warnings are bounded too, and exhausting that budget is what finally
    // detaches the pipes - which must then keep draining on their own.
    processHandle.stderr.emit(
      "data",
      Array.from({ length: 400 }, (_, index) => `warning-${index}`).join("\n")
    );
    expect(diagnostics.filter((message) => message.includes("Further Xray warnings are suppressed"))).toHaveLength(1);
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

  // Xray reads its routing only at start, and its direct rule for the local
  // network must give way to a user rule that names it.
  it("restarts Xray with routing held when the rules for the local network change, and only then", async () => {
    // Only on Windows does Xray keep the local network direct at all (for
    // what the Windows proxy hands it), so only there do these rules matter.
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    onTestFinished(() => {
      if (platform) {
        Object.defineProperty(process, "platform", platform);
      }
    });
    const first = new FakeXrayProcess();
    const configs: WrittenXrayConfig[] = [];
    spawnCapturingConfig(first, configs);
    spawnCapturingConfig(new FakeXrayProcess(), configs);
    const systemProxy = fakeSystemProxy();
    const service = createService("local-rule-restart", systemProxy);
    const diagnostics = collectDiagnostics(service);
    const rule = (id: string, type: "domain" | "ip", value: string) => ({ id, type, value, enabled: true, createdAt: "", updatedAt: "" });
    const site = rule("site", "domain", "example.org");
    const update = (routingMode: "selected-rules" | "proxy-all", routingRules: ReturnType<typeof rule>[]) => ({
      routingMode,
      routingRules,
      routingProxyDomains: [],
      routingDirectDomains: [],
      checkEndpoint: "example.com:443"
    });

    await service.connect({ ...proxyRequest("local-rules"), routingMode: "selected-rules", routingRules: [site] });
    expect(configs).toHaveLength(1);
    expect(configs[0].routing?.rules.every((entry) => entry.outboundTag === "direct")).toBe(true);
    // A fresh connect clears whatever routing was left first.
    const restoresAtConnect = vi.mocked(systemProxy.restore).mock.calls.length;

    // A rule for a public range changes nothing Xray decides: applied in place.
    await service.updateRoutingRules([site, rule("public", "ip", "91.108.4.0/22")]);
    await settle(service);
    expect(childProcess.spawn).toHaveBeenCalledTimes(1);

    // 10.0.0.0/8 does: Xray comes back with it, and routing was never taken down.
    const lanRules = [site, rule("lan", "ip", "10.0.0.0/8")];
    await service.updateRoutingRules(lanRules);
    await settle(service);
    expect(childProcess.spawn).toHaveBeenCalledTimes(2);
    expect(runtime.terminateProcess).toHaveBeenCalledWith(first);
    expect(configs[1].routing?.rules).toContainEqual({ type: "field", ip: ["10.0.0.0/8"], outboundTag: "proxy", inboundTag: ["http-in"] });
    expect(systemProxy.restore).toHaveBeenCalledTimes(restoresAtConnect);
    expect(vi.mocked(systemProxy.apply).mock.calls.at(-1)?.[0]).toMatchObject({ socksHost: "127.0.0.1", socksPort: 32001 });
    expect(service.getStatus()).toMatchObject({ state: "Connected", activeConfigId: "local-rules" });
    expect(diagnostics).toContainEqual({
      level: "info",
      message: "Routing rules for the local network changed, which Xray reads only at start: restarting Xray, with routing held until it is back."
    });

    // A mode switch with the same rules is applied in place again.
    await service.updateRouting(update("proxy-all", lanRules));
    await settle(service);
    expect(childProcess.spawn).toHaveBeenCalledTimes(2);
    expect(service.getStatus().state).toBe("Connected");
    await service.dispose();
  });

  it("applies a local-network rule change in place while the TUN adapter carries the traffic, and restarts once the proxy path takes over", async () => {
    // Under TUN everything enters through Xray's SOCKS inbound, which those
    // rules do not touch: a restart only reset every tunnelled flow.
    await withWin32(async () => {
      const configs: WrittenXrayConfig[] = [];
      spawnCapturingConfig(new FakeXrayProcess(), configs);
      spawnCapturingConfig(new FakeXrayProcess(), configs);
      const systemProxy = fakeSystemProxy();
      const dataplane = fakeDataplane();
      const service = createService("local-rule-tun", systemProxy, dataplane);
      const site = { id: "site", type: "domain" as const, value: "example.org", enabled: true, createdAt: "", updatedAt: "" };
      const lan = { id: "lan", type: "ip" as const, value: "10.0.0.0/8", enabled: true, createdAt: "", updatedAt: "" };
      await service.connect({ ...proxyRequest("local-rule-tun"), tunDataplaneEnabled: true, routingMode: "selected-rules", routingRules: [site] });
      expect(service.getStatus()).toMatchObject({ state: "Connected", tunActive: true });

      await service.updateRoutingRules([site, lan]);
      await settle(service);
      expect(childProcess.spawn).toHaveBeenCalledTimes(1);
      expect(dataplane.started).toHaveLength(2);
      expect(service.getStatus()).toMatchObject({ state: "Connected", tunActive: true });

      // The adapter goes and cannot come back: the Windows proxy now points
      // at the HTTP inbound, which needs the rule after all.
      dataplane.probe = async () => ({ available: false, reason: "wintun.dll is missing" });
      dataplane.die("Native helper exited (3).");
      await settle(service);
      expect(childProcess.spawn).toHaveBeenCalledTimes(2);
      expect(configs[1].routing?.rules).toContainEqual({ type: "field", ip: ["10.0.0.0/8"], outboundTag: "proxy", inboundTag: ["http-in"] });
      expect(service.getStatus()).toMatchObject({ state: "Connected", tunActive: false });
      await service.dispose();
    });
  });

  it("keeps what process discovery learned across the restart a local-network rule change starts", async () => {
    // On the PAC path a learned destination is never seen connecting directly
    // again once it goes through the proxy; dropping it at the restart sent
    // it direct until discovery happened to learn it anew.
    await withWin32(async () => {
      spawnCapturingConfig(new FakeXrayProcess(), []);
      spawnCapturingConfig(new FakeXrayProcess(), []);
      const systemProxy = fakeSystemProxy();
      const runtimeDirectory = runtimeDirectoryOf("held-restart-routes");
      runtimeDirectories.add(runtimeDirectory);
      let cycle = 0;
      const service = new XrayServiceBridge(initialStatus(), {
        executablePath: process.execPath,
        runtimeDirectory,
        systemProxy,
        holdInboundPorts: async () => ({ release: async () => undefined }),
        processConnectionsProvider: async () => {
          cycle += 1;
          return cycle === 1 ? [{ processName: "example-app.exe", remoteAddress: "203.0.113.10", remotePort: 443, state: "Established" }] : [];
        },
        processDnsEntriesProvider: async () => []
      });
      const app = { id: "app", type: "process.name" as const, value: "example-app.exe", enabled: true, createdAt: "", updatedAt: "" };
      const lan = { id: "lan", type: "ip" as const, value: "10.0.0.0/8", enabled: true, createdAt: "", updatedAt: "" };
      await service.connect({ ...proxyRequest("held-restart-routes"), routingMode: "selected-rules", routingRules: [app] });
      const internals = service as unknown as { processRoutes: ProcessRouteLearner };
      expect([...internals.processRoutes.ips.keys()]).toEqual(["203.0.113.10"]);

      await service.updateRoutingRules([app, lan]);
      await settle(service);

      expect(childProcess.spawn).toHaveBeenCalledTimes(2);
      expect([...internals.processRoutes.ips.keys()]).toEqual(["203.0.113.10"]);
      expect(JSON.stringify(vi.mocked(systemProxy.apply).mock.calls.at(-1)?.[0].rules)).toContain("203.0.113.10");
      await service.dispose();
    });
  });

  it("keeps the local network in the tunnel, and needs no restart for its rules, where nothing steers system traffic", async () => {
    // macOS and Linux: whatever reaches Xray was sent to it by hand.
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "darwin" });
    onTestFinished(() => {
      if (platform) {
        Object.defineProperty(process, "platform", platform);
      }
    });
    const configs: WrittenXrayConfig[] = [];
    spawnCapturingConfig(new FakeXrayProcess(), configs);
    const service = createService("manual-local");
    await service.connect(proxyRequest("manual-local"));
    expect(configs[0].routing?.rules).toEqual([]);

    await service.updateRoutingRules([{ id: "lan", type: "ip", value: "10.0.0.0/8", enabled: true, createdAt: "", updatedAt: "" }]);
    await settle(service);
    expect(childProcess.spawn).toHaveBeenCalledTimes(1);
    await service.dispose();
  });

  it("starts a Hysteria 2 profile with a config the bundled Xray accepts", async () => {
    const processHandle = new FakeXrayProcess();
    const configs: WrittenXrayConfig[] = [];
    spawnCapturingConfig(processHandle, configs);
    const service = createService("hysteria2");
    const statusMessages: string[] = [];
    service.onEvent((event) => {
      if (event.type === "status-changed") {
        statusMessages.push(event.status.message);
      }
    });
    const diagnostics = collectDiagnostics(service);

    await service.connect(hysteria2Request(
      "hy2",
      "hysteria2://hy-secret-auth@hy.example.com:443/?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=mask-secret#hy2"
    ));

    expect(service.getStatus()).toMatchObject({ state: "Connected", activeConfigId: "hy2", realTunnelAvailable: true });
    expect(statusMessages).toContain("Starting Hysteria 2 profile hy2.");
    expect(runtime.detectXrayVersion).toHaveBeenCalledWith(process.execPath);
    expect(configs).toHaveLength(1);
    expect(configs[0].outbounds[0].protocol).toBe("hysteria");
    // This Xray fails the whole config on allowInsecure, so insecure=1 must
    // not leak into it.
    expect(JSON.stringify(configs[0])).not.toContain("allowInsecure");
    expect(diagnostics).toContainEqual({
      level: "info",
      message: expect.stringContaining("Xray connect requested for Hysteria 2 hy.example.com:443, transport=hysteria, security=tls")
    });
    // The certificate is verified after all, which a self-signed server fails.
    expect(diagnostics).toContainEqual({
      level: "warning",
      message: "This link asks to skip certificate checks (insecure=1), which the bundled Xray can’t do, so the server’s certificate is checked as usual. If the server uses a self-signed certificate, add its pinSHA256 to the link."
    });
    expect(diagnostics).toContainEqual({ level: "info", message: "Xray runtime 26.3.27 started for Hysteria 2 hy.example.com:443." });
    expect(JSON.stringify(diagnostics)).not.toContain("hy-secret-auth");
    expect(JSON.stringify(diagnostics)).not.toContain("mask-secret");
    await service.dispose();
  });

  it("shapes Hysteria 2 port hopping for the Xray version the binary reports", async () => {
    const link = `hysteria2://auth@hy.example.com:443,20000-30000/?sni=hy.example.com&insecure=1&pinSHA256=${"ab".repeat(32)}#hop`;
    const configs: WrittenXrayConfig[] = [];
    spawnCapturingConfig(new FakeXrayProcess(), configs);
    spawnCapturingConfig(new FakeXrayProcess(), configs);
    runtime.detectXrayVersion.mockResolvedValueOnce("26.9.9").mockResolvedValueOnce(undefined);
    const service = createService("hysteria2-hop");
    const diagnostics = collectDiagnostics(service);

    await service.connect(hysteria2Request("hop", link, "443,20000-30000"));
    await service.connect(hysteria2Request("hop", link, "443,20000-30000"));

    // 26.9.9 moved hopping into a udphop mask and ignores the old field...
    expect(configs[0].outbounds[0].streamSettings?.finalmask?.udp?.[0]).toMatchObject({
      type: "udphop",
      settings: { remotePorts: "443,20000-30000" }
    });
    expect(configs[0].outbounds[0].streamSettings?.finalmask?.quicParams?.udpHop).toBeUndefined();
    // ...while a binary that cannot say gets the bundled 26.3.27 shape, which
    // rejects that mask.
    expect(configs[1].outbounds[0].streamSettings?.finalmask?.quicParams?.udpHop).toMatchObject({ ports: "443,20000-30000" });
    expect(configs[1].outbounds[0].streamSettings?.finalmask?.udp).toBeUndefined();
    expect(diagnostics.some((entry) =>
      entry.message.startsWith("Xray connect requested for Hysteria 2 hy.example.com:443,20000-30000, transport=hysteria")
    )).toBe(true);
    expect(diagnostics).toContainEqual({ level: "info", message: "Xray runtime 26.9.9 started for Hysteria 2 hy.example.com:443,20000-30000." });
    expect(diagnostics).toContainEqual({ level: "info", message: "Xray runtime started for Hysteria 2 hy.example.com:443,20000-30000." });
    // The pin accepts the certificate insecure=1 was meant for.
    expect(diagnostics.some((entry) => entry.message.includes("insecure=1"))).toBe(false);
    await service.dispose();
  });

  it("names the reason Xray printed when it rejects its config at startup", async () => {
    const processHandle = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(processHandle);
    runtime.waitForProcessStartup.mockImplementationOnce(async () => {
      // The exit is seen first; the line explaining it is still in the pipe.
      processHandle.exitCode = 23;
      setTimeout(() => {
        processHandle.stdout.emit(
          "data",
          "Failed to start: main: failed to load config files: [/tmp/xray-config.json] > infra/conf: failed to build outbound config with tag proxy > infra/conf: bad hysteriaSettings {\"auth\":\"hunter2\"}\n"
        );
        processHandle.emit("close", 23, null);
      }, 5);
      throw new Error("Xray runtime exited during startup with code 23.");
    });
    const service = createService("startup-reason");
    const diagnostics = collectDiagnostics(service);

    await service.connect(proxyRequest("rejected"));

    expect(service.getStatus()).toMatchObject({
      state: "Error",
      reconnectAttempt: 0,
      message: "Xray runtime exited during startup with code 23: infra/conf: failed to build outbound config with tag proxy > infra/conf: bad hysteriaSettings {\"auth\":\"<redacted>\"}"
    });
    expect(diagnostics).toContainEqual({ level: "error", message: expect.stringMatching(/^Xray: Failed to start: main: failed to load config files/u) });
    expect(JSON.stringify(diagnostics)).not.toContain("hunter2");
    expect(runtime.terminateProcess).toHaveBeenCalledWith(processHandle);
    // The close belonged to the startup that already reported it: no restart.
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(service.getStatus()).toMatchObject({ state: "Error", reconnectAttempt: 0 });
    await service.dispose();
  });

  it("keeps the plain exit message when Xray printed no reason", async () => {
    const processHandle = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(processHandle);
    runtime.waitForProcessStartup.mockImplementationOnce(async () => {
      processHandle.exitCode = 1;
      processHandle.emit("close", 1, null);
      throw new Error("Xray runtime exited during startup with code 1.");
    });
    const service = createService("startup-no-reason");

    await service.connect(proxyRequest("silent"));

    expect(service.getStatus()).toMatchObject({ state: "Error", message: "Xray runtime exited during startup with code 1." });
    await service.dispose();
  });

  it("adds the UDP hint only when a Hysteria 2 tunnel check fails", async () => {
    const service = createService("hysteria2-check");
    const connectOnClosedPort = async (request: ProxyConnectRequest): Promise<void> => {
      runtime.reserveDistinctLocalTcpPorts.mockResolvedValueOnce([
        { host: "127.0.0.1", port: await closedLocalPort() },
        { host: "127.0.0.1", port: 32001 }
      ]);
      childProcess.spawn.mockReturnValueOnce(new FakeXrayProcess());
      await service.connect(request);
    };

    await connectOnClosedPort(hysteria2Request("check", "hysteria2://auth@hy.example.com:443/?sni=hy.example.com#check"));
    const hysteria = await service.checkTunnel("example.com:443");

    expect(hysteria.ok).toBe(false);
    const hint = "Hysteria 2 runs over UDP (QUIC): the network may block UDP to the server or its ports, or the link’s password (auth), certificate pin (pinSHA256) or obfs password may be wrong.";
    expect(hysteria.message.endsWith(` ${hint}`)).toBe(true);
    expect(hysteria.message.slice(0, -hint.length - 1)).toMatch(/[.!?]$/u);
    // Xray logs the dial failure at [Info], below the runtime's "warning"
    // level, so there is no reason in the Activity log to send anyone to.
    expect(hysteria.message).not.toContain("Activity log");

    await connectOnClosedPort(proxyRequest("vless-check"));
    const vless = await service.checkTunnel("example.com:443");

    expect(vless.ok).toBe(false);
    expect(vless.message).not.toContain("Hysteria 2");
    await service.dispose();
  });

  it("hands Xray its config on stdin so the credentials never reach the disk", async () => {
    const processHandle = new FakeXrayProcess();
    const configs: WrittenXrayConfig[] = [];
    spawnCapturingConfig(processHandle, configs);
    const service = createService("stdin-config");
    const runtimeDirectory = runtimeDirectoryOf("stdin-config");

    await service.connect(proxyRequest("stdin"));

    expect(service.getStatus().state).toBe("Connected");
    expect(childProcess.spawn).toHaveBeenCalledWith(
      process.execPath,
      ["run", "-config", "stdin:"],
      expect.objectContaining({ stdio: ["pipe", "pipe", "pipe"], windowsHide: true })
    );
    // Written once and closed: Xray reads to the end of stdin before it starts.
    expect(processHandle.stdin.ended).toBe(true);
    expect(configs).toHaveLength(1);
    expect(processHandle.stdin.text).toContain("11111111-1111-4111-8111-111111111111");
    expect(existsSync(path.join(runtimeDirectory, "xray-config.json"))).toBe(false);
    // A process that dies before reading has its pipe break under the write;
    // that must not become an unhandled error.
    expect(() => processHandle.stdin.emit("error", new Error("write EPIPE"))).not.toThrow();
    await service.dispose();
  });

  it("sweeps a config an earlier version left on disk, and nothing else", async () => {
    const runtimeDirectory = runtimeDirectoryOf("legacy-sweep");
    await mkdir(runtimeDirectory, { recursive: true });
    await writeFile(path.join(runtimeDirectory, "xray-config.json"), "{\"secret\":true}");
    await writeFile(path.join(runtimeDirectory, `xray-config.json.${process.pid}.abc.tmp`), "{}");
    await writeFile(path.join(runtimeDirectory, "unrelated.json"), "{}");

    const service = createService("legacy-sweep");

    await vi.waitFor(async () => expect((await readdir(runtimeDirectory)).sort()).toEqual(["unrelated.json"]));
    await service.dispose();
  });

  it("keeps restarting after a failed restart, and a wake brings the next attempt forward", async () => {
    const first = new FakeXrayProcess();
    const third = new FakeXrayProcess();
    childProcess.spawn
      .mockReturnValueOnce(first)
      .mockReturnValueOnce(new FakeXrayProcess())
      .mockReturnValueOnce(third);
    const service = createService("restart-retry");
    const diagnostics = collectDiagnostics(service);
    await service.connect(proxyRequest("retry"));

    first.emit("close", 1, null);
    await settle(service);
    expect(service.getStatus()).toMatchObject({ state: "Reconnecting", reconnectAttempt: 1 });

    // The restart hits a slow start: once this ended recovery in Error for good.
    runtime.waitForProcessStartup.mockRejectedValueOnce(new Error("Xray listeners did not become ready within 10000 ms."));
    service.wake("test");
    await settle(service);

    expect(childProcess.spawn).toHaveBeenCalledTimes(2);
    expect(service.getStatus()).toMatchObject({
      state: "Reconnecting",
      reconnectAttempt: 2,
      message: "Restarting Xray transport after failure: Xray listeners did not become ready within 10000 ms."
    });
    expect(diagnostics).toContainEqual({
      level: "error",
      message: "Xray restart failed: Xray listeners did not become ready within 10000 ms."
    });

    // The rescheduled attempt is a pending one a wake can bring forward.
    service.wake("network change");
    await settle(service);

    expect(childProcess.spawn).toHaveBeenCalledTimes(3);
    expect(service.getStatus()).toMatchObject({ state: "Connected", reconnectAttempt: 0, realTunnelAvailable: true });
    await service.dispose();
  });

  it("stops the restart cycle when the user disconnects during an attempt", async () => {
    const first = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(first).mockReturnValueOnce(new FakeXrayProcess());
    const systemProxy = fakeSystemProxy();
    const service = createService("restart-disconnect", systemProxy);
    const internals = service as unknown as { reconnectTimer: NodeJS.Timeout | undefined };
    await service.connect(proxyRequest("disconnect"));
    first.emit("close", 1, null);
    await settle(service);
    runtime.waitForProcessStartup.mockImplementationOnce(async (_process, _endpoints, options) =>
      new Promise<void>((_resolve, reject) => {
        options.signal.addEventListener("abort", () => reject(new Error("Xray startup was cancelled.")), { once: true });
      })
    );

    service.wake("test");
    await vi.waitFor(() => expect(runtime.waitForProcessStartup).toHaveBeenCalledTimes(2));
    await service.disconnect();
    await settle(service);

    expect(service.getStatus()).toMatchObject({ state: "Disconnected", reconnectAttempt: 0 });
    expect(internals.reconnectTimer).toBeUndefined();
    // The disconnect released the routing the restart was holding.
    expect(systemProxy.restore).toHaveBeenCalled();
    service.wake("later");
    expect(childProcess.spawn).toHaveBeenCalledTimes(2);
    await service.dispose();
  });

  it("holds routing while Xray restarts and returns the machine to direct routing after 30 s", async () => {
    vi.useFakeTimers();
    const first = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(first).mockImplementation(() => new FakeXrayProcess());
    const systemProxy = fakeSystemProxy();
    const service = createService("routing-hold", systemProxy);
    const diagnostics = collectDiagnostics(service);

    try {
      await service.connect(proxyRequest("hold"));
      vi.mocked(systemProxy.restore).mockClear();
      runtime.waitForProcessStartup.mockRejectedValue(new Error("listeners timed out"));

      first.emit("close", 1, null);
      await settle(service);
      expect(service.getStatus()).toMatchObject({ state: "Reconnecting", reconnectAttempt: 1 });
      expect(systemProxy.restore).not.toHaveBeenCalled();

      // A failed restart inside the hold keeps it.
      await vi.advanceTimersByTimeAsync(1_300);
      await settle(service);
      expect(childProcess.spawn).toHaveBeenCalledTimes(2);
      expect(service.getStatus()).toMatchObject({ state: "Reconnecting", reconnectAttempt: 2 });
      expect(systemProxy.restore).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(30_000);
      await settle(service);

      expect(systemProxy.restore).toHaveBeenCalled();
      expect(diagnostics).toContainEqual({
        level: "warning",
        message: "The tunnel has been down for 30 s; returning the machine to direct routing until the session is back."
      });
      // Direct routing does not mean giving up.
      expect(service.getStatus().state).toBe("Reconnecting");
    } finally {
      try {
        await service.dispose();
      } finally {
        vi.useRealTimers();
      }
    }
  });

  it("takes held routing over on a restart, on the ports Xray had before", async () => {
    const first = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(first).mockReturnValueOnce(new FakeXrayProcess());
    const systemProxy = fakeSystemProxy();
    const service = createService("restart-takeover", systemProxy);
    await service.connect(proxyRequest("takeover"));
    vi.mocked(systemProxy.restore).mockClear();

    first.emit("close", 1, null);
    await settle(service);
    service.wake("test");
    await settle(service);

    expect(service.getStatus()).toMatchObject({
      state: "Connected",
      localProxy: { host: "127.0.0.1", httpPort: 32001, socksPort: 32000 }
    });
    // Re-applied over the held routing, never released in between.
    expect(systemProxy.restore).not.toHaveBeenCalled();
    expect(systemProxy.apply).toHaveBeenCalledTimes(2);
    expect(runtime.reserveDistinctLocalTcpPorts).toHaveBeenLastCalledWith(2, undefined, expect.objectContaining({
      preferredPorts: [32000, 32001]
    }));
    await service.dispose();
  });

  it("keeps the stopped Xray's ports bound while routing still points at them", async () => {
    // Once xray.exe is gone its loopback ports are free, and held routing
    // still sends everything there: whatever bound them first would get it.
    const first = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(first).mockReturnValueOnce(new FakeXrayProcess());
    const events: string[] = [];
    const holdInboundPorts = vi.fn(async (endpoints: ReadonlyArray<{ host: string; port: number }>) => {
      events.push(`hold ${endpoints.map((endpoint) => endpoint.port).join(",")}`);
      return { release: vi.fn(async () => { events.push("release"); }) };
    });
    runtime.reserveDistinctLocalTcpPorts.mockImplementation(async () => {
      events.push("reserve");
      return [{ host: "127.0.0.1", port: 32000 }, { host: "127.0.0.1", port: 32001 }];
    });
    const service = new XrayServiceBridge(initialStatus(), {
      executablePath: process.execPath,
      runtimeDirectory: runtimeDirectoryOf("hold-ports"),
      systemProxy: fakeSystemProxy(),
      holdInboundPorts
    });
    runtimeDirectories.add(runtimeDirectoryOf("hold-ports"));
    await service.connect(proxyRequest("hold-ports"));
    events.length = 0;

    first.emit("close", 1, null);
    await settle(service);
    expect(holdInboundPorts).toHaveBeenCalledWith([{ host: "127.0.0.1", port: 32000 }, { host: "127.0.0.1", port: 32001 }]);

    // The restart gets them back just before it binds them.
    service.wake("test");
    await settle(service);
    expect(events).toEqual(["hold 32000,32001", "release", "reserve"]);
    expect(service.getStatus().state).toBe("Connected");
    await service.dispose();
  });

  it("binds held ports so nothing else can, refuses what connects, and lets go of all of them", async () => {
    const free = await Promise.all([freeLoopbackPort(), freeLoopbackPort()]);
    const endpoints = free.map((port) => ({ host: "127.0.0.1", port }));
    const held = await bindRefusingLoopbackPorts(endpoints);
    try {
      await expect(listenOn(free[0])).rejects.toMatchObject({ code: "EADDRINUSE" });
      // A connection is accepted and dropped at once, not served.
      await expect(
        new Promise<string>((resolve, reject) => {
          const socket = net.connect({ host: "127.0.0.1", port: free[1] });
          socket.on("error", reject);
          socket.on("close", () => resolve("closed"));
          socket.on("data", () => reject(new Error("the held port answered")));
        })
      ).resolves.toBe("closed");
    } finally {
      await held.release();
    }
    const again = await listenOn(free[0]);
    await new Promise<void>((resolve) => again.close(() => resolve()));

    // All or nothing: a port someone else has releases the ones already bound.
    const taken = await listenOn(free[1]);
    try {
      await expect(bindRefusingLoopbackPorts(endpoints)).rejects.toMatchObject({ code: "EADDRINUSE" });
      const released = await listenOn(free[0]);
      await new Promise<void>((resolve) => released.close(() => resolve()));
    } finally {
      await new Promise<void>((resolve) => taken.close(() => resolve()));
    }
  });

  it("gives held routing up at once when another program took Xray's port", async () => {
    const first = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(first);
    const systemProxy = fakeSystemProxy();
    const service = new XrayServiceBridge(initialStatus(), {
      executablePath: process.execPath,
      runtimeDirectory: runtimeDirectoryOf("ports-taken"),
      systemProxy,
      holdInboundPorts: async () => {
        throw new Error("listen EADDRINUSE: address already in use 127.0.0.1:32000");
      }
    });
    runtimeDirectories.add(runtimeDirectoryOf("ports-taken"));
    const diagnostics = collectDiagnostics(service);
    await service.connect(proxyRequest("ports-taken"));
    vi.mocked(systemProxy.restore).mockClear();

    first.emit("close", 1, null);
    await settle(service);
    expect(systemProxy.restore).toHaveBeenCalled();
    expect(diagnostics.some((entry) => entry.message.startsWith("Another program took Xray's local port while Xray was down"))).toBe(true);
    // The restart still comes; it just starts from direct routing.
    expect(service.getStatus().state).toBe("Reconnecting");
    await service.dispose();
  });

  it("ends in Error, and gives routing back, when the Xray runtime disappeared", async () => {
    // An antivirus quarantined xray.exe: every restart would fail the same
    // way, every few minutes, for as long as the app runs.
    const directory = runtimeDirectoryOf("runtime-gone");
    runtimeDirectories.add(directory);
    await mkdir(directory, { recursive: true });
    const executablePath = path.join(directory, "xray");
    await writeFile(executablePath, "");
    const first = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(first);
    const systemProxy = fakeSystemProxy();
    const service = new XrayServiceBridge(initialStatus(), {
      executablePath,
      runtimeDirectory: directory,
      systemProxy,
      holdInboundPorts: async () => ({ release: async () => undefined })
    });
    await service.connect(proxyRequest("runtime-gone"));
    vi.mocked(systemProxy.restore).mockClear();

    await rm(executablePath);
    first.emit("close", 1, null);
    await settle(service);
    service.wake("test");
    await settle(service);

    expect(service.getStatus()).toMatchObject({ state: "Error", message: `Xray runtime was not found at ${executablePath}.` });
    expect((service as unknown as { reconnectTimer?: NodeJS.Timeout }).reconnectTimer).toBeUndefined();
    expect(systemProxy.restore).toHaveBeenCalled();
    expect(childProcess.spawn).toHaveBeenCalledTimes(1);
    await service.dispose();
  });

  it("lets the held ports go only after routing stopped pointing at them", async () => {
    // A blocked restart gives held routing up. Releasing the ports first left
    // the proxy setting (and an adapter) aimed at free ports while it was
    // taken down, for any local program to bind and receive.
    const directory = runtimeDirectoryOf("release-order");
    runtimeDirectories.add(directory);
    await mkdir(directory, { recursive: true });
    const executablePath = path.join(directory, "xray");
    await writeFile(executablePath, "");
    const first = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(first);
    const events: string[] = [];
    const systemProxy = fakeSystemProxy();
    const service = new XrayServiceBridge(initialStatus(), {
      executablePath,
      runtimeDirectory: directory,
      systemProxy,
      holdInboundPorts: async () => ({ release: async () => { events.push("release"); } })
    });
    await service.connect(proxyRequest("release-order"));
    vi.mocked(systemProxy.restore).mockImplementation(async () => {
      events.push("restore");
    });

    await rm(executablePath);
    first.emit("close", 1, null);
    await settle(service);
    service.wake("test");
    await settle(service);

    expect(service.getStatus().state).toBe("Error");
    expect(events).toEqual(["restore", "release"]);
    await service.dispose();
  });

  it("releases routing held for a restart when the user dismisses the error", async () => {
    const first = new FakeXrayProcess();
    childProcess.spawn.mockReturnValueOnce(first);
    const systemProxy = fakeSystemProxy();
    const service = createService("clear-error-hold", systemProxy);
    await service.connect(proxyRequest("clear"));
    vi.mocked(systemProxy.restore).mockClear();

    first.emit("close", 1, null);
    expect(service.getStatus().state).toBe("Error");
    await service.clearError();
    await settle(service);

    expect(service.getStatus().state).toBe("Disconnected");
    expect(systemProxy.restore).toHaveBeenCalled();
    expect(childProcess.spawn).toHaveBeenCalledTimes(1);
    await service.dispose();
  });

  it("never schedules a restart more than five minutes out", async () => {
    const timeouts = vi.spyOn(globalThis, "setTimeout");
    vi.spyOn(Math, "random").mockReturnValue(0.999_999);
    const service = createService("restart-cap");
    const internals = service as unknown as {
      status: RuntimeStatus;
      lastRequest: ProxyConnectRequest | undefined;
      lifecycleGeneration: number;
      scheduleReconnect(reason: string, generation: number): void;
    };
    try {
      internals.status = { ...internals.status, state: "Error", reconnectAttempt: 40 };
      internals.lastRequest = proxyRequest("cap");
      internals.scheduleReconnect("boom", internals.lifecycleGeneration);

      const delay = timeouts.mock.calls.at(-1)?.[1];
      expect(delay).toBeGreaterThanOrEqual(256_000);
      expect(delay).toBeLessThanOrEqual(5 * 60 * 1000);
    } finally {
      vi.restoreAllMocks();
      await service.dispose();
    }
  });

  it("applies routing again at once when the TUN adapter dies under a connected session", async () => {
    // The helper's death takes the adapter and its capture routes with it,
    // and the Windows proxy setting went when TUN came up: selected traffic
    // leaves directly while the session still reads Connected.
    await withWin32(async () => {
      childProcess.spawn.mockReturnValueOnce(new FakeXrayProcess());
      const systemProxy = fakeSystemProxy();
      const dataplane = fakeDataplane();
      const service = createService("tun-death", systemProxy, dataplane);
      const diagnostics = collectDiagnostics(service);
      await service.connect({ ...proxyRequest("tun-death"), tunDataplaneEnabled: true });
      expect(service.getStatus()).toMatchObject({ state: "Connected", tunActive: true });

      dataplane.die("Native helper exited (3).");
      expect(service.getStatus().tunActive).toBe(false);
      await settle(service);

      // A fresh start brings the adapter back; Xray never stopped.
      expect(dataplane.started).toHaveLength(2);
      expect(childProcess.spawn).toHaveBeenCalledTimes(1);
      expect(service.getStatus()).toMatchObject({ state: "Connected", tunActive: true });
      expect(systemProxy.apply).not.toHaveBeenCalled();
      const warning = diagnostics.find((entry) => entry.message.startsWith("TUN dataplane stopped unexpectedly"));
      expect(warning?.message).toContain("Native helper exited (3).");
      expect(warning?.message).toContain("Routing is being applied again");
      await service.dispose();
    });
  });

  it("falls back to the proxy path for the session once the adapter keeps dying", async () => {
    await withWin32(async () => {
      childProcess.spawn.mockReturnValueOnce(new FakeXrayProcess()).mockReturnValueOnce(new FakeXrayProcess());
      const systemProxy = fakeSystemProxy();
      const dataplane = fakeDataplane();
      const service = createService("tun-flap", systemProxy, dataplane);
      const diagnostics = collectDiagnostics(service);
      await service.connect({ ...proxyRequest("tun-flap"), tunDataplaneEnabled: true });

      for (let death = 0; death < 3; death += 1) {
        dataplane.die("the adapter read failed");
        await settle(service);
      }

      // Two deaths were answered with a restart; the third ends the loop of
      // adapters coming and going, and the proxy path takes over.
      expect(dataplane.started).toHaveLength(3);
      expect(dataplane.isActive).toBe(false);
      expect(systemProxy.apply).toHaveBeenCalledTimes(1);
      expect(service.getStatus()).toMatchObject({ state: "Connected", tunActive: false });
      expect(diagnostics.some((entry) => entry.message.includes("Routing continues on the Windows proxy path"))).toBe(true);
      expect(diagnostics.some((entry) => entry.message.startsWith("TUN routing is unavailable") && entry.message.includes("stopped unexpectedly 3 times"))).toBe(true);

      // A new Connect gives the adapter another chance.
      await service.connect({ ...proxyRequest("tun-flap"), tunDataplaneEnabled: true });
      expect(dataplane.started).toHaveLength(4);
      expect(service.getStatus()).toMatchObject({ state: "Connected", tunActive: true });
      await service.dispose();
    });
  });

  it("releases routing held for a restart when the adapter dies while Xray is down", async () => {
    await withWin32(async () => {
      const first = new FakeXrayProcess();
      childProcess.spawn.mockReturnValueOnce(first).mockReturnValueOnce(new FakeXrayProcess());
      const systemProxy = fakeSystemProxy();
      const dataplane = fakeDataplane();
      const service = createService("tun-death-held", systemProxy, dataplane);
      const internals = service as unknown as { routingHeld: boolean };
      const diagnostics = collectDiagnostics(service);
      await service.connect({ ...proxyRequest("tun-death-held"), tunDataplaneEnabled: true });
      vi.mocked(systemProxy.restore).mockClear();

      first.emit("close", 1, null);
      await settle(service);
      // The adapter is what holds Xray's routing for the restart.
      expect(service.getStatus().state).toBe("Reconnecting");
      expect(internals.routingHeld).toBe(true);
      expect(dataplane.stopped).toBe(0);

      dataplane.die("Native helper exited (3).");
      await settle(service);

      // Nothing captures traffic any more, so there is nothing left to hold.
      expect(internals.routingHeld).toBe(false);
      expect(systemProxy.restore).toHaveBeenCalled();
      expect(diagnostics.find((entry) => entry.message.startsWith("TUN dataplane stopped unexpectedly"))?.message)
        .toContain("Routing is applied again when Xray is back");
      expect(diagnostics.find((entry) => entry.message.startsWith("TUN dataplane stopped unexpectedly"))?.message)
        .toContain("Until then apps connect directly.");

      // The restart applies routing afresh, adapter included.
      service.wake("test");
      await settle(service);
      expect(dataplane.started).toHaveLength(2);
      expect(service.getStatus()).toMatchObject({ state: "Connected", tunActive: true });
      await service.dispose();
    });
  });

  it("prefers the ports the previous Xray listened on, never the routing listener's", async () => {
    childProcess.spawn
      .mockReturnValueOnce(new FakeXrayProcess())
      .mockReturnValueOnce(new FakeXrayProcess())
      .mockReturnValueOnce(new FakeXrayProcess());
    rememberLocalProxyPort(50_817);
    const service = createService("sticky-ports");

    await service.connect(proxyRequest("first"));
    expect(runtime.reserveDistinctLocalTcpPorts).toHaveBeenLastCalledWith(2, undefined, {
      preferredPorts: [undefined, undefined],
      avoidPorts: [50_817, undefined]
    });

    await service.connect(proxyRequest("second"));
    expect(runtime.reserveDistinctLocalTcpPorts).toHaveBeenLastCalledWith(2, undefined, {
      preferredPorts: [32000, 32001],
      avoidPorts: [50_817, undefined]
    });

    // Xray exiting at startup on a remembered port - taken since the check -
    // sends the next attempt to fresh ports.
    const exiting = new FakeXrayProcess();
    childProcess.spawn.mockReset().mockReturnValueOnce(exiting);
    runtime.waitForProcessStartup.mockImplementationOnce(async () => {
      exiting.exitCode = 23;
      exiting.emit("close", 23, null);
      throw new Error("Xray runtime exited during startup with code 23.");
    });
    await service.connect(proxyRequest("third"));
    expect(service.getStatus().state).toBe("Error");

    childProcess.spawn.mockReturnValueOnce(new FakeXrayProcess());
    await service.connect(proxyRequest("fourth"));
    expect(runtime.reserveDistinctLocalTcpPorts).toHaveBeenLastCalledWith(2, undefined, {
      preferredPorts: [undefined, undefined],
      avoidPorts: [50_817, undefined]
    });
    await service.dispose();
  });
});

interface WrittenXrayConfig {
  routing?: { rules: Array<{ ip?: string[]; domain?: string[]; outboundTag: string }> };
  outbounds: Array<{
    protocol: string;
    streamSettings?: {
      finalmask?: {
        udp?: Array<{ type: string; settings?: Record<string, unknown> }>;
        quicParams?: { udpHop?: Record<string, unknown> };
      };
    };
  }>;
}

/** Hands out `processHandle` on the next spawn, keeping the config Xray was given on stdin. */
function spawnCapturingConfig(processHandle: FakeXrayProcess, configs: WrittenXrayConfig[]): void {
  childProcess.spawn.mockImplementationOnce((_executable: string, args: string[]) => {
    expect(args).toEqual(["run", "-config", "stdin:"]);
    processHandle.stdin.onEnd = (text) => configs.push(JSON.parse(text) as WrittenXrayConfig);
    return processHandle;
  });
}

/** Waits until every queued lifecycle step, including ones queued while waiting, has run. */
async function settle(service: XrayServiceBridge): Promise<void> {
  const internals = service as unknown as { mutationTail: Promise<void> };
  let tail = internals.mutationTail;
  for (;;) {
    await tail;
    if (internals.mutationTail === tail) {
      return;
    }
    tail = internals.mutationTail;
  }
}

function collectDiagnostics(service: XrayServiceBridge): Array<{ level: string; message: string }> {
  const entries: Array<{ level: string; message: string }> = [];
  service.onEvent((event) => {
    if (event.type === "diagnostics-appended") {
      entries.push({ level: event.entry.level, message: event.entry.message });
    }
  });
  return entries;
}

/** A loopback port nothing listens on, so a SOCKS connect to it is refused at once. */
async function closedLocalPort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return typeof address === "object" && address ? address.port : 1;
}

class FakeOutput extends EventEmitter {
  readonly resume = vi.fn(() => this);

  setEncoding(): this {
    return this;
  }
}

/** Xray's stdin: what was written to it, and whether it was closed. */
class FakeInput extends EventEmitter {
  text = "";
  ended = false;
  onEnd: ((text: string) => void) | undefined;

  write(chunk: string): boolean {
    this.text += chunk;
    return true;
  }

  end(chunk?: string): this {
    if (chunk !== undefined) {
      this.text += chunk;
    }
    this.ended = true;
    this.onEnd?.(this.text);
    return this;
  }
}

class FakeXrayProcess extends EventEmitter {
  readonly stdout = new FakeOutput();
  readonly stderr = new FakeOutput();
  readonly stdin = new FakeInput();
  readonly kill = vi.fn(() => true);
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
}

function runtimeDirectoryOf(name: string): string {
  return path.join(os.tmpdir(), `shadow-ssh-xray-lifecycle-${process.pid}-${name}`);
}

async function freeLoopbackPort(): Promise<number> {
  const server = await listenOn(0);
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

function listenOn(port: number): Promise<net.Server> {
  return new Promise<net.Server>((resolve, reject) => {
    const server = net.createServer((socket) => socket.destroy());
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port, exclusive: true }, () => resolve(server));
  });
}

function createService(name: string, systemProxy = fakeSystemProxy(), dataplane?: DataplaneController): XrayServiceBridge {
  const runtimeDirectory = runtimeDirectoryOf(name);
  runtimeDirectories.add(runtimeDirectory);
  return new XrayServiceBridge(initialStatus(), {
    executablePath: process.execPath,
    runtimeDirectory,
    systemProxy,
    // The mocked ports are fixed; binding them for real would make the
    // result depend on what else the machine listens on.
    holdInboundPorts: async () => ({ release: async () => undefined }),
    ...(dataplane ? { dataplane, protectedAddressResolver: async () => ["203.0.113.9"] } : {})
  });
}

type FakeDataplane = DataplaneController & {
  started: DataplaneStartRequest[];
  stopped: number;
  isActive: boolean;
  /** Plays the helper dying under a running adapter. */
  die(reason: string): void;
};

function fakeDataplane(): FakeDataplane {
  const listeners = new Set<(reason: string) => void>();
  // Like the real controller: active from a successful start until a stop
  // or the helper's death.
  const controller: FakeDataplane = {
    started: [],
    stopped: 0,
    isActive: false,
    probe: async () => ({ available: true }),
    start: async (request) => {
      controller.started.push(request);
      controller.isActive = true;
    },
    stop: async () => {
      controller.stopped += 1;
      controller.isActive = false;
    },
    dispose: async () => undefined,
    onUnexpectedStop: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    die: (reason) => {
      if (!controller.isActive) {
        return;
      }
      controller.isActive = false;
      for (const listener of listeners) {
        listener(reason);
      }
    }
  };
  return controller;
}

async function withWin32(run: () => Promise<void>): Promise<void> {
  const platform = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
  try {
    await run();
  } finally {
    if (platform) {
      Object.defineProperty(process, "platform", platform);
    }
  }
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

function hysteria2Request(id: string, rawUri: string, hopPorts?: string): ProxyConnectRequest {
  const request = proxyRequest(id);
  return {
    ...request,
    profile: {
      ...request.profile,
      protocol: "hysteria2",
      host: "hy.example.com",
      port: 443,
      ...(hopPorts ? { hopPorts } : {}),
      transport: "hysteria",
      security: "tls"
    },
    secrets: { rawUri }
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
