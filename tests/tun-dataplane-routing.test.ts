import { describe, expect, it, vi } from "vitest";
import type { SystemProxyApplyRequest, WindowsSystemProxyManager } from "../src/core/network/windows-system-proxy.js";
import type { DataplaneAvailability, DataplaneController } from "../src/service/native-dataplane.js";
import type { DataplaneStartRequest } from "../src/service/local-ipc-protocol.js";
import { LiveSshServiceBridge } from "../src/service/live-ssh-service.js";
import { XrayServiceBridge } from "../src/service/xray-service.js";
import type { ProcessAttribution } from "../src/service/process-attribution.js";
import type { ConnectRequest, ProxyConnectRequest, RoutingRule, RuntimeStatus } from "../src/shared/types.js";

// The Windows proxy setting is advisory: an application with its own proxy
// stack, or one speaking QUIC, ignores it and connects directly even when a
// `process.name` rule selects it. These cases pin the behaviour that fixes
// that - the adapter is preferred, it replaces the proxy setting rather than
// running beside it, and a machine that cannot bring it up still gets the old
// path instead of no routing at all.

interface SshInternals {
  status: RuntimeStatus;
  lastRequest: ConnectRequest | undefined;
  applySystemRouting(
    request: ConnectRequest,
    socksEndpoint: { host: string; port: number },
    allowConnecting?: boolean
  ): Promise<void>;
  stopRouting(): Promise<void>;
}

interface XrayInternals {
  status: RuntimeStatus;
  lastRequest: ProxyConnectRequest | undefined;
  applySystemRouting(request: ProxyConnectRequest, socksEndpoint: { host: string; port: number }): Promise<void>;
}

describe("TUN routing", () => {
  it("captures traffic at the adapter and takes the Windows proxy setting down", async () => {
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const dataplane = fakeDataplane();
      const service = createSshService(applies, dataplane);
      const internals = service as unknown as SshInternals;

      internals.status = { ...internals.status, state: "Connected" };
      const request = { ...sshConnectRequest(), tunDataplaneEnabled: true };
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 }, true);

      expect(dataplane.started).toHaveLength(1);
      const started = dataplane.started[0];
      expect(started.tunnelProxyEndpoint).toBe("127.0.0.1:51234");
      // The transport's own server must stay off the adapter, or the tunnel
      // would be asked to carry itself.
      expect(started.protectedAddresses).toEqual(["203.0.113.9"]);
      expect(started.protectedPort).toBe(22);
      // SSH has no datagram channel, so a selected application's UDP is
      // dropped by the helper rather than let out directly.
      expect(started.udpSupported).toBe(false);
      expect(started.routingRules).toEqual(request.routingRules);

      // Leaving the proxy setting in place would give proxy-aware apps a
      // second path into the same listener with different rules applied.
      expect(applies).toHaveLength(0);
      expect(dataplane.stopped).toBe(0);

      await internals.stopRouting();
      expect(dataplane.stopped).toBe(1);
    });
  });

  it("falls back to the Windows proxy path when the adapter cannot be created", async () => {
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const dataplane = fakeDataplane({
        availability: { available: false, reason: "not elevated" }
      });
      const service = createSshService(applies, dataplane);
      const internals = service as unknown as SshInternals;
      const messages: string[] = [];
      service.onEvent((event) => {
        if (event.type === "diagnostics-appended") {
          messages.push(event.entry.message);
        }
      });

      internals.status = { ...internals.status, state: "Connected" };
      const request = { ...sshConnectRequest(), tunDataplaneEnabled: true };
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 }, true);

      expect(dataplane.started).toHaveLength(0);
      // Partial protection beats none: the proxy path still runs.
      expect(applies.length).toBeGreaterThan(0);
      // The user has to be told why, or an unelevated launch looks identical
      // to a working one until traffic leaks.
      expect(messages.join("\n")).toContain("not elevated");
    });
  });

  it("is not used unless the setting asks for it", async () => {
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const dataplane = fakeDataplane();
      const service = createSshService(applies, dataplane);
      const internals = service as unknown as SshInternals;

      internals.status = { ...internals.status, state: "Connected" };
      const request = sshConnectRequest();
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 }, true);

      expect(dataplane.probes).toBe(0);
      expect(dataplane.started).toHaveLength(0);
      expect(applies.length).toBeGreaterThan(0);
    });
  });

  it("points the helper straight at Xray's inbound, which can carry UDP", async () => {
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const dataplane = fakeDataplane();
      const service = createXrayService(applies, dataplane);
      const internals = service as unknown as XrayInternals;

      internals.status = { ...internals.status, state: "Connected" };
      const request = { ...xrayConnectRequest(), tunDataplaneEnabled: true };
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 52_000 });

      expect(dataplane.started).toHaveLength(1);
      const started = dataplane.started[0];
      expect(started.tunnelProxyEndpoint).toBe("127.0.0.1:52000");
      // Xray's SOCKS inbound speaks UDP ASSOCIATE, so Discord voice and QUIC
      // are carried instead of dropped.
      expect(started.udpSupported).toBe(true);
      expect(applies).toHaveLength(0);
    });
  });
});

interface FakeDataplane extends DataplaneController {
  started: DataplaneStartRequest[];
  stopped: number;
  probes: number;
}

function fakeDataplane({
  availability = { available: true } as DataplaneAvailability,
  startError
}: { availability?: DataplaneAvailability; startError?: Error } = {}): FakeDataplane {
  const controller: FakeDataplane = {
    started: [],
    stopped: 0,
    probes: 0,
    isActive: false,
    probe: async () => {
      controller.probes += 1;
      return availability;
    },
    start: async (request) => {
      if (startError) {
        throw startError;
      }
      controller.started.push(request);
    },
    stop: async () => {
      controller.stopped += 1;
    },
    dispose: async () => undefined
  };
  return controller;
}

function attribution(): ProcessAttribution {
  return {
    // Attribution is the system-proxy path's mechanism. The adapter does its
    // own, so this only matters for the fallback cases.
    isAvailable: async () => false,
    resolveProcessName: async () => undefined,
    dispose: async () => undefined
  };
}

function systemProxy(applies: SystemProxyApplyRequest[]): WindowsSystemProxyManager {
  return {
    apply: vi.fn(async (request: SystemProxyApplyRequest) => {
      applies.push(request);
      return { applied: true, message: "applied" };
    }),
    restore: vi.fn(async () => undefined)
  } as unknown as WindowsSystemProxyManager;
}

function createSshService(applies: SystemProxyApplyRequest[], dataplane: DataplaneController): LiveSshServiceBridge {
  return new LiveSshServiceBridge(initialStatus(), {
    systemProxy: systemProxy(applies),
    processConnectionsProvider: async () => [],
    processDnsEntriesProvider: async () => [],
    processAttribution: attribution(),
    dataplane,
    protectedAddressResolver: async () => ["203.0.113.9"]
  });
}

function createXrayService(applies: SystemProxyApplyRequest[], dataplane: DataplaneController): XrayServiceBridge {
  return new XrayServiceBridge(initialStatus(), {
    runtimeDirectory: "/tmp/shadow-ssh-tun-routing",
    systemProxy: systemProxy(applies),
    processConnectionsProvider: async () => [],
    processDnsEntriesProvider: async () => [],
    processAttribution: attribution(),
    dataplane,
    protectedAddressResolver: async () => ["203.0.113.9"]
  });
}

function routingRules(): RoutingRule[] {
  return [
    { id: "p1", type: "process.name", value: "telegram.exe", enabled: true, createdAt: "", updatedAt: "" }
  ];
}

function sshConnectRequest(): ConnectRequest {
  return {
    config: {
      id: "config",
      name: "config",
      host: "ssh.example",
      port: 22,
      username: "user",
      authType: "password",
      expectedServerFingerprint: "",
      keepaliveIntervalSec: 30,
      note: "",
      createdAt: "",
      updatedAt: ""
    },
    routingMode: "selected-rules",
    routingRules: routingRules(),
    routingProxyDomains: [],
    routingDirectDomains: [],
    checkEndpoint: "example.com:443"
  };
}

function xrayConnectRequest(): ProxyConnectRequest {
  return {
    profile: {
      id: "profile",
      name: "profile",
      protocol: "vless",
      host: "proxy.example",
      port: 443,
      transport: "tcp",
      security: "tls",
      flow: "",
      source: "manual",
      rawUriSecretId: "secret",
      fingerprint: "",
      isSelected: true,
      isPinned: false,
      isStale: false,
      lastTestStatus: "unknown",
      lastSeenAt: "",
      createdAt: "",
      updatedAt: ""
    },
    routingMode: "selected-rules",
    routingRules: routingRules(),
    routingProxyDomains: [],
    routingDirectDomains: [],
    checkEndpoint: "example.com:443",
    secrets: {} as ProxyConnectRequest["secrets"]
  };
}

function initialStatus(): RuntimeStatus {
  return {
    state: "Disconnected",
    message: "",
    reconnectAttempt: 0,
    transport: "live-ssh",
    platformTarget: { platform: "windows", arch: "x64", serviceExecutableName: "", serviceRelativePath: "", supportsPrivilegedService: true },
    realTunnelAvailable: false
  };
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

describe("TUN routing refuses to capture without an exclusion", () => {
  it("stays on the proxy path when the transport server cannot be resolved", async () => {
    // Capturing the default route without excluding the server resets the
    // transport's own connection and leaves the adapter black-holing exactly
    // the traffic it was meant to protect.
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const dataplane = fakeDataplane();
      const service = new LiveSshServiceBridge(initialStatus(), {
        systemProxy: systemProxy(applies),
        processConnectionsProvider: async () => [],
        processDnsEntriesProvider: async () => [],
        processAttribution: attribution(),
        dataplane,
        protectedAddressResolver: async () => []
      });
      const internals = service as unknown as SshInternals;
      const messages: string[] = [];
      service.onEvent((event) => {
        if (event.type === "diagnostics-appended") {
          messages.push(event.entry.message);
        }
      });

      internals.status = { ...internals.status, state: "Connected" };
      const request = { ...sshConnectRequest(), tunDataplaneEnabled: true };
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 }, true);

      expect(dataplane.started).toHaveLength(0);
      expect(applies.length).toBeGreaterThan(0);
      expect(messages.join("\n")).toContain("no address could be resolved");
    });
  });
});
