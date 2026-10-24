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
  stopRouting(): Promise<void>;
  holdRouting(): void;
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
      // Only port hopping dials more than one server port.
      expect(started).not.toHaveProperty("protectedPorts");
      expect(applies).toHaveLength(0);
    });
  });

  it("keeps every port a Hysteria 2 profile hops across off the adapter", async () => {
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const dataplane = fakeDataplane();
      const service = createXrayService(applies, dataplane);
      const internals = service as unknown as XrayInternals;

      internals.status = { ...internals.status, state: "Connected" };
      const base = xrayConnectRequest();
      const request: ProxyConnectRequest = {
        ...base,
        profile: {
          ...base.profile,
          protocol: "hysteria2",
          port: 443,
          hopPorts: "443,20000-30000",
          transport: "hysteria"
        },
        tunDataplaneEnabled: true
      };
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 52_000 });

      expect(dataplane.started).toHaveLength(1);
      const started = dataplane.started[0];
      expect(started.protectedAddresses).toEqual(["203.0.113.9"]);
      // With hopping Xray starts on a random port from the list, not on the
      // profile's port, then hops across the rest; a port missing here would
      // route the transport into its own adapter. protectedPort is only the
      // port the link names first.
      expect(started.protectedPort).toBe(443);
      expect(started.protectedPorts).toBe("443,20000-30000");
      // QUIC is UDP, which is why it can hop at all.
      expect(started.udpSupported).toBe(true);
      expect(applies).toHaveLength(0);
    });
  });
});

interface FakeDataplane extends DataplaneController {
  started: DataplaneStartRequest[];
  startAttempts: number;
  stopped: number;
  probes: number;
  disposals: number;
  isActive: boolean;
  /** What the next probes answer; changeable mid-test. */
  availability: DataplaneAvailability;
  /** Thrown by every following start; changeable mid-test. */
  startError: Error | undefined;
  /** Starts and stops in the order they happened, with the proxy applies a test records beside them. */
  calls: string[];
}

function fakeDataplane({
  availability = { available: true } as DataplaneAvailability,
  startError,
  failFirstStarts = 0
}: { availability?: DataplaneAvailability; startError?: Error; failFirstStarts?: number } = {}): FakeDataplane {
  let remainingFailures = failFirstStarts;
  const controller: FakeDataplane = {
    started: [],
    startAttempts: 0,
    stopped: 0,
    probes: 0,
    disposals: 0,
    isActive: false,
    availability,
    startError,
    calls: [],
    probe: async () => {
      controller.probes += 1;
      return controller.availability;
    },
    start: async (request) => {
      controller.startAttempts += 1;
      controller.calls.push("start");
      if (remainingFailures > 0) {
        remainingFailures -= 1;
        throw new Error("adapter is still being removed");
      }
      if (controller.startError) {
        throw controller.startError;
      }
      controller.started.push(request);
      controller.isActive = true;
    },
    stop: async () => {
      controller.stopped += 1;
      controller.calls.push("stop");
      controller.isActive = false;
    },
    dispose: async () => {
      controller.disposals += 1;
    }
  };
  return controller;
}

/**
 * Attribution that answers, so the locally enforced path is taken - and that
 * latches off once disposed, exactly as the real one does. Without the latch
 * this fake would hide the bug it is here to catch.
 */
function workingAttribution(): ProcessAttribution {
  let disposed = false;
  return {
    isAvailable: async () => !disposed,
    resolveProcessName: async () => (disposed ? undefined : "telegram.exe"),
    unavailableReason: () => (disposed ? "the attribution helper has been shut down" : undefined),
    dispose: async () => {
      disposed = true;
    }
  };
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

describe("TUN routing across a reconnect", () => {
  it("retries a start that loses the race with the previous adapter being removed", async () => {
    // Toggling the tunnel off and straight back on is the normal case, and it
    // is exactly when Windows has not finished removing the old adapter. One
    // attempt turned that race into a silent session-long fallback to the
    // proxy path, where domain rules keep working and process rules do not -
    // which is what the bug looked like from the outside.
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const dataplane = fakeDataplane({ failFirstStarts: 1 });
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

      expect(dataplane.startAttempts).toBe(2);
      expect(dataplane.started).toHaveLength(1);
      expect(applies).toHaveLength(0);
      expect(messages.some((message) => message.includes("retrying"))).toBe(true);
    });
  });

  it("stops enforcing locally before the helper starts, so its IPv6 check goes through the tunnel", async () => {
    // The helper asks through the listener whether the server reaches IPv6
    // the moment it is up. A listener still enforcing the policy of an earlier
    // fallback would send that check out directly, and this machine's IPv6
    // would be taken for the server's.
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const enforcingDuringStart: boolean[] = [];
      let failStarts = 2;
      const dataplane = {
        isActive: false,
        probe: async () => ({ available: true }),
        start: async () => {
          enforcingDuringStart.push((service as unknown as { localProcessEnforcement: boolean }).localProcessEnforcement);
          if (failStarts > 0) {
            failStarts -= 1;
            throw new Error("adapter is still being removed");
          }
        },
        stop: async () => undefined,
        dispose: async () => undefined
      } as unknown as DataplaneController;
      const service = new LiveSshServiceBridge(initialStatus(), {
        systemProxy: systemProxy(applies),
        processConnectionsProvider: async () => [],
        processDnsEntriesProvider: async () => [],
        processAttribution: workingAttribution(),
        dataplane,
        protectedAddressResolver: async () => ["203.0.113.9"]
      });
      const internals = service as unknown as SshInternals & { localProcessEnforcement: boolean };

      internals.status = { ...internals.status, state: "Connected" };
      const request = { ...sshConnectRequest(), tunDataplaneEnabled: true };
      internals.lastRequest = request;
      // Both attempts fail: the session falls back to enforcing locally.
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 }, true);
      expect(internals.localProcessEnforcement).toBe(true);

      // A later apply - a routing change, a held reconnect - brings TUN up.
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 }, true);
      expect(enforcingDuringStart).toEqual([false, false, false]);
      expect(internals.localProcessEnforcement).toBe(false);
    });
  });

  it("does not switch the listener to local enforcement under an adapter an overtaken update kept", async () => {
    // The session drops while a routing update waits on the helper. The
    // adapter stays up for the reconnect and keeps forwarding selected flows
    // to the listener - from the helper's own socket, as bare addresses. An
    // enforcer switched on there sent a process rule's flows direct instead
    // of letting them wait for the tunnel.
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const dataplane = fakeDataplane();
      const service = new LiveSshServiceBridge(initialStatus(), {
        systemProxy: systemProxy(applies),
        processConnectionsProvider: async () => [],
        processDnsEntriesProvider: async () => [],
        processAttribution: workingAttribution(),
        dataplane,
        protectedAddressResolver: async () => ["203.0.113.9"]
      });
      const internals = service as unknown as SshInternals & { localProcessEnforcement: boolean };
      internals.status = { ...internals.status, state: "Connected" };
      const request = { ...sshConnectRequest(), tunDataplaneEnabled: true };
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 });
      expect(dataplane.isActive).toBe(true);
      expect(internals.localProcessEnforcement).toBe(false);

      const probe = dataplane.probe;
      dataplane.probe = async () => {
        internals.status = { ...internals.status, state: "Reconnecting" };
        return probe();
      };
      dataplane.calls.length = 0;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 });

      expect(dataplane.isActive).toBe(true);
      expect(dataplane.calls).toEqual([]);
      expect(applies).toHaveLength(0);
      expect(internals.localProcessEnforcement).toBe(false);
      await service.dispose();
    });
  });

  it("keeps enforcing locally when an update's TUN start is overtaken with no adapter up", async () => {
    // On the enforced path the system proxy hands everything to the listener.
    // The session dropped while a retried TUN start failed: the listener used
    // to stop enforcing, park every flow for the tunnel and, after the
    // reconnect, tunnel unselected apps and direct-list sites with them.
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const dataplane = fakeDataplane({ startError: new Error("wintun.dll is missing") });
      const service = new LiveSshServiceBridge(initialStatus(), {
        systemProxy: systemProxy(applies),
        processConnectionsProvider: async () => [],
        processDnsEntriesProvider: async () => [],
        processAttribution: workingAttribution(),
        dataplane,
        protectedAddressResolver: async () => ["203.0.113.9"]
      });
      const internals = service as unknown as SshInternals & { localProcessEnforcement: boolean; localRoutingContext: unknown };
      internals.status = { ...internals.status, state: "Connected" };
      const request = { ...sshConnectRequest(), tunDataplaneEnabled: true };
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 });
      expect(internals.localProcessEnforcement).toBe(true);
      const context = internals.localRoutingContext;
      expect(context).toBeDefined();
      const appliesBefore = applies.length;

      dataplane.start = async () => {
        dataplane.calls.push("start");
        internals.status = { ...internals.status, state: "Reconnecting" };
        throw new Error("Native helper start-dataplane request timed out.");
      };
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 });

      expect(internals.localProcessEnforcement).toBe(true);
      expect(internals.localRoutingContext).toBe(context);
      // Whoever overtook the update applies routing afresh.
      expect(applies).toHaveLength(appliesBefore);
      await service.dispose();
    });
  });

  it("says what a permanent failure costs instead of falling back silently", async () => {
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const dataplane = fakeDataplane({ startError: new Error("wintun.dll is missing") });
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

      expect(applies.length).toBeGreaterThan(0);
      const fallback = messages.find((message) => message.includes("continuing on the Windows proxy path"));
      expect(fallback).toContain("wintun.dll is missing");
      // The tunnel still looks healthy on the fallback path, so the diagnostic
      // has to name what stopped working.
      expect(fallback).toContain("process rules will not reach");
    });
  });

  it("brings the adapter back up on a second connect after a clean stop", async () => {
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const dataplane = fakeDataplane();
      const service = createSshService(applies, dataplane);
      const internals = service as unknown as SshInternals;

      internals.status = { ...internals.status, state: "Connected" };
      const first = { ...sshConnectRequest(), tunDataplaneEnabled: true };
      internals.lastRequest = first;
      await internals.applySystemRouting(first, { host: "127.0.0.1", port: 51_234 }, true);
      await internals.stopRouting();

      // The listener gets a fresh ephemeral port on every connect, so the
      // helper has to be told where to send captured traffic again.
      internals.status = { ...internals.status, state: "Connected" };
      await internals.applySystemRouting(first, { host: "127.0.0.1", port: 51_999 }, true);

      expect(dataplane.stopped).toBe(1);
      expect(dataplane.started).toHaveLength(2);
      expect(dataplane.started[1].tunnelProxyEndpoint).toBe("127.0.0.1:51999");
      expect(applies).toHaveLength(0);
    });
  });
});

describe("Per-process enforcement across an Xray reconnect", () => {
  // The Xray bridge used to dispose its attribution helper on an ordinary
  // disconnect, so the second connect fell back to PAC guessing: domain rules
  // kept working and process rules stopped reaching anything. SSH never had
  // that bug, which is exactly how the asymmetry showed up in the field.
  it("still enforces locally on the second connect", async () => {
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const service = new XrayServiceBridge(initialStatus(), {
        runtimeDirectory: "/tmp/shadow-ssh-xray-reconnect",
        systemProxy: systemProxy(applies),
        processConnectionsProvider: async () => [],
        processDnsEntriesProvider: async () => [],
        processAttribution: workingAttribution(),
        dataplane: fakeDataplane({ availability: { available: false, reason: "no adapter here" } }),
        protectedAddressResolver: async () => ["203.0.113.9"]
      });
      const internals = service as unknown as XrayInternals;

      internals.status = { ...internals.status, state: "Connected" };
      const request = xrayConnectRequest();
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 52_000 });
      // The enforced path points the system proxy at our own listener and
      // takes over policy; the PAC fallback would publish "selected-rules".
      expect(applies.at(-1)?.mode).toBe("proxy-all");

      await service.disconnect();

      internals.status = { ...internals.status, state: "Connected" };
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 52_777 });
      expect(applies.at(-1)?.mode).toBe("proxy-all");

      await service.dispose();
    });
  });

  it("names the cause when it has to fall back", async () => {
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const service = new XrayServiceBridge(initialStatus(), {
        runtimeDirectory: "/tmp/shadow-ssh-xray-fallback",
        systemProxy: systemProxy(applies),
        processConnectionsProvider: async () => [],
        processDnsEntriesProvider: async () => [],
        processAttribution: {
          isAvailable: async () => false,
          resolveProcessName: async () => undefined,
          unavailableReason: () => "the attribution helper has been shut down",
          dispose: async () => undefined
        },
        dataplane: fakeDataplane({ availability: { available: false, reason: "no adapter here" } }),
        protectedAddressResolver: async () => ["203.0.113.9"]
      });
      const internals = service as unknown as XrayInternals;
      const messages: string[] = [];
      service.onEvent((event) => {
        if (event.type === "diagnostics-appended") {
          messages.push(event.entry.message);
        }
      });

      internals.status = { ...internals.status, state: "Connected" };
      const request = xrayConnectRequest();
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 52_000 });

      const warning = messages.find((message) => message.includes("Per-process enforcement is unavailable"));
      expect(warning).toContain("the attribution helper has been shut down");
      await service.dispose();
    });
  });
});

describe("Reporting why the tunnel adapter is unavailable", () => {
  it("passes the helper's own reason through instead of guessing at elevation", async () => {
    // "Start as administrator" is wrong advice for the user who already is one
    // and whose wintun.dll is simply in the wrong folder - and there is no way
    // for them to find that out from the app.
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const dataplane = fakeDataplane({
        availability: {
          available: false,
          reason: String.raw`The native helper cannot create a tunnel adapter: wintun.dll was not found next to the service binary in C:\App
esources
ative\windowsd.`
        }
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

      const warning = messages.find((message) => message.includes("TUN routing is unavailable"));
      expect(warning).toContain("wintun.dll");
      expect(warning).toContain(String.raw`C:\App
esources
ative\windowsd`);
    });
  });
});

describe("Disconnecting a transport must not end the helpers", () => {
  // Disposal is permanent. Doing it on an ordinary disconnect made every later
  // connect report "the dataplane controller is disposed" and fall back to the
  // proxy path - where domain rules keep working and process rules do not, so
  // the tunnel looked healthy while Telegram and Discord went direct.
  it("keeps the Xray dataplane usable across disconnect and reconnect", async () => {
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const dataplane = fakeDataplane();
      const attributionController = attribution();
      let attributionDisposals = 0;
      const service = new XrayServiceBridge(initialStatus(), {
        runtimeDirectory: "/tmp/shadow-ssh-tun-routing-disconnect",
        systemProxy: systemProxy(applies),
        processConnectionsProvider: async () => [],
        processDnsEntriesProvider: async () => [],
        processAttribution: {
          ...attributionController,
          dispose: async () => {
            attributionDisposals += 1;
          }
        },
        dataplane,
        protectedAddressResolver: async () => ["203.0.113.9"]
      });
      const internals = service as unknown as XrayInternals;

      internals.status = { ...internals.status, state: "Connected" };
      const request = { ...xrayConnectRequest(), tunDataplaneEnabled: true };
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 52_000 });
      expect(dataplane.started).toHaveLength(1);

      await service.disconnect();
      expect(dataplane.disposals).toBe(0);
      expect(attributionDisposals).toBe(0);

      internals.status = { ...internals.status, state: "Connected" };
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 52_777 });

      expect(dataplane.started).toHaveLength(2);
      expect(dataplane.started[1].tunnelProxyEndpoint).toBe("127.0.0.1:52777");
      expect(applies).toHaveLength(0);

      // Quitting is the one moment that does end them.
      await service.dispose();
      expect(dataplane.disposals).toBe(1);
      expect(attributionDisposals).toBe(1);
    });
  });

  it("keeps the SSH dataplane usable across disconnect", async () => {
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

      await service.disconnect();
      expect(dataplane.disposals).toBe(0);

      internals.status = { ...internals.status, state: "Connected" };
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_888 }, true);
      expect(dataplane.started).toHaveLength(2);

      await service.dispose();
      expect(dataplane.disposals).toBe(1);
    });
  });
});

describe("Falling back from a running adapter", () => {
  // A routing update that cannot restart TUN used to apply the system proxy
  // or local enforcement on top of the adapter still running underneath,
  // with the old rules: two policies at once, and a stale adapter that the
  // status still called active.
  function createRecordingService(dataplane: FakeDataplane): { service: LiveSshServiceBridge; internals: SshInternals } {
    const proxy = {
      apply: vi.fn(async () => {
        dataplane.calls.push("proxy-apply");
        return { applied: true, message: "applied" };
      }),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const service = new LiveSshServiceBridge(initialStatus(), {
      systemProxy: proxy,
      processConnectionsProvider: async () => [],
      processDnsEntriesProvider: async () => [],
      processAttribution: attribution(),
      dataplane,
      protectedAddressResolver: async () => ["203.0.113.9"]
    });
    return { service, internals: service as unknown as SshInternals };
  }

  async function connectedWithTun(dataplane: FakeDataplane): Promise<{ service: LiveSshServiceBridge; internals: SshInternals; request: ConnectRequest }> {
    const { service, internals } = createRecordingService(dataplane);
    internals.status = { ...internals.status, state: "Connected" };
    const request = { ...sshConnectRequest(), tunDataplaneEnabled: true };
    internals.lastRequest = request;
    await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 }, true);
    expect(service.getStatus().tunActive).toBe(true);
    dataplane.calls.length = 0;
    return { service, internals, request };
  }

  it("takes the adapter down before the proxy path when a routing update cannot restart it", async () => {
    await withWin32(async () => {
      const dataplane = fakeDataplane();
      const { service, internals, request } = await connectedWithTun(dataplane);

      dataplane.startError = new Error("the new policy does not compile");
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 }, true);

      expect(dataplane.calls).toEqual(["start", "start", "stop", "proxy-apply"]);
      expect(dataplane.isActive).toBe(false);
      expect(service.getStatus().tunActive).toBe(false);
    });
  });

  it("takes the adapter down when the helper can no longer create one", async () => {
    await withWin32(async () => {
      const dataplane = fakeDataplane();
      const { service, internals, request } = await connectedWithTun(dataplane);

      dataplane.availability = { available: false, reason: "wintun.dll is missing" };
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 }, true);

      expect(dataplane.calls).toEqual(["stop", "proxy-apply"]);
      expect(service.getStatus().tunActive).toBe(false);
    });
  });

  it("keeps a held adapter, and has the reconnect rebuild it, when the session drops while a routing update's start fails", async () => {
    await withWin32(async () => {
      const dataplane = fakeDataplane();
      const { service, internals, request } = await connectedWithTun(dataplane);
      const state = internals as unknown as { suspendTunnel(): void; systemRoutingApplied: boolean; routingChangedWhileDown: boolean };
      state.systemRoutingApplied = true;
      dataplane.startError = new Error("the new policy does not compile");
      const start = dataplane.start;
      let first = true;
      dataplane.start = async (startRequest) => {
        if (first) {
          first = false;
          // What a dropped session does while the start is in flight.
          state.suspendTunnel();
          internals.status = { ...internals.status, state: "Reconnecting" };
        }
        return start(startRequest);
      };

      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 });

      // Selected flows keep waiting at the listener for the reconnect rather
      // than going out directly, and the reconnect builds the adapter anew
      // with the rules this update could not install.
      expect(dataplane.calls).toEqual(["start", "start"]);
      expect(dataplane.isActive).toBe(true);
      expect(state.routingChangedWhileDown).toBe(true);
      await service.dispose();
    });
  });

  it("still sends a stop for a start that failed before the proxy path goes on", async () => {
    // The start may have timed out here and still finished in the helper,
    // which would leave an adapter nobody tracks capturing traffic.
    await withWin32(async () => {
      const dataplane = fakeDataplane({ startError: new Error("Native helper start-dataplane request timed out.") });
      const { internals } = createRecordingService(dataplane);
      internals.status = { ...internals.status, state: "Connected" };
      const request = { ...sshConnectRequest(), tunDataplaneEnabled: true };
      internals.lastRequest = request;
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 51_234 }, true);

      expect(dataplane.calls).toEqual(["start", "start", "stop", "proxy-apply"]);
      // Nothing more is owed once that stop went through.
      await internals.stopRouting();
      expect(dataplane.stopped).toBe(1);
    });
  });
});

describe("Falling back from a running Xray adapter", () => {
  // The same gap on the Xray side, which also reaches it from a restart that
  // takes held routing over while the held adapter is still up.
  async function connectedXrayWithTun(
    dataplane: FakeDataplane,
    protectedAddresses: string[][] = []
  ): Promise<{ service: XrayServiceBridge; internals: XrayInternals; request: ProxyConnectRequest }> {
    const proxy = {
      apply: vi.fn(async () => {
        dataplane.calls.push("proxy-apply");
        return { applied: true, message: "applied" };
      }),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const service = new XrayServiceBridge(initialStatus(), {
      runtimeDirectory: "/tmp/shadow-ssh-xray-tun-fallback",
      systemProxy: proxy,
      processConnectionsProvider: async () => [],
      processDnsEntriesProvider: async () => [],
      processAttribution: attribution(),
      dataplane,
      protectedAddressResolver: async () => protectedAddresses.shift() ?? ["203.0.113.9"]
    });
    const internals = service as unknown as XrayInternals;
    internals.status = { ...internals.status, state: "Connected" };
    const request = { ...xrayConnectRequest(), tunDataplaneEnabled: true };
    internals.lastRequest = request;
    await internals.applySystemRouting(request, { host: "127.0.0.1", port: 52_000 });
    expect(service.getStatus().tunActive).toBe(true);
    dataplane.calls.length = 0;
    return { service, internals, request };
  }

  it("takes the adapter down before the proxy path when a routing update cannot restart it", async () => {
    await withWin32(async () => {
      const dataplane = fakeDataplane();
      const { service, internals, request } = await connectedXrayWithTun(dataplane);

      dataplane.startError = new Error("the new policy does not compile");
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 52_000 });

      expect(dataplane.calls).toEqual(["start", "start", "stop", "proxy-apply"]);
      expect(dataplane.isActive).toBe(false);
      expect(service.getStatus().tunActive).toBe(false);
      await service.dispose();
    });
  });

  it("keeps a running adapter on the addresses it was started with when a re-apply cannot resolve the server", async () => {
    await withWin32(async () => {
      const dataplane = fakeDataplane();
      // The first apply resolves the server; the next one - a rule edit, or a
      // restart under the hold - hits a resolver that fails for a moment.
      const { service, internals, request } = await connectedXrayWithTun(dataplane, [["203.0.113.9"], []]);

      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 52_000 });

      expect(dataplane.calls).toEqual(["start"]);
      expect(dataplane.started.at(-1)?.protectedAddresses).toEqual(["203.0.113.9"]);
      expect(service.getStatus().tunActive).toBe(true);
      await service.dispose();
    });
  });

  it("stays on the proxy path when the server does not resolve and no adapter is up", async () => {
    await withWin32(async () => {
      const dataplane = fakeDataplane();
      const { service, internals, request } = await connectedXrayWithTun(dataplane, [["203.0.113.9"], []]);
      // The adapter went down in between, so there is nothing to keep.
      await internals.stopRouting();
      dataplane.calls.length = 0;
      internals.status = { ...internals.status, state: "Connected" };

      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 52_000 });

      expect(dataplane.calls).toEqual(["proxy-apply"]);
      expect(service.getStatus().tunActive).toBe(false);
      await service.dispose();
    });
  });

  it("leaves a held adapter alone when Xray stops while a routing update tries it", async () => {
    // Xray dying mid-update holds routing as it is for the restart. The
    // overtaken attempt used to go on to the proxy path regardless, putting a
    // PAC that points at the dead Xray on top of the adapter still running.
    await withWin32(async () => {
      const dataplane = fakeDataplane();
      const { service, internals, request } = await connectedXrayWithTun(dataplane);
      const probe = dataplane.probe;
      dataplane.probe = async () => {
        internals.status = { ...internals.status, state: "Error" };
        internals.holdRouting();
        return probe();
      };
      // A domain rule, so no process-route learning step stands in the way.
      const update = {
        ...request,
        routingRules: [{ id: "d1", type: "domain" as const, value: "example.org", enabled: true, createdAt: "", updatedAt: "" }]
      };

      await internals.applySystemRouting(update, { host: "127.0.0.1", port: 52_000 });

      expect(dataplane.calls).toEqual([]);
      expect(dataplane.isActive).toBe(true);
      await service.dispose();
    });
  });

  it("leaves a held adapter alone when Xray stops while a routing update's start then fails", async () => {
    // The same overtaking, later: Xray exits while the start is in flight.
    // Taking the adapter down here left nothing capturing the traffic the
    // hold was keeping at Xray's ports, so selected traffic went direct.
    await withWin32(async () => {
      const dataplane = fakeDataplane();
      const { service, internals, request } = await connectedXrayWithTun(dataplane);
      dataplane.startError = new Error("the new policy does not compile");
      const start = dataplane.start;
      let first = true;
      dataplane.start = async (startRequest) => {
        if (first) {
          first = false;
          internals.status = { ...internals.status, state: "Error" };
          internals.holdRouting();
        }
        return start(startRequest);
      };
      const update = {
        ...request,
        routingRules: [{ id: "d1", type: "domain" as const, value: "example.org", enabled: true, createdAt: "", updatedAt: "" }]
      };

      await internals.applySystemRouting(update, { host: "127.0.0.1", port: 52_000 });

      expect(dataplane.calls).toEqual(["start", "start"]);
      expect(dataplane.isActive).toBe(true);
      await service.dispose();
    });
  });

  it("stops waiting for a routing update's TUN start the moment a disconnect begins", async () => {
    // Main queues the disconnect behind the update, so the bridge's own
    // disconnect would only run once both start attempts had timed out.
    await withWin32(async () => {
      const dataplane = fakeDataplane();
      const { service, internals, request } = await connectedXrayWithTun(dataplane);
      const signals: Array<AbortSignal | undefined> = [];
      dataplane.start = (_startRequest, signal) => {
        dataplane.calls.push("start");
        signals.push(signal);
        return new Promise<void>((_resolve, reject) => {
          signal?.addEventListener("abort", () => reject(new Error("Native helper start-dataplane request was abandoned.")), { once: true });
        });
      };
      const update = {
        ...request,
        routingRules: [{ id: "d1", type: "domain" as const, value: "example.org", enabled: true, createdAt: "", updatedAt: "" }]
      };

      const updating = internals.applySystemRouting(update, { host: "127.0.0.1", port: 52_000 });
      await vi.waitFor(() => expect(signals).toHaveLength(1));
      service.beginDisconnect();
      await updating;

      expect(signals[0]?.aborted).toBe(true);
      // No second attempt, and no proxy path on top of an adapter the
      // teardown is about to take down.
      expect(dataplane.calls).toEqual(["start"]);
      expect(service.getStatus().state).toBe("Disconnecting");
      await service.dispose();
    });
  });

  it("still sends a stop for a start that failed before the proxy path goes on", async () => {
    await withWin32(async () => {
      const dataplane = fakeDataplane();
      const { service, internals, request } = await connectedXrayWithTun(dataplane);
      await internals.stopRouting();
      expect(dataplane.stopped).toBe(1);
      dataplane.calls.length = 0;

      dataplane.startError = new Error("Native helper start-dataplane request timed out.");
      internals.status = { ...internals.status, state: "Connected" };
      await internals.applySystemRouting(request, { host: "127.0.0.1", port: 52_000 });

      expect(dataplane.calls).toEqual(["start", "start", "stop", "proxy-apply"]);
      await service.dispose();
      // Nothing more is owed once that stop went through.
      expect(dataplane.stopped).toBe(2);
    });
  });
});

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
