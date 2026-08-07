import { afterEach, describe, expect, it, vi } from "vitest";
import type { WindowsSystemProxyManager } from "../src/core/network/windows-system-proxy.js";
import { LiveSshServiceBridge } from "../src/service/live-ssh-service.js";
import { XrayServiceBridge } from "../src/service/xray-service.js";
import type { ConnectRequest, RoutingRule, RuntimeStatus } from "../src/shared/types.js";

const PROCESS_NAME = "example-app.exe";
const ADDRESS = "203.0.113.10";
const DOMAIN = "media.example-app.test";
const PROCESS_ROUTE_TTL_MS = 5 * 60 * 1000;
// Longer than the DNS record TTL below, shorter than the process-route TTL.
const ELAPSED_MS = 60 * 1000;
const DNS_RECORD_TTL_SECONDS = 30;

interface ProcessRoutingState {
  processRoutingIps: Map<string, number>;
  processRoutingDomains: Map<string, number>;
}

interface LiveSshInternals extends ProcessRoutingState {
  learnProcessRoutingIps(request: ConnectRequest): Promise<boolean>;
}

interface XrayInternals extends ProcessRoutingState {
  learnProcessRoutingIps(rules: RoutingRule[], directDomains?: string[]): Promise<boolean>;
}

describe("process-name route retention", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // A destination can only be observed while the application still reaches it
  // directly. Once it is routed, the application connects to the loopback proxy
  // instead, Get-NetTCPConnection stops reporting the real remote address and
  // nothing refreshes the Windows DNS cache entry. Tying the PAC route to the
  // DNS record TTL therefore dropped hosts back to DIRECT while they were still
  // in use, so process-name routing only covered part of an application's
  // traffic.
  it("keeps a learned live SSH route after the DNS record TTL elapses and the app is fully proxied", async () => {
    await withWin32(async () => {
      const service = new LiveSshServiceBridge(initialStatus("live-ssh"), {
        systemProxy: stubSystemProxy(),
        processConnectionsProvider: onlyFirstCycleConnections(),
        processDnsEntriesProvider: async () => [
          { address: ADDRESS, domain: DOMAIN, ttlSeconds: DNS_RECORD_TTL_SECONDS }
        ]
      });
      const internals = service as unknown as LiveSshInternals;

      try {
        await internals.learnProcessRoutingIps(liveSshRequest());

        expect([...internals.processRoutingDomains.keys()]).toEqual([DOMAIN]);
        expect(remainingLifetimeMs(internals, DOMAIN)).toBeGreaterThan(DNS_RECORD_TTL_SECONDS * 1000);

        rewind(internals, ELAPSED_MS);
        await internals.learnProcessRoutingIps(liveSshRequest());

        expect([...internals.processRoutingDomains.keys()]).toEqual([DOMAIN]);
        expect([...internals.processRoutingIps.keys()]).toEqual([ADDRESS]);
        // The renewal must restore a full process-route TTL, not merely survive
        // one cycle, otherwise the route still decays a minute later.
        expect(remainingLifetimeMs(internals, DOMAIN)).toBeGreaterThan(PROCESS_ROUTE_TTL_MS - ELAPSED_MS);
      } finally {
        await service.dispose();
      }
    });
  });

  it("keeps a learned Xray route after the DNS record TTL elapses and the app is fully proxied", async () => {
    await withWin32(async () => {
      const service = new XrayServiceBridge(initialStatus("xray"), {
        runtimeDirectory: "/tmp/shadow-ssh-process-route-retention",
        systemProxy: stubSystemProxy(),
        processConnectionsProvider: onlyFirstCycleConnections(),
        processDnsEntriesProvider: async () => [
          { address: ADDRESS, domain: DOMAIN, ttlSeconds: DNS_RECORD_TTL_SECONDS }
        ]
      });
      const internals = service as unknown as XrayInternals;

      try {
        await internals.learnProcessRoutingIps([processRule()]);

        expect([...internals.processRoutingDomains.keys()]).toEqual([DOMAIN]);

        rewind(internals, ELAPSED_MS);
        await internals.learnProcessRoutingIps([processRule()]);

        expect([...internals.processRoutingDomains.keys()]).toEqual([DOMAIN]);
        expect([...internals.processRoutingIps.keys()]).toEqual([ADDRESS]);
      } finally {
        await service.dispose();
      }
    });
  });

  it("still drops a learned route once discovery has been failing for a full TTL", async () => {
    await withWin32(async () => {
      let cycle = 0;
      const service = new LiveSshServiceBridge(initialStatus("live-ssh"), {
        systemProxy: stubSystemProxy(),
        processConnectionsProvider: async () => {
          cycle += 1;
          if (cycle === 1) {
            return [{ processName: PROCESS_NAME, remoteAddress: ADDRESS, remotePort: 443, state: "Established" }];
          }
          // A broken discovery cycle must not renew stale routes.
          throw new Error("PowerShell snapshot failed.");
        },
        processDnsEntriesProvider: async () => [
          { address: ADDRESS, domain: DOMAIN, ttlSeconds: DNS_RECORD_TTL_SECONDS }
        ]
      });
      const internals = service as unknown as LiveSshInternals;

      try {
        await internals.learnProcessRoutingIps(liveSshRequest());
        expect([...internals.processRoutingDomains.keys()]).toEqual([DOMAIN]);

        rewind(internals, PROCESS_ROUTE_TTL_MS + 1_000);
        await internals.learnProcessRoutingIps(liveSshRequest());

        expect([...internals.processRoutingDomains.keys()]).toEqual([]);
        expect([...internals.processRoutingIps.keys()]).toEqual([]);
      } finally {
        await service.dispose();
      }
    });
  });
});

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

function onlyFirstCycleConnections(): () => Promise<
  Array<{ processName: string; remoteAddress: string; remotePort: number; state: string }>
> {
  let cycle = 0;
  return async () => {
    cycle += 1;
    // First cycle: the application still reaches the destination directly.
    // Later cycles: everything already flows through the loopback proxy, so
    // Windows no longer reports a routable remote address for this process.
    return cycle === 1
      ? [{ processName: PROCESS_NAME, remoteAddress: ADDRESS, remotePort: 443, state: "Established" }]
      : [];
  };
}

function stubSystemProxy(): WindowsSystemProxyManager {
  return {
    apply: vi.fn(async () => ({ applied: true, message: "applied" })),
    restore: vi.fn(async () => undefined)
  } as unknown as WindowsSystemProxyManager;
}

function initialStatus(transport: RuntimeStatus["transport"]): RuntimeStatus {
  return {
    state: "Disconnected",
    message: "",
    reconnectAttempt: 0,
    transport,
    platformTarget: {
      platform: "windows",
      arch: "x64",
      serviceExecutableName: "",
      serviceRelativePath: "",
      supportsPrivilegedService: false
    },
    realTunnelAvailable: false
  };
}

function processRule(): RoutingRule {
  return {
    id: "process-rule",
    type: "process.name",
    value: PROCESS_NAME,
    enabled: true,
    createdAt: "",
    updatedAt: ""
  };
}

function liveSshRequest(): ConnectRequest {
  return {
    config: {
      id: "retention",
      name: "retention",
      host: "retention.example.com",
      port: 22,
      username: "user",
      authType: "password",
      expectedServerFingerprint: "SHA256:test",
      keepaliveIntervalSec: 30,
      note: "",
      createdAt: "",
      updatedAt: ""
    },
    routingMode: "selected-rules",
    routingRules: [processRule()],
    routingProxyDomains: [],
    routingDirectDomains: [],
    checkEndpoint: "example.com:443",
    secrets: { password: "secret" }
  };
}

function remainingLifetimeMs(internals: ProcessRoutingState, domain: string): number {
  return (internals.processRoutingDomains.get(domain) ?? 0) - Date.now();
}

/** Simulates elapsed wall-clock time without waiting for it. */
function rewind(internals: ProcessRoutingState, elapsedMs: number): void {
  for (const [domain, expiresAt] of internals.processRoutingDomains) {
    internals.processRoutingDomains.set(domain, expiresAt - elapsedMs);
  }
  for (const [address, observedAt] of internals.processRoutingIps) {
    internals.processRoutingIps.set(address, observedAt - elapsedMs);
  }
}
