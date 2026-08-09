import net from "node:net";
import { afterEach, beforeAll, afterAll, describe, expect, it, vi } from "vitest";
import type { WindowsSystemProxyManager, SystemProxyApplyRequest } from "../src/core/network/windows-system-proxy.js";
import type { DirectTcpIpChannel, DirectTcpIpTarget } from "../src/core/network/local-tcp-proxy.js";
import type { SshLiveClient } from "../src/core/ssh/live-client.js";
import { LiveSshServiceBridge } from "../src/service/live-ssh-service.js";
import type { ProcessAttribution } from "../src/service/process-attribution.js";
import type { ConnectRequest, RoutingRule, RuntimeStatus } from "../src/shared/types.js";

const TARGET_APP = "telegram.exe";
const OTHER_APP = "chrome.exe";
const TARGET_APP_PORT = 41_001;
const OTHER_APP_PORT = 41_002;

let echoServer: net.Server;
let echoPort = 0;

beforeAll(async () => {
  echoServer = net.createServer((socket) => {
    // A client that hangs up mid-transfer must not raise an unhandled error.
    socket.on("error", () => undefined);
    socket.end("ok");
  });
  await new Promise<void>((resolve) => echoServer.listen(0, "127.0.0.1", resolve));
  const address = echoServer.address();
  echoPort = typeof address === "object" && address ? address.port : 0;
});

afterAll(async () => {
  await new Promise<void>((resolve) => echoServer.close(() => resolve()));
});

interface ServiceInternals {
  localProcessEnforcement: boolean;
  lastRequest: ConnectRequest | undefined;
  status: RuntimeStatus;
  applySystemRouting(
    request: ConnectRequest,
    socksEndpoint: { host: string; port: number },
    allowConnecting?: boolean
  ): Promise<void>;
  openProxyChannel(
    client: SshLiveClient,
    target: DirectTcpIpTarget,
    originator: { address: string; port: number },
    signal?: AbortSignal
  ): Promise<DirectTcpIpChannel>;
}

describe("locally enforced per-process routing", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // Windows PAC has no process identity, so process rules can only be enforced
  // where the owning process is known: on the local proxy. Domain, IP and
  // process rules must all be evaluated there, together, for every connection.
  it("evaluates domain, IP and process rules together and keeps unmatched traffic out of the tunnel", async () => {
    await withWin32(async () => {
      const harness = createHarness({ attributionAvailable: true });
      const internals = harness.service as unknown as ServiceInternals;

      try {
        internals.status = { ...internals.status, state: "Connecting" };
        internals.lastRequest = connectRequest(mixedRules());
        await internals.applySystemRouting(internals.lastRequest, { host: "127.0.0.1", port: 31_080 }, true);

        // All proxy-aware TCP has to reach the local listener, otherwise a
        // connection from a selected process would never be seen at all.
        expect(harness.applies.at(-1)?.mode).toBe("proxy-all");
        expect(internals.localProcessEnforcement).toBe(true);

        const open = (host: string, port: number, sourcePort: number): Promise<DirectTcpIpChannel> =>
          internals.openProxyChannel(harness.client, { host, port }, { address: "127.0.0.1", port: sourcePort });

        // A domain rule applies to every process, including unselected ones.
        await open("www.youtube.com", 443, OTHER_APP_PORT);
        expect(harness.tunnelled).toContain("www.youtube.com:443");

        // A process rule applies to a host no rule mentions and no DNS cache
        // could have revealed - the case the PAC fallback could never cover.
        await open("cdn.telegram-cdn.test", 443, TARGET_APP_PORT);
        expect(harness.tunnelled).toContain("cdn.telegram-cdn.test:443");

        await open("203.0.113.77", 443, OTHER_APP_PORT);
        expect(harness.tunnelled).toContain("203.0.113.77:443");

        const tunnelledBefore = harness.tunnelled.length;
        const direct = await open("127.0.0.1", echoPort, OTHER_APP_PORT);
        expect(harness.tunnelled).toHaveLength(tunnelledBefore);
        await direct.close();
      } finally {
        await harness.service.dispose();
      }
    });
  });

  it("never sends the SSH control connection back through its own tunnel", async () => {
    await withWin32(async () => {
      const harness = createHarness({ attributionAvailable: true });
      const internals = harness.service as unknown as ServiceInternals;

      try {
        internals.status = { ...internals.status, state: "Connecting" };
        internals.lastRequest = connectRequest(mixedRules());
        await internals.applySystemRouting(internals.lastRequest, { host: "127.0.0.1", port: 31_080 }, true);

        // Even though this arrives from a selected process, tunnelling the SSH
        // endpoint through itself would deadlock the transport.
        await internals
          .openProxyChannel(
            harness.client,
            { host: internals.lastRequest.config.host, port: internals.lastRequest.config.port },
            { address: "127.0.0.1", port: TARGET_APP_PORT }
          )
          .then((channel) => channel.close())
          .catch(() => undefined);
        expect(harness.tunnelled).toHaveLength(0);
      } finally {
        await harness.service.dispose();
      }
    });
  });

  it("keeps the curated proxy list working alongside process rules", async () => {
    await withWin32(async () => {
      const harness = createHarness({ attributionAvailable: true });
      const internals = harness.service as unknown as ServiceInternals;

      try {
        internals.status = { ...internals.status, state: "Connecting" };
        internals.lastRequest = {
          ...connectRequest([processRule()]),
          // Curated lists ship plain domains next to bare TLD suffixes, which
          // are not expressible as routing rules and so need their own match.
          routingProxyDomains: ["rutracker.org", ".onion"]
        };
        await internals.applySystemRouting(internals.lastRequest, { host: "127.0.0.1", port: 31_080 }, true);

        const open = (host: string): Promise<DirectTcpIpChannel> =>
          internals.openProxyChannel(harness.client, { host, port: 443 }, { address: "127.0.0.1", port: OTHER_APP_PORT });

        await open("rutracker.org");
        await open("static.rutracker.org");
        await open("somesite.onion");
        expect(harness.tunnelled).toEqual(["rutracker.org:443", "static.rutracker.org:443", "somesite.onion:443"]);

        const tunnelledBefore = harness.tunnelled.length;
        const direct = await internals.openProxyChannel(
          harness.client,
          { host: "127.0.0.1", port: echoPort },
          { address: "127.0.0.1", port: OTHER_APP_PORT }
        );
        expect(harness.tunnelled).toHaveLength(tunnelledBefore);
        await direct.close();
      } finally {
        await harness.service.dispose();
      }
    });
  });

  it("falls back to selected-rules PAC when native attribution is unavailable", async () => {
    await withWin32(async () => {
      const harness = createHarness({ attributionAvailable: false });
      const internals = harness.service as unknown as ServiceInternals;

      try {
        internals.status = { ...internals.status, state: "Connecting" };
        internals.lastRequest = connectRequest(mixedRules());
        await internals.applySystemRouting(internals.lastRequest, { host: "127.0.0.1", port: 31_080 }, true);

        // Without attribution the proxy could not tell processes apart, so
        // routing everything to it would silently disable the tunnel.
        expect(harness.applies.at(-1)?.mode).toBe("selected-rules");
        expect(internals.localProcessEnforcement).toBe(false);
      } finally {
        await harness.service.dispose();
      }
    });
  });

  it("tunnels every accepted connection when no process rule is configured", async () => {
    await withWin32(async () => {
      const harness = createHarness({ attributionAvailable: true });
      const internals = harness.service as unknown as ServiceInternals;

      try {
        internals.status = { ...internals.status, state: "Connecting" };
        internals.lastRequest = connectRequest([domainRule()]);
        await internals.applySystemRouting(internals.lastRequest, { host: "127.0.0.1", port: 31_080 }, true);

        expect(internals.localProcessEnforcement).toBe(false);
        expect(harness.applies.at(-1)?.mode).toBe("selected-rules");

        // The PAC already selected this traffic, so the proxy must not
        // second-guess it and must keep tunnelling unconditionally.
        await internals.openProxyChannel(
          harness.client,
          { host: "anything.example", port: 443 },
          { address: "127.0.0.1", port: OTHER_APP_PORT }
        );
        expect(harness.tunnelled).toContain("anything.example:443");
      } finally {
        await harness.service.dispose();
      }
    });
  });
});

function createHarness({ attributionAvailable }: { attributionAvailable: boolean }): {
  service: LiveSshServiceBridge;
  client: SshLiveClient;
  applies: SystemProxyApplyRequest[];
  tunnelled: string[];
} {
  const applies: SystemProxyApplyRequest[] = [];
  const tunnelled: string[] = [];
  const portOwners = new Map([
    [TARGET_APP_PORT, TARGET_APP],
    [OTHER_APP_PORT, OTHER_APP]
  ]);
  const attribution: ProcessAttribution = {
    isAvailable: async () => attributionAvailable,
    resolveProcessName: async (localPort) => portOwners.get(localPort),
    dispose: async () => undefined
  };

  const service = new LiveSshServiceBridge(initialStatus(), {
    systemProxy: {
      apply: vi.fn(async (request: SystemProxyApplyRequest) => {
        applies.push(request);
        return { applied: true, message: "applied" };
      }),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager,
    processConnectionsProvider: async () => [],
    processDnsEntriesProvider: async () => [],
    processAttribution: attribution
  });

  const client = {
    openDirectTcpIpChannel: async (target: DirectTcpIpTarget) => {
      tunnelled.push(`${target.host}:${target.port}`);
      return stubChannel();
    }
  } as unknown as SshLiveClient;

  return { service, client, applies, tunnelled };
}

function stubChannel(): DirectTcpIpChannel {
  return {
    write: async () => undefined,
    close: async () => undefined,
    end: async () => undefined,
    onData: () => () => undefined,
    onEnd: () => () => undefined,
    onClose: () => () => undefined,
    onError: () => () => undefined
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

function domainRule(): RoutingRule {
  return { id: "d1", type: "domain", value: "youtube.com", enabled: true, createdAt: "", updatedAt: "" };
}

function processRule(): RoutingRule {
  return { id: "p1", type: "process.name", value: TARGET_APP, enabled: true, createdAt: "", updatedAt: "" };
}

function mixedRules(): RoutingRule[] {
  return [
    domainRule(),
    { id: "d2", type: "domain", value: "*.youtube.com", enabled: true, createdAt: "", updatedAt: "" },
    { id: "i1", type: "ip", value: "203.0.113.0/24", enabled: true, createdAt: "", updatedAt: "" },
    processRule()
  ];
}

function connectRequest(routingRules: RoutingRule[]): ConnectRequest {
  return {
    config: {
      id: "local-enforcement",
      name: "local-enforcement",
      host: "srv.example.com",
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
    routingRules,
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
      platform: "windows",
      arch: "x64",
      serviceExecutableName: "",
      serviceRelativePath: "",
      supportsPrivilegedService: false
    },
    realTunnelAvailable: false
  };
}
