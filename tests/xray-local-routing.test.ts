import net from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { SystemProxyApplyRequest, WindowsSystemProxyManager } from "../src/core/network/windows-system-proxy.js";
import { XrayServiceBridge } from "../src/service/xray-service.js";
import type { ProcessAttribution } from "../src/service/process-attribution.js";
import type { ProxyConnectRequest, RoutingRule, RuntimeStatus } from "../src/shared/types.js";

// Each connection binds an explicit source port so it can be attributed, and a
// port cannot be rebound while its previous socket lingers in TIME_WAIT - so
// every case gets its own.
const TARGET_APP_PORTS = [41_001, 41_003, 41_005];
const OTHER_APP_PORTS = [41_002, 41_004, 41_006];
const VIA_TUNNEL = "VIA-TUNNEL";
const DIRECT_EXIT = "DIRECT-EXIT";

/** Stands in for Xray's SOCKS inbound and records what it was asked to reach. */
let upstream: net.Server;
let upstreamPort = 0;
let upstreamTargets: string[] = [];
let directServer: net.Server;
let directPort = 0;

beforeAll(async () => {
  upstream = net.createServer((socket) => {
    // A client that hangs up mid-transfer must not raise an unhandled error.
    socket.on("error", () => undefined);
    let buffer = Buffer.alloc(0);
    let stage: "greeting" | "connect" | "data" = "greeting";
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (stage === "greeting") {
        if (buffer.length < 2 || buffer.length < 2 + buffer[1]) {
          return;
        }
        buffer = buffer.subarray(2 + buffer[1]);
        socket.write(Buffer.from([0x05, 0x00]));
        stage = "connect";
      }
      if (stage === "connect") {
        const parsed = parseSocks5Connect(buffer);
        if (!parsed) {
          return;
        }
        buffer = buffer.subarray(parsed.length);
        upstreamTargets.push(`${parsed.host}:${parsed.port}`);
        socket.write(Buffer.concat([
          Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
          Buffer.from(VIA_TUNNEL)
        ]));
        stage = "data";
      }
    });
  });
  await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  upstreamPort = addressPort(upstream);

  directServer = net.createServer((socket) => {
    socket.on("error", () => undefined);
    socket.end(DIRECT_EXIT);
  });
  await new Promise<void>((resolve) => directServer.listen(0, "127.0.0.1", resolve));
  directPort = addressPort(directServer);
});

afterAll(async () => {
  await new Promise<void>((resolve) => upstream.close(() => resolve()));
  await new Promise<void>((resolve) => directServer.close(() => resolve()));
});

afterEach(() => {
  upstreamTargets = [];
  vi.restoreAllMocks();
});

interface XrayInternals {
  status: RuntimeStatus;
  lastRequest: ProxyConnectRequest | undefined;
  applySystemRouting(request: ProxyConnectRequest, socksEndpoint: { host: string; port: number }): Promise<void>;
}

describe("Xray transport with local per-process routing", () => {
  // Xray's system proxy used to point straight at its own inbound, so no
  // component ever saw which process opened a connection and process rules
  // could not be honoured at all on this transport.
  it("puts its own listener in front of Xray and routes only matching traffic into it", async () => {
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const service = createService(applies);
      const internals = service as unknown as XrayInternals;

      try {
        internals.status = { ...internals.status, state: "Connected" };
        internals.lastRequest = connectRequest();
        await internals.applySystemRouting(internals.lastRequest, { host: "127.0.0.1", port: upstreamPort });

        const applied = applies.at(-1);
        expect(applied?.mode).toBe("proxy-all");
        // The system proxy must reach us, not Xray, or attribution never runs.
        expect(applied?.socksPort).not.toBe(upstreamPort);
        const listener = { host: applied!.socksHost, port: applied!.socksPort };

        // A domain rule applies whichever process opened the connection.
        await expect(connectThrough(listener, "www.youtube.com", 443, OTHER_APP_PORTS[0])).resolves.toContain(VIA_TUNNEL);
        expect(upstreamTargets).toContain("www.youtube.com:443");

        // A process rule covers a host that no rule names and no DNS cache
        // could have revealed - previously impossible on this transport.
        await expect(connectThrough(listener, "cdn.telegram-cdn.test", 443, TARGET_APP_PORTS[0])).resolves.toContain(VIA_TUNNEL);
        expect(upstreamTargets).toContain("cdn.telegram-cdn.test:443");

        // A process rule means "everything this application sends", so even a
        // host on the curated direct list must still be tunnelled.
        await expect(connectThrough(listener, "lk.gosuslugi.ru", 443, TARGET_APP_PORTS[1])).resolves.toContain(VIA_TUNNEL);
        expect(upstreamTargets).toContain("lk.gosuslugi.ru:443");

        const tunnelledBefore = upstreamTargets.length;
        await expect(connectThrough(listener, "127.0.0.1", directPort, OTHER_APP_PORTS[1])).resolves.toContain(DIRECT_EXIT);
        expect(upstreamTargets).toHaveLength(tunnelledBefore);
      } finally {
        await service.dispose();
      }
    });
  });

  it("keeps pointing the system proxy at Xray when attribution is unavailable", async () => {
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const service = createService(applies, { attributionAvailable: false });
      const internals = service as unknown as XrayInternals;

      try {
        internals.status = { ...internals.status, state: "Connected" };
        internals.lastRequest = connectRequest();
        await internals.applySystemRouting(internals.lastRequest, { host: "127.0.0.1", port: upstreamPort });

        expect(applies.at(-1)?.mode).toBe("selected-rules");
      } finally {
        await service.dispose();
      }
    });
  });
});

function createService(
  applies: SystemProxyApplyRequest[],
  { attributionAvailable = true }: { attributionAvailable?: boolean } = {}
): XrayServiceBridge {
  const attribution: ProcessAttribution = {
    isAvailable: async () => attributionAvailable,
    resolveProcessName: async (localPort) => (TARGET_APP_PORTS.includes(localPort) ? "telegram.exe" : "chrome.exe"),
    dispose: async () => undefined
  };
  return new XrayServiceBridge(initialStatus(), {
    runtimeDirectory: "/tmp/shadow-ssh-xray-local-routing",
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
}

/** Drives a real SOCKS5 client through our listener and returns the payload. */
function connectThrough(
  listener: { host: string; port: number },
  host: string,
  port: number,
  sourcePort: number
): Promise<string> {
  return new Promise((resolve, reject) => {
    const client = net.connect({
      host: listener.host,
      port: listener.port,
      localAddress: "127.0.0.1",
      localPort: sourcePort
    });
    let stage: "greeting" | "connect" | "data" = "greeting";
    let payload = "";
    const finish = (): void => {
      clearTimeout(timer);
      client.destroy();
      resolve(payload);
    };
    const timer = setTimeout(finish, 2_000);
    client.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    client.on("connect", () => client.write(Buffer.from([0x05, 0x01, 0x00])));
    client.on("data", (chunk: Buffer) => {
      if (stage === "greeting") {
        stage = "connect";
        const encodedHost = Buffer.from(host, "utf8");
        const encodedPort = Buffer.alloc(2);
        encodedPort.writeUInt16BE(port);
        client.write(Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, encodedHost.length]),
          encodedHost,
          encodedPort
        ]));
        return;
      }
      if (stage === "connect") {
        stage = "data";
        if (chunk.length > 10) {
          payload += chunk.subarray(10).toString();
        }
        return;
      }
      payload += chunk.toString();
    });
    client.on("close", finish);
  });
}

function parseSocks5Connect(buffer: Buffer): { host: string; port: number; length: number } | undefined {
  if (buffer.length < 5) {
    return undefined;
  }
  const addressType = buffer[3];
  if (addressType === 0x03) {
    const length = 5 + buffer[4] + 2;
    if (buffer.length < length) {
      return undefined;
    }
    return { host: buffer.subarray(5, 5 + buffer[4]).toString(), port: buffer.readUInt16BE(length - 2), length };
  }
  if (addressType === 0x01) {
    const length = 4 + 4 + 2;
    if (buffer.length < length) {
      return undefined;
    }
    return {
      host: Array.from(buffer.subarray(4, 8)).join("."),
      port: buffer.readUInt16BE(length - 2),
      length
    };
  }
  return undefined;
}

function addressPort(server: net.Server): number {
  const address = server.address();
  return typeof address === "object" && address ? address.port : 0;
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

function routingRules(): RoutingRule[] {
  return [
    { id: "d1", type: "domain", value: "youtube.com", enabled: true, createdAt: "", updatedAt: "" },
    { id: "p1", type: "process.name", value: "telegram.exe", enabled: true, createdAt: "", updatedAt: "" }
  ];
}

function connectRequest(): ProxyConnectRequest {
  return {
    profile: {
      id: "profile",
      name: "profile",
      protocol: "vless",
      host: "example.com",
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
    routingDirectDomains: ["gosuslugi.ru"],
    checkEndpoint: "example.com:443",
    secrets: {} as ProxyConnectRequest["secrets"]
  };
}

function initialStatus(): RuntimeStatus {
  return {
    state: "Disconnected",
    message: "",
    reconnectAttempt: 0,
    transport: "xray",
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
