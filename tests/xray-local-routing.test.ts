import net from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { SystemProxyApplyRequest, WindowsSystemProxyManager } from "../src/core/network/windows-system-proxy.js";
import { XrayServiceBridge } from "../src/service/xray-service.js";
import type { DataplaneStartRequest } from "../src/service/local-ipc-protocol.js";
import type { DataplaneController } from "../src/service/native-dataplane.js";
import type { ProcessAttribution } from "../src/service/process-attribution.js";
import type { ProxyConnectRequest, RoutingRule, RuntimeStatus } from "../src/shared/types.js";

// Each connection binds an explicit source port so it can be attributed, and a
// port cannot be rebound while its previous socket lingers in TIME_WAIT - so
// every case gets its own.
const TARGET_APP_PORTS = [41_001, 41_003, 41_005];
const OTHER_APP_PORTS = [41_002, 41_004, 41_006, 41_008, 41_010, 41_012];
const VIA_TUNNEL = "VIA-TUNNEL";
const DIRECT_EXIT = "DIRECT-EXIT";

/** Stands in for Xray's SOCKS inbound and records what it was asked to reach. */
let upstream: net.Server;
let upstreamPort = 0;
let upstreamTargets: string[] = [];
/** A second Xray inbound, as a restart on other ports would bring up. */
let restartedUpstream: net.Server;
let restartedUpstreamPort = 0;
let restartedUpstreamTargets: string[] = [];
let directServer: net.Server;
let directPort = 0;
/** A destination that keeps its connections open and echoes what it gets. */
let echoServer: net.Server;
let echoPort = 0;

beforeAll(async () => {
  upstream = createSocksUpstream((target) => upstreamTargets.push(target));
  await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  upstreamPort = addressPort(upstream);
  restartedUpstream = createSocksUpstream((target) => restartedUpstreamTargets.push(target));
  await new Promise<void>((resolve) => restartedUpstream.listen(0, "127.0.0.1", resolve));
  restartedUpstreamPort = addressPort(restartedUpstream);

  directServer = net.createServer((socket) => {
    socket.on("error", () => undefined);
    socket.end(DIRECT_EXIT);
  });
  await new Promise<void>((resolve) => directServer.listen(0, "127.0.0.1", resolve));
  directPort = addressPort(directServer);

  echoServer = net.createServer((socket) => {
    socket.on("error", () => undefined);
    socket.pipe(socket);
  });
  await new Promise<void>((resolve) => echoServer.listen(0, "127.0.0.1", resolve));
  echoPort = addressPort(echoServer);
});

afterAll(async () => {
  await new Promise<void>((resolve) => upstream.close(() => resolve()));
  await new Promise<void>((resolve) => restartedUpstream.close(() => resolve()));
  await new Promise<void>((resolve) => directServer.close(() => resolve()));
  echoServer.close();
});

afterEach(() => {
  upstreamTargets = [];
  restartedUpstreamTargets = [];
  vi.restoreAllMocks();
});

function createSocksUpstream(record: (target: string) => void): net.Server {
  return net.createServer((socket) => {
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
        record(`${parsed.host}:${parsed.port}`);
        // Close after answering, the way the direct stand-in does. The client
        // helper below resolves on `close`, falling back to a 2s guard timer;
        // a stand-in that answered and then held the socket open made every
        // tunnelled case wait out that full guard, and three of them together
        // overran the default test timeout.
        socket.end(Buffer.concat([
          Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
          Buffer.from(VIA_TUNNEL)
        ]));
        stage = "data";
      }
    });
  });
}

interface XrayInternals {
  status: RuntimeStatus;
  lastRequest: ProxyConnectRequest | undefined;
  process: { pid?: number } | undefined;
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

  // Every rule toggle used to stop and rebuild the listener, and stopping it
  // destroys every socket it carries - direct ones included.
  it("swaps the rules and Xray's inbound in place, keeping the listener and its open connections", async () => {
    await withWin32(async () => {
      const applies: SystemProxyApplyRequest[] = [];
      const service = createService(applies);
      const internals = service as unknown as XrayInternals;
      let open: net.Socket | undefined;

      try {
        internals.status = { ...internals.status, state: "Connected" };
        const request = connectRequest();
        internals.lastRequest = request;
        await internals.applySystemRouting(request, { host: "127.0.0.1", port: upstreamPort });
        const listener = { host: applies.at(-1)!.socksHost, port: applies.at(-1)!.socksPort };
        open = await openThrough(listener, "127.0.0.1", echoPort, OTHER_APP_PORTS[2]);

        // A routing edit: one more domain rule.
        const edited: ProxyConnectRequest = {
          ...request,
          routingRules: [
            ...request.routingRules,
            { id: "d2", type: "domain", value: "swap.test", enabled: true, createdAt: "", updatedAt: "" }
          ]
        };
        internals.lastRequest = edited;
        await internals.applySystemRouting(edited, { host: "127.0.0.1", port: upstreamPort });

        expect(applies.at(-1)?.socksPort).toBe(listener.port);
        await expect(echo(open, "still-open")).resolves.toBe("still-open");
        // The new rule decides the very next connection.
        await expect(connectThrough(listener, "swap.test", 443, OTHER_APP_PORTS[3])).resolves.toContain(VIA_TUNNEL);
        expect(upstreamTargets).toContain("swap.test:443");

        // Xray restarted on another port: the same listener forwards there now.
        await internals.applySystemRouting(edited, { host: "127.0.0.1", port: restartedUpstreamPort });

        expect(applies.at(-1)?.socksPort).toBe(listener.port);
        await expect(echo(open, "after-restart")).resolves.toBe("after-restart");
        await expect(connectThrough(listener, "www.youtube.com", 443, OTHER_APP_PORTS[4])).resolves.toContain(VIA_TUNNEL);
        expect(restartedUpstreamTargets).toEqual(["www.youtube.com:443"]);
      } finally {
        open?.destroy();
        await service.dispose();
      }
    });
  });

  it("tells the adapter to let Xray's own process out directly", async () => {
    await withWin32(async () => {
      const started: DataplaneStartRequest[] = [];
      const dataplane = {
        isActive: false,
        probe: async () => ({ available: true }),
        start: async (request: DataplaneStartRequest) => {
          started.push(request);
        },
        stop: async () => undefined,
        dispose: async () => undefined
      } as unknown as DataplaneController;
      const service = createService([], {
        dataplane,
        executablePath: "C:\\Users\\me\\AppData\\Local\\Temp\\Shadow\\resources\\xray\\windows\\x64\\xray.exe"
      });
      const internals = service as unknown as XrayInternals;

      try {
        internals.status = { ...internals.status, state: "Connected" };
        const request: ProxyConnectRequest = { ...connectRequest(), tunDataplaneEnabled: true };
        internals.lastRequest = request;
        // Only Shadow's own Xray child goes direct: it is named by its process
        // ID, so another program called xray.exe is routed like any other.
        internals.process = { pid: 4242 };
        await internals.applySystemRouting(request, { host: "127.0.0.1", port: upstreamPort });

        expect(started).toHaveLength(1);
        expect(started[0].directProcesses).toEqual([{ pid: 4242, name: "xray.exe" }]);

        // A restarted child has another ID, and the next apply sends it.
        internals.process = { pid: 5150 };
        await internals.applySystemRouting(request, { host: "127.0.0.1", port: upstreamPort });
        expect(started.at(-1)?.directProcesses).toEqual([{ pid: 5150, name: "xray.exe" }]);
      } finally {
        internals.process = undefined;
        await service.dispose();
      }
    });
  });
});

/** Opens a SOCKS5 CONNECT through our listener and hands back the live socket once it is established. */
function openThrough(
  listener: { host: string; port: number },
  host: string,
  port: number,
  sourcePort: number
): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const client = net.connect({ host: listener.host, port: listener.port, localAddress: "127.0.0.1", localPort: sourcePort });
    let stage: "greeting" | "connect" = "greeting";
    client.on("error", reject);
    client.on("connect", () => client.write(Buffer.from([0x05, 0x01, 0x00])));
    const onData = (chunk: Buffer): void => {
      if (stage === "greeting") {
        stage = "connect";
        const encodedHost = Buffer.from(host, "utf8");
        const encodedPort = Buffer.alloc(2);
        encodedPort.writeUInt16BE(port);
        client.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, encodedHost.length]), encodedHost, encodedPort]));
        return;
      }
      if (chunk[1] !== 0x00) {
        reject(new Error(`SOCKS5 CONNECT failed with reply ${chunk[1]}.`));
        return;
      }
      client.off("data", onData);
      client.off("error", reject);
      client.on("error", () => undefined);
      resolve(client);
    };
    client.on("data", onData);
  });
}

/** Writes `text` and resolves with what comes back, failing if the socket closes first. */
function echo(socket: net.Socket, text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (socket.destroyed) {
      reject(new Error("socket was destroyed"));
      return;
    }
    let received = "";
    const onData = (chunk: Buffer): void => {
      received += chunk.toString();
      if (received.length >= text.length) {
        cleanup();
        resolve(received);
      }
    };
    const onClose = (): void => {
      cleanup();
      reject(new Error("socket closed"));
    };
    const cleanup = (): void => {
      socket.off("data", onData);
      socket.off("close", onClose);
    };
    socket.on("data", onData);
    socket.on("close", onClose);
    socket.write(text);
  });
}

function createService(
  applies: SystemProxyApplyRequest[],
  {
    attributionAvailable = true,
    dataplane,
    executablePath
  }: { attributionAvailable?: boolean; dataplane?: DataplaneController; executablePath?: string } = {}
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
    processAttribution: attribution,
    ...(dataplane ? { dataplane, protectedAddressResolver: async () => ["203.0.113.9"] } : {}),
    ...(executablePath ? { executablePath } : {})
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
