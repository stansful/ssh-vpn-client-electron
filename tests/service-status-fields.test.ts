import net from "node:net";
import os from "node:os";
import path from "node:path";
import { rm } from "node:fs/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Socks5Proxy } from "../src/core/network/socks5-proxy.js";
import { MemoryDirectTcpIpChannel } from "../src/core/network/memory-direct-channel.js";
import type { DirectTcpIpChannel } from "../src/core/network/local-tcp-proxy.js";
import type { WindowsSystemProxyManager } from "../src/core/network/windows-system-proxy.js";
import { SshAuthenticationError, SshLiveClient, type SshLiveClientEvent } from "../src/core/ssh/live-client.js";
import type { DataplaneController } from "../src/service/native-dataplane.js";
import { InProcessServiceBridge } from "../src/service/in-process-service.js";
import { formatServiceTarget, LiveSshServiceBridge } from "../src/service/live-ssh-service.js";
import { XrayServiceBridge } from "../src/service/xray-service.js";
import type { ServiceEvent } from "../src/shared/ipc.js";
import type { ConnectRequest, ProxyConnectRequest, RuntimeStatus } from "../src/shared/types.js";

const HOST_KEY = "SHA256:Qm3fV9kLr2T8xWb4NcJ7yPd1sHg6ZaE0uQoKiM5vRtY";

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("live SSH status fields", () => {
  it("names the session, its target, the local proxy and the verified host key", async () => {
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(new FakeSshClient().asClient());
    mockProxy();
    const { service, statuses } = createSshService();

    await service.connect(sshRequest("Frankfurt-01", "frankfurt.example.com"));

    expect(service.getStatus()).toMatchObject({
      state: "Connected",
      activeConfigId: "Frankfurt-01",
      activeConfigName: "Frankfurt-01",
      activeTarget: "frankfurt.example.com:22",
      localProxy: { host: "127.0.0.1", httpPort: 31090 },
      observedHostKeyFingerprint: HOST_KEY,
      tunActive: false
    });
    expect(service.getStatus().localProxy).not.toHaveProperty("socksPort");
    // The name is known from the first status of the attempt, before the session is up.
    expect(statuses.find((status) => status.state === "Connecting")).toMatchObject({
      activeConfigName: "Frankfurt-01",
      activeTarget: "frankfurt.example.com:22"
    });

    await service.disconnect();

    const status = service.getStatus();
    expect(status.state).toBe("Disconnected");
    expect(status.message).toBe("Disconnected.");
    expect(status.activeConfigName).toBeUndefined();
    expect(status.activeTarget).toBeUndefined();
    expect(status.localProxy).toBeUndefined();
    expect(status.observedHostKeyFingerprint).toBeUndefined();
    await service.dispose();
  });

  it("writes IPv6 targets with brackets", () => {
    expect(formatServiceTarget("2001:db8::10", 2222)).toBe("[2001:db8::10]:2222");
    expect(formatServiceTarget("[2001:db8::10]", 22)).toBe("[2001:db8::10]:22");
    expect(formatServiceTarget("203.0.113.10", 22)).toBe("203.0.113.10:22");
  });

  it("reports tunActive only while the adapter carries the session", async () => {
    await withWin32(async () => {
      vi.spyOn(SshLiveClient, "connect").mockResolvedValue(new FakeSshClient("203.0.113.9").asClient());
      mockProxy();
      const dataplane = fakeDataplane();
      const { service } = createSshService({ dataplane });

      await service.connect({ ...sshRequest("tun", "tun.example.com"), tunDataplaneEnabled: true });
      expect(service.getStatus()).toMatchObject({ state: "Connected", tunActive: true });

      await service.disconnect();
      expect(service.getStatus().tunActive).toBe(false);
      await service.dispose();
    });
  });

  it("reports the latency of a passed tunnel check", async () => {
    const client = new FakeSshClient();
    client.openDirectTcpIpChannel.mockImplementation(async () => new AnsweringChannel(Buffer.from([0x16, 0x03, 0x03, 0x00, 0x2a, 0x02])));
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
    mockProxy();
    const { service } = createSshService();
    await service.connect(sshRequest("check", "check.example.com"));

    const result = await service.checkTunnel("youtube.com:443");

    expect(result).toMatchObject({ ok: true, endpoint: "youtube.com:443" });
    expect(result.message).toMatch(/^Tunnel check succeeded for youtube\.com:443 in \d+ ms: youtube\.com:443 answered the TLS handshake\.$/u);
    expect(typeof result.latencyMs).toBe("number");
    expect(result.note).toBeUndefined();
    await service.dispose();
  });
});

describe("live SSH clearError", () => {
  it("turns a halted Error into Disconnected without reconnecting", async () => {
    vi.useFakeTimers();
    vi.spyOn(SshLiveClient, "connect").mockRejectedValue(new SshAuthenticationError("SSH authentication failed: password auth rejected.", []));
    mockProxy();
    const { service } = createSshService();
    await service.connect(sshRequest("Frankfurt-01", "frankfurt.example.com"));
    expect(service.getStatus()).toMatchObject({ state: "Error", activeConfigName: "Frankfurt-01" });

    await service.clearError();

    expect(service.getStatus()).toMatchObject({
      state: "Disconnected",
      message: "Disconnected.",
      reconnectAttempt: 0,
      realTunnelAvailable: false
    });
    expect(service.getStatus().activeConfigId).toBeUndefined();
    expect(service.getStatus().activeConfigName).toBeUndefined();
    service.wake("system resume");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(1);
    expect(service.getStatus().state).toBe("Disconnected");
    await service.dispose();
  });

  it("does nothing unless the session is in Error", async () => {
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(new FakeSshClient().asClient());
    mockProxy();
    const { service } = createSshService();
    await service.connect(sshRequest("live", "live.example.com"));

    await service.clearError();

    expect(service.getStatus().state).toBe("Connected");
    await service.dispose();
  });

  // The session fails into Error and the teardown is still queued when the
  // user dismisses it: the listener must still come down.
  it("finishes the teardown of a session dismissed while it was still failing", async () => {
    const client = new FakeSshClient();
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
    const proxy = mockProxy();
    const { service } = createSshService();
    await service.connect(sshRequest("pinned", "pinned.example.com"));

    client.emit({ type: "error", error: new Error("SSH server host key changed during rekey: expected A, got B.") });
    expect(service.getStatus().state).toBe("Error");
    await service.clearError();
    await vi.waitFor(() => expect(proxy.stop).toHaveBeenCalled());

    expect(service.getStatus()).toMatchObject({ state: "Disconnected", message: "Disconnected." });
    expect(service.getStatus().localProxy).toBeUndefined();
    await service.dispose();
  });
});

describe("Xray status fields and clearError", () => {
  const runtimeDirectories: string[] = [];

  afterEach(async () => {
    await Promise.all(runtimeDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
  });

  it("names the profile from the first status and clears it when an Error is dismissed", async () => {
    const service = createXrayService(runtimeDirectories);
    const statuses: RuntimeStatus[] = [];
    service.onEvent((event) => {
      if (event.type === "status-changed") {
        statuses.push(event.status);
      }
    });

    // No Xray runtime is configured, so the attempt ends in Error.
    await service.connect(xrayRequest("de-fra-reality", "2001:db8::443"));

    expect(statuses[0]).toMatchObject({
      state: "Connecting",
      activeConfigName: "de-fra-reality",
      activeTarget: "[2001:db8::443]:443"
    });
    expect(service.getStatus()).toMatchObject({ state: "Error", activeConfigName: "de-fra-reality" });
    expect(service.getStatus().localProxy).toBeUndefined();

    await service.clearError();

    expect(service.getStatus()).toMatchObject({ state: "Disconnected", message: "Disconnected.", reconnectAttempt: 0 });
    expect(service.getStatus().activeConfigId).toBeUndefined();
    expect(service.getStatus().activeConfigName).toBeUndefined();
    expect(service.getStatus().activeTarget).toBeUndefined();
    await service.dispose();
  });

  it("leaves a state other than Error alone", async () => {
    const service = createXrayService(runtimeDirectories);

    await service.clearError();

    expect(service.getStatus()).toMatchObject({ state: "Disconnected", message: "Xray transport is ready." });
    await service.dispose();
  });
});

describe("simulator status fields and clearError", () => {
  it("names the session it simulates", async () => {
    vi.useFakeTimers();
    const service = new InProcessServiceBridge(initialStatus("simulator"));

    const connecting = service.connect(sshRequest("Lab Raspberry", "192.0.2.55"));
    await vi.advanceTimersByTimeAsync(600);
    await connecting;

    expect(service.getStatus()).toMatchObject({
      state: "Connected",
      activeConfigName: "Lab Raspberry",
      activeTarget: "192.0.2.55:22"
    });
    await service.clearError();
    expect(service.getStatus().state).toBe("Connected");
  });

  it("dismisses an Error", async () => {
    const service = new InProcessServiceBridge({ ...initialStatus("simulator"), state: "Error", message: "Simulated failure." });

    await service.clearError();

    expect(service.getStatus()).toMatchObject({ state: "Disconnected", message: "Disconnected." });
  });

  it("reports the latency of a direct endpoint check", async () => {
    const server = net.createServer((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as net.AddressInfo;
    try {
      const result = await new InProcessServiceBridge(initialStatus("simulator")).checkTunnel(`127.0.0.1:${port}`);

      expect(result.ok).toBe(true);
      expect(typeof result.latencyMs).toBe("number");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

class FakeSshClient {
  private listener: ((event: SshLiveClientEvent) => void) | undefined;
  readonly hostKeyFingerprint = HOST_KEY;
  readonly disconnect = vi.fn(async () => undefined);
  readonly openShell = vi.fn(async () => undefined);
  readonly closeShell = vi.fn(async () => undefined);
  readonly writeShell = vi.fn(async () => undefined);
  readonly probeLiveness = vi.fn(async () => undefined);
  readonly openDirectTcpIpChannel = vi.fn<() => Promise<DirectTcpIpChannel>>(async () => new MemoryDirectTcpIpChannel());

  constructor(readonly serverAddress: string | undefined = undefined) {}

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

/** Answers the first write the way a TLS server answers a ClientHello. */
class AnsweringChannel extends MemoryDirectTcpIpChannel {
  constructor(private readonly reply: Buffer) {
    super();
  }

  override async write(data: Buffer): Promise<void> {
    await super.write(data);
    setTimeout(() => this.pushRemoteData(this.reply), 0);
  }
}

function mockProxy(): { stop: ReturnType<typeof vi.fn> } {
  vi.spyOn(Socks5Proxy.prototype, "start").mockResolvedValue({ host: "127.0.0.1", port: 31090 });
  const stop = vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
  return { stop: stop as unknown as ReturnType<typeof vi.fn> };
}

function fakeSystemProxy(): WindowsSystemProxyManager {
  return {
    apply: vi.fn(async () => ({ applied: true, message: "applied" })),
    restore: vi.fn(async () => undefined)
  } as unknown as WindowsSystemProxyManager;
}

function createSshService(options: { dataplane?: DataplaneController } = {}): {
  service: LiveSshServiceBridge;
  statuses: RuntimeStatus[];
} {
  const service = new LiveSshServiceBridge(initialStatus("live-ssh"), {
    systemProxy: fakeSystemProxy(),
    systemWakeDetection: false,
    ...(options.dataplane
      ? {
          dataplane: options.dataplane,
          processConnectionsProvider: async () => [],
          processDnsEntriesProvider: async () => [],
          protectedAddressResolver: async () => ["203.0.113.9"]
        }
      : {})
  });
  const statuses: RuntimeStatus[] = [];
  service.onEvent((event: ServiceEvent) => {
    if (event.type === "status-changed") {
      statuses.push(event.status);
    }
  });
  return { service, statuses };
}

function createXrayService(runtimeDirectories: string[]): XrayServiceBridge {
  const runtimeDirectory = path.join(os.tmpdir(), `shadow-ssh-status-fields-${process.pid}-${runtimeDirectories.length}`);
  runtimeDirectories.push(runtimeDirectory);
  return new XrayServiceBridge(initialStatus("xray"), { runtimeDirectory, systemProxy: fakeSystemProxy() });
}

function fakeDataplane(): DataplaneController {
  const controller = {
    isActive: false,
    probe: async () => ({ available: true }),
    start: async () => {
      controller.isActive = true;
    },
    stop: async () => {
      controller.isActive = false;
    },
    dispose: async () => undefined
  };
  return controller;
}

function sshRequest(name: string, host: string): ConnectRequest {
  return {
    config: {
      id: name,
      name,
      host,
      port: 22,
      username: "root",
      authType: "password",
      expectedServerFingerprint: "",
      keepaliveIntervalSec: 120,
      note: "",
      createdAt: "",
      updatedAt: ""
    },
    routingMode: "proxy-all",
    routingRules: [],
    routingProxyDomains: [],
    routingDirectDomains: [],
    checkEndpoint: "youtube.com:443",
    secrets: { password: "secret" }
  };
}

function xrayRequest(name: string, host: string): ProxyConnectRequest {
  return {
    profile: {
      id: name,
      name,
      protocol: "vless",
      host,
      port: 443,
      transport: "tcp",
      security: "reality",
      flow: "",
      source: "manual",
      rawUriSecretId: "secret",
      fingerprint: name,
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
    checkEndpoint: "youtube.com:443",
    secrets: { rawUri: "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=tcp&security=tls#test" }
  };
}

function initialStatus(transport: RuntimeStatus["transport"]): RuntimeStatus {
  return {
    state: "Disconnected",
    message: "",
    reconnectAttempt: 0,
    transport,
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
