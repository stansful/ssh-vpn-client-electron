import { afterEach, describe, expect, it, vi } from "vitest";
import { Socks5Proxy } from "../src/core/network/socks5-proxy.js";
import type { WindowsSystemProxyManager } from "../src/core/network/windows-system-proxy.js";
import { SshLiveClient, type SshLiveClientEvent } from "../src/core/ssh/live-client.js";
import { SshHostKeyMismatchError } from "../src/core/ssh/session-state.js";
import { LiveSshServiceBridge, formatServiceTarget, parseServiceTarget } from "../src/service/live-ssh-service.js";
import type { ServiceEvent } from "../src/shared/ipc.js";
import type { ConnectRequest, RuntimeStatus, SshConfig } from "../src/shared/types.js";
import { createFakeHostKeys, FakeSshServer } from "./ssh-fake-server.js";

// Without a pinned fingerprint any validly signed host key used to be
// accepted, on every connect and every reconnect: a man in the middle on any
// network the laptop joined got the password and the tunnel. The bridge now
// holds a server to the key it first proved - the one main saved, or the one
// this session verified - and stops when that changes.

const KEY_A = `SHA256:${"A".repeat(43)}`;
const KEY_B = `SHA256:${"B".repeat(43)}`;
const KEY_PINNED = `SHA256:${"P".repeat(43)}`;

describe("SSH host key trust", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("expects the key saved on the first connection when nothing is pinned", async () => {
    const connect = vi.spyOn(SshLiveClient, "connect").mockResolvedValue(new FakeSshClient(KEY_A).asClient());
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest({ trustedHostKeyFingerprint: KEY_A }));

    expect(connect.mock.calls[0][0].expectedServerFingerprint).toBe(KEY_A);
    // The key's type is reported with it, for main to save beside it.
    expect(service.getStatus()).toMatchObject({ state: "Connected", observedHostKeyFingerprint: KEY_A, observedHostKeyType: "ssh-ed25519" });
    await service.dispose();
  });

  it("tells the client the saved key's type from the first connect of a run", async () => {
    // So a key of that type that does not match is final there too, and an
    // impostor cannot turn the mismatch into a retried network error by
    // dropping the connection that asks for the other type.
    const connect = vi.spyOn(SshLiveClient, "connect").mockResolvedValue(new FakeSshClient(KEY_A).asClient());
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest({ trustedHostKeyFingerprint: KEY_A, trustedHostKeyType: "ssh-ed25519" }));

    expect(connect.mock.calls[0][0]).toMatchObject({ expectedServerFingerprint: KEY_A, preferredHostKeyType: "ssh-ed25519" });
    await service.dispose();
  });

  it("tells the client a pinned key's saved type from the first connect of a run", async () => {
    // Pins used to learn their type only from a connect in this run, so the
    // first one - the auto-connect at startup included - let an impostor hide
    // the mismatch behind a dropped second connection.
    const connect = vi.spyOn(SshLiveClient, "connect").mockResolvedValue(new FakeSshClient(KEY_PINNED, undefined, "ssh-rsa").asClient());
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest({ expectedServerFingerprint: KEY_PINNED, pinnedHostKeyType: "ssh-rsa" }));

    expect(connect.mock.calls[0][0]).toMatchObject({ expectedServerFingerprint: KEY_PINNED, preferredHostKeyType: "ssh-rsa" });
    await service.dispose();
  });

  it("names the key that did not match when the retry for the server's other key type fails otherwise", async () => {
    // The pin's type is not known yet, so a dropped retry stays a retryable
    // failure - it may be the real server's RSA key - but it is not silent.
    const hostKeys = createFakeHostKeys();
    const impostor = await FakeSshServer.start({ hostKeys, stall: (index) => (index >= 1 ? "identification" : undefined) });
    const failure = await SshLiveClient.connect({
      host: "127.0.0.1",
      port: impostor.port,
      username: "user",
      password: "secret",
      expectedServerFingerprint: KEY_PINNED,
      connectTimeoutMs: 300,
      operationTimeoutMs: 1_000,
      keepaliveIntervalSec: 0
    }).catch((error: unknown) => error);
    await impostor.close();
    vi.spyOn(SshLiveClient, "connect").mockRejectedValue(failure);
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const { service, diagnostics } = createService();
    await service.connect(connectRequest({ expectedServerFingerprint: KEY_PINNED }));

    const warning = diagnostics.find((entry) => entry.includes(hostKeys.ed25519.fingerprint));
    expect(warning).toContain(`not the expected host key ${KEY_PINNED}`);
    expect(warning).toContain("may not be yours");
    expect((service as unknown as { reconnectHalted: boolean }).reconnectHalted).toBe(false);
    await service.dispose();
  });

  it("lets a pinned fingerprint override the trusted key", async () => {
    const connect = vi.spyOn(SshLiveClient, "connect").mockResolvedValue(new FakeSshClient(KEY_PINNED).asClient());
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest({ expectedServerFingerprint: ` ${KEY_PINNED} `, trustedHostKeyFingerprint: KEY_A }));

    expect(connect.mock.calls[0][0].expectedServerFingerprint).toBe(KEY_PINNED);
    await service.dispose();
  });

  it("accepts the first key of an unpinned server and holds every reconnect of the session to it", async () => {
    vi.useFakeTimers();
    const clients = [new FakeSshClient(KEY_A), new FakeSshClient(KEY_A)];
    const connect = vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(clients[0].asClient())
      .mockResolvedValueOnce(clients[1].asClient());
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest());
    expect(connect.mock.calls[0][0].expectedServerFingerprint).toBeUndefined();
    await vi.advanceTimersByTimeAsync(5_000);

    // Main never saved the key here (say the write failed); the session
    // still remembers it.
    clients[0].emit({ type: "close" });
    await vi.advanceTimersByTimeAsync(10);
    expect(connect).toHaveBeenCalledTimes(2);
    expect(connect.mock.calls[1][0].expectedServerFingerprint).toBe(KEY_A);
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus().state).toBe("Connected");
    await service.dispose();
  });

  it("stops at once, and says how to accept the change, when a trusted key changes", async () => {
    vi.spyOn(SshLiveClient, "connect").mockRejectedValue(mismatch(KEY_A, KEY_B));
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const { service, diagnostics } = createService();
    await service.connect(connectRequest({ trustedHostKeyFingerprint: KEY_A }));

    const status = service.getStatus();
    expect(status.state).toBe("Error");
    // Reconnect halting, attention and the connect screen match on these words.
    expect(status.message).toContain("host key");
    expect(status.message).toContain("fingerprint");
    expect(status.message).toContain(KEY_B);
    expect(status.message).toContain("paste the new fingerprint into the server's Fingerprint field");
    expect((service as unknown as { reconnectTimer?: NodeJS.Timeout }).reconnectTimer).toBeUndefined();
    expect(diagnostics.some((entry) => entry.startsWith("Reconnect stopped because SSH host trust"))).toBe(true);
    await service.dispose();
  });

  it("halts a reconnect that finds another key than the session verified", async () => {
    vi.useFakeTimers();
    const client = new FakeSshClient(KEY_A);
    const connect = vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(client.asClient())
      .mockRejectedValue(mismatch(KEY_A, KEY_B));
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest());
    await vi.advanceTimersByTimeAsync(5_000);

    client.emit({ type: "close" });
    await vi.advanceTimersByTimeAsync(10);
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus().state).toBe("Error");
    // Nothing was saved, so the message does not claim a key was trusted on
    // the first connection; it says the session saw another key earlier.
    expect(service.getStatus().message).toContain("presented earlier in this session");
    expect(service.getStatus().message).not.toContain("trusted on its first connection");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(connect).toHaveBeenCalledTimes(2);
    await service.dispose();
  });

  it("keeps the wording of a pinned-fingerprint mismatch", async () => {
    const error = mismatch(KEY_PINNED, KEY_B);
    vi.spyOn(SshLiveClient, "connect").mockRejectedValue(error);
    vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
    const { service } = createService();
    await service.connect(connectRequest({ expectedServerFingerprint: KEY_PINNED }));

    expect(service.getStatus()).toMatchObject({ state: "Error", message: error.message });
    await service.dispose();
  });

  it("learns the key afresh on the next user Connect", async () => {
    const connect = vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(new FakeSshClient(KEY_A).asClient())
      .mockResolvedValueOnce(new FakeSshClient(KEY_B).asClient());
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest());
    await service.disconnect();
    await service.connect(connectRequest());

    // A user Connect is a new session; what holds across sessions is the key
    // main saved, which this request does not carry.
    expect(connect.mock.calls[1][0].expectedServerFingerprint).toBeUndefined();
    await service.dispose();
  });

  it("asks first for the key type a fingerprint turned out to be, on reconnects and later Connects", async () => {
    vi.useFakeTimers();
    const clients = [
      new FakeSshClient(KEY_PINNED, undefined, "ssh-rsa"),
      new FakeSshClient(KEY_PINNED, undefined, "ssh-rsa"),
      new FakeSshClient(KEY_PINNED, undefined, "ssh-rsa"),
      new FakeSshClient(KEY_A)
    ];
    const connect = vi.spyOn(SshLiveClient, "connect");
    for (const client of clients) {
      connect.mockResolvedValueOnce(client.asClient());
    }
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest({ expectedServerFingerprint: KEY_PINNED }));
    expect(connect.mock.calls[0][0].preferredHostKeyType).toBeUndefined();
    await vi.advanceTimersByTimeAsync(5_000);

    clients[0].emit({ type: "close" });
    await vi.advanceTimersByTimeAsync(10);
    await vi.advanceTimersByTimeAsync(0);
    expect(connect).toHaveBeenCalledTimes(2);
    expect(connect.mock.calls[1][0]).toMatchObject({ expectedServerFingerprint: KEY_PINNED, preferredHostKeyType: "ssh-rsa" });

    // The type belongs to the key, not to the session: a new Connect with the
    // same pin keeps it, one with another pin does not use it.
    await service.disconnect();
    await service.connect(connectRequest({ expectedServerFingerprint: KEY_PINNED }));
    expect(connect.mock.calls[2][0].preferredHostKeyType).toBe("ssh-rsa");
    await service.disconnect();
    await service.connect(connectRequest({ expectedServerFingerprint: KEY_A }));
    expect(connect.mock.calls[3][0].preferredHostKeyType).toBeUndefined();
    await service.dispose();
  });

  it("falls back to the last address when the name will not resolve, if the key is trusted", async () => {
    vi.useFakeTimers();
    const clients = [new FakeSshClient(KEY_A, "203.0.113.5"), new FakeSshClient(KEY_A, "203.0.113.5")];
    const dnsFailure = Object.assign(new Error("getaddrinfo EAI_AGAIN trusted.example.com"), { code: "EAI_AGAIN", syscall: "getaddrinfo" });
    const connect = vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(clients[0].asClient())
      .mockRejectedValueOnce(dnsFailure)
      .mockResolvedValueOnce(clients[1].asClient());
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest({ trustedHostKeyFingerprint: KEY_A }));
    await vi.advanceTimersByTimeAsync(5_000);

    clients[0].emit({ type: "close" });
    await vi.advanceTimersByTimeAsync(10);
    await vi.advanceTimersByTimeAsync(0);
    // The trusted key decides whether the host at the old address is the
    // right one, exactly as a pinned fingerprint does.
    expect(connect).toHaveBeenCalledTimes(3);
    expect(connect.mock.calls[2][0]).toMatchObject({ host: "203.0.113.5", expectedServerFingerprint: KEY_A });
    expect(service.getStatus().state).toBe("Connected");
    await service.dispose();
  });
});

describe("service target strings", () => {
  it("reads back what it formats", () => {
    expect(parseServiceTarget(formatServiceTarget("ssh.example.com", 22))).toEqual({ host: "ssh.example.com", port: 22 });
    expect(parseServiceTarget(formatServiceTarget("2001:db8::1", 2222))).toEqual({ host: "2001:db8::1", port: 2222 });
    expect(parseServiceTarget(formatServiceTarget("203.0.113.5", 443))).toEqual({ host: "203.0.113.5", port: 443 });
    expect(parseServiceTarget("no-port")).toBeUndefined();
    expect(parseServiceTarget("host:0")).toBeUndefined();
    expect(parseServiceTarget(undefined)).toBeUndefined();
  });
});

function mismatch(expected: string, presented: string): SshHostKeyMismatchError {
  return new SshHostKeyMismatchError({
    expectedFingerprint: expected,
    presentedHostKeys: [{ fingerprint: presented, keyType: "ssh-ed25519" }],
    negotiatedHostKeyAlgorithm: "ssh-ed25519",
    serverHostKeyAlgorithms: ["ssh-ed25519"]
  });
}

class FakeSshClient {
  private listener: ((event: SshLiveClientEvent) => void) | undefined;
  readonly disconnect = vi.fn(async () => undefined);
  readonly probeLiveness = vi.fn(async () => undefined);

  constructor(
    readonly hostKeyFingerprint: string | undefined,
    readonly serverAddress: string | undefined = undefined,
    readonly hostKeyAlgorithm: string | undefined = "ssh-ed25519"
  ) {}

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

function mockProxy(): void {
  vi.spyOn(Socks5Proxy.prototype, "start").mockResolvedValue({ host: "127.0.0.1", port: 31_190 });
  vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
}

function createService(): { service: LiveSshServiceBridge; diagnostics: string[] } {
  const systemProxy = {
    apply: vi.fn(async () => ({ applied: true, message: "applied" })),
    restore: vi.fn(async () => undefined)
  } as unknown as WindowsSystemProxyManager;
  const service = new LiveSshServiceBridge(initialStatus(), { systemProxy, systemWakeDetection: false });
  const diagnostics: string[] = [];
  service.onEvent((event: ServiceEvent) => {
    if (event.type === "diagnostics-appended") {
      diagnostics.push(event.entry.message);
    }
  });
  return { service, diagnostics };
}

function connectRequest(
  trust: Partial<Pick<SshConfig, "expectedServerFingerprint" | "trustedHostKeyFingerprint" | "trustedHostKeyType" | "pinnedHostKeyType">> = {}
): ConnectRequest {
  return {
    config: {
      id: "trusted",
      name: "trusted",
      host: "trusted.example.com",
      port: 22,
      username: "user",
      authType: "password",
      expectedServerFingerprint: "",
      keepaliveIntervalSec: 60,
      note: "",
      createdAt: "",
      updatedAt: "",
      ...trust
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

