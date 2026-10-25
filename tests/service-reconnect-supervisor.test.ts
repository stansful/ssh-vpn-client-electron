import net from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Socks5Proxy, type Socks5ProxyOptions } from "../src/core/network/socks5-proxy.js";
import type { DirectTcpIpChannel } from "../src/core/network/local-tcp-proxy.js";
import type { DataplaneController } from "../src/service/native-dataplane.js";
import type { DataplaneStartRequest } from "../src/service/local-ipc-protocol.js";
import type { WindowsSystemProxyManager } from "../src/core/network/windows-system-proxy.js";
import { SshAuthenticationError, SshLiveClient, type SshLiveClientEvent } from "../src/core/ssh/live-client.js";
import { SshHostKeyMismatchError } from "../src/core/ssh/session-state.js";
import { TransportMutationCoordinator } from "../src/main/app/transport-mutation-coordinator.js";
import { LiveSshServiceBridge } from "../src/service/live-ssh-service.js";
import type { ServiceEvent } from "../src/shared/ipc.js";
import type { ConnectRequest, RuntimeStatus } from "../src/shared/types.js";

/**
 * The reconnect loop as a supervisor: whatever happens - a failed teardown, a
 * lost timer, a resume from sleep, a resolver that is not back yet - either a
 * session comes up again or the status explains why it will not.
 */
describe("live SSH service reconnect supervisor", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("brings a scheduled reconnect forward on wake and restarts the backoff", async () => {
    vi.useFakeTimers();
    const clients = [new FakeSshClient(), new FakeSshClient()];
    const refused = Object.assign(new Error("connect ECONNREFUSED 203.0.113.5:22"), { code: "ECONNREFUSED" });
    vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(clients[0].asClient())
      .mockRejectedValueOnce(refused)
      .mockRejectedValueOnce(refused)
      .mockRejectedValueOnce(refused)
      .mockResolvedValueOnce(clients[1].asClient());
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest("wake"));
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);
    expect(service.getStatus().state).toBe("Connected");

    clients[0].emit({ type: "close" });
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus().state).toBe("Reconnecting");
    // The first retry is immediate; attempts 2..3 back off 1 s and 2 s
    // (+ jitter of at most 20 %), and the fourth would wait 4 s.
    await vi.advanceTimersByTimeAsync(10);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1_300);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(2_500);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(4);
    expect(service.getStatus()).toMatchObject({ state: "Reconnecting", reconnectAttempt: 4 });
    await vi.advanceTimersByTimeAsync(500);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(4);

    // The next attempt would wait 4 s. The machine just woke up: go now.
    service.wake("system resume");
    await vi.advanceTimersByTimeAsync(1_000);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(5);
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus()).toMatchObject({ state: "Connected", reconnectAttempt: 0, realTunnelAvailable: true });
    await service.dispose();
  });

  it("probes a live session on wake and reconnects when the probe fails", async () => {
    vi.useFakeTimers();
    const clients = [new FakeSshClient(), new FakeSshClient()];
    vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(clients[0].asClient())
      .mockResolvedValueOnce(clients[1].asClient());
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest("probe"));
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);

    clients[0].probeLiveness.mockImplementation(async () => {
      const error = new Error("SSH keepalive timed out: nothing received from the server for 15 s.");
      clients[0].emit({ type: "error", error });
      throw error;
    });
    service.wake("network-changed: en0 moved");
    expect(clients[0].probeLiveness).toHaveBeenCalledWith(15_000);
    expect(service.getStatus().state).toBe("Reconnecting");
    await vi.advanceTimersByTimeAsync(10);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus().state).toBe("Connected");

    // A healthy session answers the probe and nothing else happens.
    service.wake("clock-jump");
    expect(clients[1].probeLiveness).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(2);
    expect(service.getStatus().state).toBe("Connected");
    await service.dispose();
  });

  it("keeps reconnecting when the teardown of a failed session throws", async () => {
    vi.useFakeTimers();
    const clients = [new FakeSshClient(), new FakeSshClient()];
    vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(clients[0].asClient())
      .mockResolvedValueOnce(clients[1].asClient());
    mockProxy();
    const { service, diagnostics } = createService();
    await service.connect(connectRequest("teardown"));
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);
    const internals = service as unknown as { disconnectClient(client: SshLiveClient, reason: string): Promise<void> };
    const disconnectClient = vi.spyOn(internals, "disconnectClient").mockRejectedValueOnce(new Error("teardown exploded"));

    clients[0].emit({ type: "error", error: new Error("transport failed") });
    expect(service.getStatus().state).toBe("Reconnecting");
    await vi.advanceTimersByTimeAsync(0);
    expect(disconnectClient).toHaveBeenCalledTimes(1);
    expect(diagnostics.some((entry) => entry.includes("Cleanup after the SSH transport failure failed: teardown exploded"))).toBe(true);

    await vi.advanceTimersByTimeAsync(10);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus().state).toBe("Connected");
    await service.dispose();
  });

  it("records a failure inside the attempt's own teardown as a failed attempt", async () => {
    vi.useFakeTimers();
    const clients = [new FakeSshClient(), new FakeSshClient()];
    vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(clients[0].asClient())
      .mockResolvedValueOnce(clients[1].asClient());
    mockProxy();
    const { service } = createService();
    const internals = service as unknown as { stopSystemRouting(): Promise<void> };
    // A user Connect starts by clearing routing; that step dies.
    vi.spyOn(internals, "stopSystemRouting").mockRejectedValueOnce(new Error("routing restore hung"));
    await service.connect(connectRequest("attempt-teardown"));
    expect(service.getStatus()).toMatchObject({ state: "Reconnecting", reconnectAttempt: 1 });
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(0);

    // The retry honours the one-second spacing from the attempt that just failed.
    await vi.advanceTimersByTimeAsync(1_300);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus().state).toBe("Connected");
    await service.dispose();
  });

  it("repairs a lost reconnect timer from the watchdog", async () => {
    vi.useFakeTimers();
    const clients = [new FakeSshClient(), new FakeSshClient()];
    vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(clients[0].asClient())
      .mockRejectedValueOnce(new Error("connect ECONNREFUSED"))
      .mockResolvedValueOnce(clients[1].asClient());
    mockProxy();
    const { service, diagnostics } = createService();
    await service.connect(connectRequest("watchdog"));
    await vi.advanceTimersByTimeAsync(5_000);

    clients[0].emit({ type: "close" });
    // The immediate retry fails and a 1 s retry is armed.
    await vi.advanceTimersByTimeAsync(10);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(2);
    expect(service.getStatus().state).toBe("Reconnecting");
    const internals = service as unknown as { clearReconnectTimer(): void; reconnectTimer: NodeJS.Timeout | undefined };
    expect(internals.reconnectTimer).toBeDefined();
    // Simulate the bug class the watchdog exists for: the armed timer is gone.
    internals.clearReconnectTimer();
    await vi.advanceTimersByTimeAsync(4_000);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(2);

    await vi.advanceTimersByTimeAsync(10_000);
    expect(diagnostics.some((entry) => entry.includes("Connection supervisor: no session, no attempt in progress"))).toBe(true);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus().state).toBe("Connected");
    await service.dispose();
  });

  it("does nothing on wake or from the watchdog once reconnecting is halted", async () => {
    vi.useFakeTimers();
    vi.spyOn(SshLiveClient, "connect").mockRejectedValue(new Error("SSH server fingerprint mismatch: expected SHA256:a, got SHA256:b."));
    mockProxy();
    const { service, diagnostics } = createService();
    await service.connect(connectRequest("halted"));
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);
    expect(service.getStatus().state).toBe("Error");
    expect(diagnostics.some((entry) => entry.includes("Reconnect stopped"))).toBe(true);

    service.wake("system resume");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(1);
    expect(service.getStatus().state).toBe("Error");
    expect(vi.getTimerCount()).toBe(0);
    await service.dispose();
  });

  it("does nothing on wake after the user disconnected", async () => {
    vi.useFakeTimers();
    const client = new FakeSshClient();
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest("disconnected"));
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);
    await service.disconnect();

    service.wake("system resume");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(1);
    expect(client.probeLiveness).not.toHaveBeenCalled();
    expect(service.getStatus().state).toBe("Disconnected");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("retries an automatic reconnect once after an authentication rejection, then stops", async () => {
    vi.useFakeTimers();
    const client = new FakeSshClient();
    const rejected = () => new SshAuthenticationError("SSH authentication failed: password auth rejected", []);
    vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(client.asClient())
      .mockRejectedValueOnce(rejected())
      .mockRejectedValueOnce(rejected());
    mockProxy();
    const { service, diagnostics } = createService();
    await service.connect(connectRequest("auth"));
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);

    client.emit({ type: "close" });
    await vi.advanceTimersByTimeAsync(10);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus().state).toBe("Reconnecting");
    expect(diagnostics.some((entry) => entry.includes("rejected during automatic reconnect (1/2)"))).toBe(true);

    await vi.advanceTimersByTimeAsync(1_300);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus().state).toBe("Error");
    expect(diagnostics.some((entry) => entry.includes("Reconnect stopped. Update the SSH configuration or key"))).toBe(true);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(3);
    await service.dispose();
  });

  it("stops at once when a user-initiated connect is rejected by authentication", async () => {
    vi.useFakeTimers();
    vi.spyOn(SshLiveClient, "connect").mockRejectedValue(new SshAuthenticationError("SSH authentication failed: private-key auth rejected", []));
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest("user-auth"));
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);
    expect(service.getStatus().state).toBe("Error");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(1);
    await service.dispose();
  });

  it("falls back to the last known server address when the name does not resolve", async () => {
    vi.useFakeTimers();
    const clients = [new FakeSshClient("203.0.113.5"), new FakeSshClient("203.0.113.5")];
    const dnsFailure = Object.assign(new Error("getaddrinfo EAI_AGAIN dns.example.com"), {
      code: "EAI_AGAIN",
      syscall: "getaddrinfo"
    });
    const connect = vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(clients[0].asClient())
      .mockRejectedValueOnce(dnsFailure)
      .mockResolvedValueOnce(clients[1].asClient());
    mockProxy();
    const { service, diagnostics } = createService();
    await service.connect(connectRequest("dns"));
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);

    clients[0].emit({ type: "close" });
    await vi.advanceTimersByTimeAsync(10);
    expect(connect).toHaveBeenCalledTimes(3);
    expect(connect.mock.calls[1][0].host).toBe("dns.example.com");
    expect(connect.mock.calls[2][0].host).toBe("203.0.113.5");
    expect(connect.mock.calls[2][0].expectedServerFingerprint).toBe("SHA256:test");
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus()).toMatchObject({ state: "Connected", reconnectAttempt: 0 });
    expect(diagnostics.some((entry) => entry.includes("retrying with the last known address 203.0.113.5"))).toBe(true);
    await service.dispose();
  });

  it("applies a wake that arrived during a failing attempt to the next schedule", async () => {
    vi.useFakeTimers();
    const clients = [new FakeSshClient(), new FakeSshClient()];
    const pending = deferred<SshLiveClient>();
    vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(clients[0].asClient())
      .mockRejectedValueOnce(new Error("connect ETIMEDOUT"))
      .mockRejectedValueOnce(new Error("connect ETIMEDOUT"))
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce(clients[1].asClient());
    mockProxy();
    const { service, diagnostics } = createService();
    await service.connect(connectRequest("pending-wake"));
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);
    clients[0].emit({ type: "close" });
    await vi.advanceTimersByTimeAsync(10);
    await vi.advanceTimersByTimeAsync(1_300);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(3);
    // Attempt 4 is now hanging in the 10 s connect timeout; the next backoff
    // step would be 4 s.
    await vi.advanceTimersByTimeAsync(2_500);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(4);
    service.wake("network-changed: en0 gained 10.0.0.7");
    pending.reject(new Error("connect ETIMEDOUT"));
    // Without the wake the next step would wait 4 s; with it the attempt runs
    // as soon as the one-second spacing allows.
    await vi.advanceTimersByTimeAsync(1_000);
    expect(diagnostics.some((entry) => entry.includes("brought forward by wake"))).toBe(true);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(5);
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus().state).toBe("Connected");
    await service.dispose();
  });

  it("does not let a backward clock step stretch the wake spacing", async () => {
    vi.useFakeTimers();
    const clients = [new FakeSshClient(), new FakeSshClient()];
    vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(clients[0].asClient())
      .mockRejectedValueOnce(new Error("connect ECONNREFUSED"))
      .mockResolvedValueOnce(clients[1].asClient());
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest("clock"));
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);
    clients[0].emit({ type: "close" });
    await vi.advanceTimersByTimeAsync(10);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(2);
    expect(service.getStatus().state).toBe("Reconnecting");

    // NTP steps the clock ten minutes back after a resume.
    vi.setSystemTime(Date.now() - 10 * 60 * 1000);
    service.wake("system resume");
    await vi.advanceTimersByTimeAsync(1_000);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus().state).toBe("Connected");
    await service.dispose();
  });

  it("restarts the backoff for at most one wake per half minute", async () => {
    vi.useFakeTimers();
    const client = new FakeSshClient();
    const refused = new Error("connect ECONNREFUSED");
    vi.spyOn(SshLiveClient, "connect").mockResolvedValueOnce(client.asClient()).mockRejectedValue(refused);
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest("storm"));
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);
    client.emit({ type: "close" });
    await vi.advanceTimersByTimeAsync(10);
    await vi.advanceTimersByTimeAsync(1_300);
    await vi.advanceTimersByTimeAsync(2_500);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(5);

    // A flapping interface wakes the service every five seconds.
    for (let tick = 0; tick < 6; tick += 1) {
      service.wake(`network-changed: flap ${tick}`);
      await vi.advanceTimersByTimeAsync(5_000);
    }
    // One wake restarted the ladder (attempt at +1 s, then 0, 1, 2, 4 s
    // steps); the other five did not, so the count stays near the ladder's
    // pace instead of one attempt per wake.
    const attempts = vi.mocked(SshLiveClient.connect).mock.calls.length;
    expect(attempts).toBeGreaterThanOrEqual(9);
    expect(attempts).toBeLessThanOrEqual(12);
    await service.dispose();
  });

  it("does not fall back to a cached address without a pinned fingerprint", async () => {
    vi.useFakeTimers();
    const client = new FakeSshClient("203.0.113.5");
    const dnsFailure = Object.assign(new Error("getaddrinfo EAI_AGAIN unpinned.example.com"), {
      code: "EAI_AGAIN",
      syscall: "getaddrinfo"
    });
    const connect = vi.spyOn(SshLiveClient, "connect").mockResolvedValueOnce(client.asClient()).mockRejectedValue(dnsFailure);
    mockProxy();
    const { service } = createService();
    await service.connect({ ...connectRequest("unpinned"), config: { ...connectRequest("unpinned").config, expectedServerFingerprint: "" } });
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);
    client.emit({ type: "close" });
    await vi.advanceTimersByTimeAsync(10);
    expect(connect).toHaveBeenCalledTimes(2);
    expect(connect.mock.calls[1][0].host).toBe("unpinned.example.com");
    expect(service.getStatus().state).toBe("Reconnecting");
    await service.dispose();
  });

  it("forgets a cached address that another host now answers from and keeps retrying", async () => {
    vi.useFakeTimers();
    const clients = [new FakeSshClient("203.0.113.5"), new FakeSshClient("203.0.113.9")];
    const dnsFailure = Object.assign(new Error("getaddrinfo EAI_AGAIN stale.example.com"), {
      code: "EAI_AGAIN",
      syscall: "getaddrinfo"
    });
    const connect = vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(clients[0].asClient())
      .mockRejectedValueOnce(dnsFailure)
      .mockRejectedValueOnce(new Error("SSH server fingerprint mismatch: expected SHA256:test, got SHA256:other."))
      .mockResolvedValueOnce(clients[1].asClient());
    mockProxy();
    const { service, diagnostics } = createService();
    await service.connect(connectRequest("stale"));
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);
    clients[0].emit({ type: "close" });
    await vi.advanceTimersByTimeAsync(10);
    expect(connect).toHaveBeenCalledTimes(3);
    expect(connect.mock.calls[2][0].host).toBe("203.0.113.5");
    // The mismatch belongs to the stale address, not the configuration: the
    // loop keeps going and the next resolution succeeds.
    expect(service.getStatus().state).toBe("Reconnecting");
    expect(diagnostics.some((entry) => entry.includes("no longer belongs to stale.example.com"))).toBe(true);
    await vi.advanceTimersByTimeAsync(1_300);
    expect(connect).toHaveBeenCalledTimes(4);
    expect(connect.mock.calls[3][0].host).toBe("stale.example.com");
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus().state).toBe("Connected");
    await service.dispose();
  });

  it("does not retry an authentication rejection when no session was ever established", async () => {
    vi.useFakeTimers();
    vi.spyOn(SshLiveClient, "connect")
      .mockRejectedValueOnce(new Error("connect ECONNREFUSED"))
      .mockRejectedValueOnce(new SshAuthenticationError("SSH authentication failed: password auth rejected", []));
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest("never"));
    expect(service.getStatus().state).toBe("Reconnecting");
    await vi.advanceTimersByTimeAsync(1_300);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(0);
    expect(service.getStatus().state).toBe("Error");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(2);
    await service.dispose();
  });

  it("keeps the listener up and parks new connections until the session is back", async () => {
    vi.useFakeTimers();
    const clients = [new FakeSshClient(), new FakeSshClient()];
    vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(clients[0].asClient())
      .mockRejectedValueOnce(new Error("connect ECONNREFUSED"))
      .mockResolvedValueOnce(clients[1].asClient());
    const listener = mockProxy();
    const { service, diagnostics } = createService();
    await service.connect(connectRequest("park"));
    await vi.advanceTimersByTimeAsync(5_000);
    const target = { host: "chat.example.com", port: 443 };
    const originator = { address: "127.0.0.1", port: 50000 };

    // A connection while the session is up goes straight through it.
    const live = await listener.connectChannel()(target, originator);
    expect((live as unknown as { owner: FakeSshClient }).owner).toBe(clients[0]);

    clients[0].emit({ type: "close" });
    expect(service.getStatus().state).toBe("Reconnecting");
    // A WebSocket client reconnects at once: the listener is still there and
    // the connection waits instead of being refused.
    const parked = listener.connectChannel()(target, originator);
    let settled = false;
    void parked.then(() => {
      settled = true;
    }, () => {
      settled = true;
    });
    await vi.advanceTimersByTimeAsync(10);
    expect(SshLiveClient.connect).toHaveBeenCalledTimes(2);
    expect(settled).toBe(false);
    expect(Socks5Proxy.prototype.stop).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1_300);
    expect(service.getStatus().state).toBe("Connected");
    const channel = await parked;
    expect((channel as unknown as { owner: FakeSshClient }).owner).toBe(clients[1]);
    expect(Socks5Proxy.prototype.start).toHaveBeenCalledTimes(1);
    expect(diagnostics.some((entry) => entry.includes("1 waiting proxy connection resumed"))).toBe(true);
    await service.dispose();
  });

  it("fails a parked connection after the park window, on abort, and on disconnect", async () => {
    vi.useFakeTimers();
    const client = new FakeSshClient();
    vi.spyOn(SshLiveClient, "connect").mockResolvedValueOnce(client.asClient()).mockRejectedValue(new Error("connect ETIMEDOUT"));
    const listener = mockProxy();
    const { service } = createService();
    await service.connect(connectRequest("park-timeout"));
    await vi.advanceTimersByTimeAsync(5_000);
    client.emit({ type: "close" });
    const target = { host: "api.example.com", port: 443 };
    const originator = { address: "127.0.0.1", port: 50001 };

    const timedOut = listener.connectChannel()(target, originator);
    const timedOutRejection = expect(timedOut).rejects.toThrow("gave up waiting for it after 25 s");
    const aborter = new AbortController();
    const aborted = listener.connectChannel()(target, originator, aborter.signal);
    const abortedRejection = expect(aborted).rejects.toMatchObject({ name: "AbortError" });

    aborter.abort();
    await abortedRejection;
    await vi.advanceTimersByTimeAsync(25_100);
    await timedOutRejection;

    const untilDisconnect = listener.connectChannel()(target, originator);
    const disconnectRejection = expect(untilDisconnect).rejects.toThrow("SSH session is not connected");
    await service.disconnect();
    await disconnectRejection;
    // Once nothing is wanted, a new connection is refused at once.
    await expect(listener.connectChannel()(target, originator)).rejects.toThrow("SSH session is not connected");
    expect(Socks5Proxy.prototype.stop).toHaveBeenCalled();
  });

  it("refuses connections and stops the listener once reconnecting is halted", async () => {
    vi.useFakeTimers();
    const client = new FakeSshClient();
    vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(client.asClient())
      .mockRejectedValue(new Error("SSH server fingerprint mismatch: expected SHA256:test, got SHA256:x."));
    const listener = mockProxy();
    const { service } = createService();
    await service.connect(connectRequest("halt-park"));
    await vi.advanceTimersByTimeAsync(5_000);
    client.emit({ type: "close" });
    const parked = listener.connectChannel()({ host: "api.example.com", port: 443 }, { address: "127.0.0.1", port: 50002 });
    const rejection = expect(parked).rejects.toThrow("SSH session is not connected");
    await vi.advanceTimersByTimeAsync(10);
    expect(service.getStatus().state).toBe("Error");
    await rejection;
    await vi.advanceTimersByTimeAsync(0);
    expect(Socks5Proxy.prototype.stop).toHaveBeenCalled();
    await service.dispose();
  });

  it("keeps TUN capture across a reconnect by reusing the protected server address", async () => {
    await withWin32(async () => {
      vi.useFakeTimers();
      const clients = [new FakeSshClient("203.0.113.9"), new FakeSshClient("203.0.113.9")];
      const connect = vi.spyOn(SshLiveClient, "connect")
        .mockResolvedValueOnce(clients[0].asClient())
        .mockResolvedValueOnce(clients[1].asClient());
      mockProxy();
      const dataplane = fakeDataplane();
      const { service, diagnostics } = createService({ dataplane, tun: true });
      await service.connect({ ...connectRequest("tun"), tunDataplaneEnabled: true });
      expect(dataplane.started).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(5_000);

      clients[0].emit({ type: "close" });
      await vi.advanceTimersByTimeAsync(10);
      expect(connect).toHaveBeenCalledTimes(2);
      // The adapter captures everything but the protected address, so that is
      // the address the new session must use - a fresh lookup could route the
      // transport into its own tunnel.
      expect(connect.mock.calls[1][0].host).toBe("203.0.113.9");
      await vi.advanceTimersByTimeAsync(0);
      expect(service.getStatus().state).toBe("Connected");
      expect(dataplane.stopped).toBe(0);
      expect(dataplane.started).toHaveLength(1);
      expect(diagnostics.some((entry) => entry.includes("TUN routing was kept across the reconnect"))).toBe(true);
      await service.dispose();
      expect(dataplane.stopped).toBe(1);
    });
  });

  it("rebuilds held TUN capture when the rules changed while the session was down", async () => {
    await withWin32(async () => {
      vi.useFakeTimers();
      const clients = [new FakeSshClient("203.0.113.9"), new FakeSshClient("203.0.113.9")];
      const connect = vi.spyOn(SshLiveClient, "connect")
        .mockResolvedValueOnce(clients[0].asClient())
        .mockResolvedValueOnce(clients[1].asClient());
      mockProxy();
      const dataplane = fakeDataplane();
      const { service } = createService({ dataplane, tun: true });
      const request = { ...connectRequest("tun-rules"), tunDataplaneEnabled: true };
      await service.connect(request);
      await vi.advanceTimersByTimeAsync(5_000);

      clients[0].emit({ type: "close" });
      await service.updateRouting({
        routingMode: "selected-rules",
        routingRules: [{ id: "d1", type: "domain", value: "example.org", enabled: true, createdAt: "", updatedAt: "" }],
        routingProxyDomains: [],
        routingDirectDomains: [],
        checkEndpoint: "example.com:443"
      });
      await vi.advanceTimersByTimeAsync(10);
      // The adapter cannot keep running the old rules: it is taken down and
      // started again with the new ones, and the attempt resolves normally.
      expect(connect.mock.calls[1][0].host).toBe("tun-rules.example.com");
      await vi.advanceTimersByTimeAsync(0);
      expect(service.getStatus().state).toBe("Connected");
      expect(dataplane.stopped).toBe(1);
      expect(dataplane.started).toHaveLength(2);
      expect(dataplane.started[1].routingRules).toEqual([expect.objectContaining({ value: "example.org" })]);
      await service.dispose();
    });
  });

  it("keeps a fresh hold when a session comes and goes while the previous hold expires", async () => {
    vi.useFakeTimers();
    const clients = [new FakeSshClient(), new FakeSshClient(), new FakeSshClient()];
    const pending = deferred<SshLiveClient>();
    vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(clients[0].asClient())
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce(clients[2].asClient());
    mockProxy();
    const systemProxy = {
      apply: vi.fn(async () => ({ applied: true, message: "applied" })),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager;
    const service = new LiveSshServiceBridge(initialStatus(), { systemProxy, systemWakeDetection: false });
    await service.connect(connectRequest("hold-generation"));
    await vi.advanceTimersByTimeAsync(5_000);
    expect(systemProxy.restore).toHaveBeenCalledTimes(1);

    clients[0].emit({ type: "close" });
    // The immediate retry hangs past the hold window; the hold fires while it
    // is still in flight and queues the fail-open behind it.
    await vi.advanceTimersByTimeAsync(30_500);
    // ... and the new session dies the moment it is announced. Its outage
    // gets a hold of its own; the stale fail-open must not strip routing
    // from underneath it.
    let connectedEvents = 0;
    service.onEvent((event) => {
      if (event.type === "status-changed" && event.status.state === "Connected") {
        connectedEvents += 1;
        if (connectedEvents === 1) {
          clients[1].emit({ type: "close" });
        }
      }
    });
    pending.resolve(clients[1].asClient());
    await vi.advanceTimersByTimeAsync(10);
    // The second session died and the third came up at once; through all of
    // it the machine kept its routing.
    expect(connectedEvents).toBe(2);
    expect(service.getStatus().state).toBe("Connected");
    expect(systemProxy.restore).toHaveBeenCalledTimes(1);
    await service.dispose();
  });

  it("releases TUN capture when the protected address does not answer", async () => {
    await withWin32(async () => {
      vi.useFakeTimers();
      const clients = [new FakeSshClient("203.0.113.9"), new FakeSshClient("203.0.113.10")];
      const connect = vi.spyOn(SshLiveClient, "connect")
        .mockResolvedValueOnce(clients[0].asClient())
        .mockRejectedValueOnce(new Error("connect ETIMEDOUT 203.0.113.9:22"))
        .mockResolvedValueOnce(clients[1].asClient());
      mockProxy();
      const dataplane = fakeDataplane();
      const { service, diagnostics } = createService({ dataplane, tun: true });
      await service.connect({ ...connectRequest("tun-fallback"), tunDataplaneEnabled: true });
      await vi.advanceTimersByTimeAsync(5_000);

      clients[0].emit({ type: "close" });
      await vi.advanceTimersByTimeAsync(10);
      expect(connect).toHaveBeenCalledTimes(2);
      expect(connect.mock.calls[1][0].host).toBe("203.0.113.9");
      await vi.advanceTimersByTimeAsync(0);
      // The shortcut failed: the adapter comes down so the next attempt can
      // resolve and reach the server the ordinary way.
      expect(dataplane.stopped).toBe(1);
      expect(diagnostics.some((entry) => entry.includes("releasing TUN routing"))).toBe(true);
      await vi.advanceTimersByTimeAsync(1_300);
      expect(connect).toHaveBeenCalledTimes(3);
      expect(connect.mock.calls[2][0].host).toBe("tun-fallback.example.com");
      await vi.advanceTimersByTimeAsync(0);
      expect(service.getStatus().state).toBe("Connected");
      expect(dataplane.started).toHaveLength(2);
      await service.dispose();
    });
  });

  it("resolves the name again when another server answers at the protected address", async () => {
    await withWin32(async () => {
      vi.useFakeTimers();
      // The server moved while the session was down, and another host with
      // its own key now has the old address. A fresh lookup finds the server
      // and its unchanged key; halting as if it were an impostor would not.
      const clients = [new FakeSshClient("203.0.113.9"), new FakeSshClient("203.0.113.20")];
      const connect = vi.spyOn(SshLiveClient, "connect")
        .mockResolvedValueOnce(clients[0].asClient())
        .mockRejectedValueOnce(new SshHostKeyMismatchError({
          expectedFingerprint: "SHA256:server",
          presentedHostKeys: [{ fingerprint: "SHA256:someone-else", keyType: "ssh-ed25519" }],
          negotiatedHostKeyAlgorithm: "ssh-ed25519",
          serverHostKeyAlgorithms: ["ssh-ed25519"]
        }))
        .mockResolvedValueOnce(clients[1].asClient());
      mockProxy();
      const dataplane = fakeDataplane();
      const { service, diagnostics } = createService({ dataplane, tun: true });
      await service.connect({ ...connectRequest("tun-moved"), tunDataplaneEnabled: true });
      await vi.advanceTimersByTimeAsync(5_000);

      clients[0].emit({ type: "close" });
      await vi.advanceTimersByTimeAsync(10);
      expect(connect.mock.calls[1][0].host).toBe("203.0.113.9");
      await vi.advanceTimersByTimeAsync(0);
      expect(service.getStatus().state).toBe("Reconnecting");
      expect(service.getStatus().message).not.toMatch(/host key|fingerprint/iu);
      expect(dataplane.stopped).toBe(1);
      expect(diagnostics.some((entry) => entry.includes("A different SSH server answers at 203.0.113.9"))).toBe(true);
      await vi.advanceTimersByTimeAsync(1_300);
      expect(connect).toHaveBeenCalledTimes(3);
      expect(connect.mock.calls[2][0].host).toBe("tun-moved.example.com");
      await vi.advanceTimersByTimeAsync(0);
      expect(service.getStatus().state).toBe("Connected");
      await service.dispose();
    });
  });

  it("keeps the local network out of the tunnel on the Windows proxy path", async () => {
    // Full tunnel through the plain listener: WinINet's bypass list cannot
    // name a private address or an IPv6 unique-local one, and a client that
    // ignores it sends the rest here too. LAN destinations still go direct.
    await withWin32(async () => {
      const lan = net.createServer((socket) => socket.end());
      await new Promise<void>((resolve) => lan.listen(0, "127.0.0.1", () => resolve()));
      const port = (lan.address() as net.AddressInfo).port;
      const client = new FakeSshClient();
      vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
      const listener = mockProxy();
      const { service } = createService();
      try {
        await service.connect(connectRequest("lan"));
        const channel = await listener.connectChannel()({ host: "127.0.0.1", port }, { address: "127.0.0.1", port: 50003 });
        expect(client.openDirectTcpIpChannel).not.toHaveBeenCalled();
        await channel.close();

        await listener.connectChannel()({ host: "api.example.com", port: 443 }, { address: "127.0.0.1", port: 50004 });
        expect(client.openDirectTcpIpChannel).toHaveBeenCalledTimes(1);
      } finally {
        await service.dispose();
        await new Promise<void>((resolve) => lan.close(() => resolve()));
      }
    });
  });

  it("tunnels the local network for an app pointed at the listener by hand", async () => {
    // macOS and Linux: nothing steers the system's traffic, so whatever
    // reaches the listener was sent to it on purpose - `ssh -D` reaches the
    // server's own network and its localhost.
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "darwin" });
    const client = new FakeSshClient();
    vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
    const listener = mockProxy();
    const { service } = createService();
    try {
      await service.connect(connectRequest("manual"));
      for (const [index, host] of ["10.0.0.5", "localhost", "jenkins", "192.168.1.1"].entries()) {
        await listener.connectChannel()({ host, port: 8080 }, { address: "127.0.0.1", port: 50010 + index });
      }
      expect(client.openDirectTcpIpChannel.mock.calls.map((call) => (call as unknown[])[0])).toEqual([
        { host: "10.0.0.5", port: 8080 },
        { host: "localhost", port: 8080 },
        { host: "jenkins", port: 8080 },
        { host: "192.168.1.1", port: 8080 }
      ]);
    } finally {
      await service.dispose();
      if (platform) {
        Object.defineProperty(process, "platform", platform);
      }
    }
  });

  it("tunnels a private address the TUN adapter sends, which a domain rule picked by a learned name", async () => {
    // wiki.corp.example resolves to 10.20.0.5 behind the server. The adapter
    // proxies ssh to it under the domain rule, by address: port 22 carries no
    // name. Sending it direct here would take it out of the tunnel and back
    // into the adapter.
    await withWin32(async () => {
      const client = new FakeSshClient("203.0.113.9");
      vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
      const listener = mockProxy();
      const dataplane = fakeDataplane();
      const { service } = createService({ dataplane, tun: true });
      try {
        await service.connect({
          ...connectRequest("tun-intranet"),
          tunDataplaneEnabled: true,
          routingMode: "selected-rules",
          routingRules: [{ id: "corp", type: "domain", value: "corp.example", enabled: true, createdAt: "", updatedAt: "" }]
        });
        expect(service.getStatus().tunActive).toBe(true);
        await listener.connectChannel()({ host: "10.20.0.5", port: 22 }, { address: "127.0.0.1", port: 50020 });
        expect(client.openDirectTcpIpChannel).toHaveBeenCalledTimes(1);
        expect((client.openDirectTcpIpChannel.mock.calls[0] as unknown[])[0]).toMatchObject({ host: "10.20.0.5", port: 22 });
      } finally {
        await service.dispose();
      }
    });
  });

  it("stops waiting for a TUN start when the user disconnects, and tries it no second time", async () => {
    // netsh can take minutes over a start the helper cannot be interrupted
    // in; Disconnect must not sit behind both attempts.
    await withWin32(async () => {
      vi.spyOn(SshLiveClient, "connect").mockResolvedValue(new FakeSshClient("203.0.113.9").asClient());
      mockProxy();
      const dataplane = fakeDataplane();
      const signals: Array<AbortSignal | undefined> = [];
      dataplane.start = (request, signal) => {
        dataplane.started.push(request);
        signals.push(signal);
        return new Promise<void>((_resolve, reject) => {
          signal?.addEventListener("abort", () => reject(new Error("Native helper start-dataplane request was abandoned.")), { once: true });
        });
      };
      const { service, diagnostics, systemProxy } = createService({ dataplane, tun: true });
      const connecting = service.connect({ ...connectRequest("tun-slow"), tunDataplaneEnabled: true });
      await vi.waitFor(() => expect(dataplane.started).toHaveLength(1));

      await service.disconnect();
      await connecting.catch(() => undefined);

      expect(service.getStatus().state).toBe("Disconnected");
      expect(dataplane.started).toHaveLength(1);
      expect(signals[0]?.aborted).toBe(true);
      // The helper still finishes that start; the teardown owes it a stop.
      expect(dataplane.stopped).toBe(1);
      expect(diagnostics.some((entry) => entry.includes("did not start on attempt"))).toBe(false);
      expect(diagnostics.some((entry) => entry.includes("TUN routing could not start"))).toBe(false);
      // And no proxy path was put on top of it.
      expect(systemProxy.apply).not.toHaveBeenCalled();
      await service.dispose();
    });
  });

  it("stops waiting for a routing update's TUN start when main queues a Disconnect behind it", async () => {
    // Main runs every intent through one queue: the Disconnect waits for the
    // routing update ahead of it, which waits for the TUN start. Only the part
    // of the disconnect that runs at once - the preempt - can cut that short.
    await withWin32(async () => {
      vi.spyOn(SshLiveClient, "connect").mockResolvedValue(new FakeSshClient("203.0.113.9").asClient());
      mockProxy();
      const dataplane = fakeDataplane();
      // TUN was unavailable at connect, so the session runs on the proxy
      // path; a routing update then tries a full start, which hangs.
      let tunAvailable = false;
      dataplane.probe = async () => (tunAvailable ? { available: true } : { available: false, reason: "wintun.dll is missing" });
      const signals: Array<AbortSignal | undefined> = [];
      dataplane.start = (request, signal) => {
        dataplane.started.push(request);
        signals.push(signal);
        return new Promise<void>((_resolve, reject) => {
          signal?.addEventListener("abort", () => reject(new Error("Native helper start-dataplane request was abandoned.")), { once: true });
        });
      };
      const { service, systemProxy } = createService({ dataplane, tun: true });
      const coordinator = new TransportMutationCoordinator();
      const request = { ...connectRequest("tun-update"), tunDataplaneEnabled: true };
      await coordinator.requestIntent(async () => {
        await service.connect(request);
      });
      expect(service.getStatus().state).toBe("Connected");
      const appliesBefore = systemProxy.apply.mock.calls.length;

      tunAvailable = true;
      const updating = coordinator.enqueue(() =>
        service.updateRouting({
          routingMode: request.routingMode,
          routingRules: request.routingRules,
          routingProxyDomains: request.routingProxyDomains,
          routingDirectDomains: request.routingDirectDomains,
          checkEndpoint: request.checkEndpoint,
          tunDataplaneEnabled: true
        })
      );
      await vi.waitFor(() => expect(dataplane.started).toHaveLength(1));
      const disconnecting = coordinator.requestIntent(
        async () => {
          await service.disconnect();
        },
        { preempt: () => service.beginDisconnect() }
      );
      expect(signals[0]?.aborted).toBe(true);
      expect(service.getStatus().state).toBe("Disconnecting");

      await updating;
      await expect(disconnecting).resolves.toBe(true);
      expect(service.getStatus().state).toBe("Disconnected");
      expect(dataplane.started).toHaveLength(1);
      // The overtaken update put no proxy path on before the teardown.
      expect(systemProxy.apply.mock.calls.length).toBe(appliesBefore);
      await service.dispose();
    });
  });

  it("leaves an idle bridge alone when a disconnect begins", () => {
    const { service } = createService();
    service.beginDisconnect();
    expect(service.getStatus().state).toBe("Disconnected");
  });

  it("tunnels a local destination a user rule names on the Windows proxy path", async () => {
    // The PAC sent 10.1.2.3 here because of the rule; the listener must not
    // take it back out of the tunnel.
    await withWin32(async () => {
      const lan = net.createServer((socket) => socket.end());
      await new Promise<void>((resolve) => lan.listen(0, "127.0.0.1", () => resolve()));
      const port = (lan.address() as net.AddressInfo).port;
      const client = new FakeSshClient();
      vi.spyOn(SshLiveClient, "connect").mockResolvedValue(client.asClient());
      const listener = mockProxy();
      const { service } = createService();
      try {
        await service.connect({
          ...connectRequest("lan-rule"),
          routingMode: "selected-rules",
          routingRules: [
            { id: "lan", type: "ip", value: "10.0.0.0/8", enabled: true, createdAt: "", updatedAt: "" },
            { id: "corp", type: "domain", value: "corp.local", enabled: true, createdAt: "", updatedAt: "" }
          ]
        });
        await listener.connectChannel()({ host: "10.1.2.3", port: 445 }, { address: "127.0.0.1", port: 50005 });
        expect(client.openDirectTcpIpChannel).toHaveBeenCalledTimes(1);
        expect((client.openDirectTcpIpChannel.mock.calls[0] as unknown[])[0]).toMatchObject({ host: "10.1.2.3", port: 445 });
        await listener.connectChannel()({ host: "wiki.corp.local", port: 443 }, { address: "127.0.0.1", port: 50006 });
        expect(client.openDirectTcpIpChannel).toHaveBeenCalledTimes(2);

        // The rest of the local network still leaves directly.
        const channel = await listener.connectChannel()({ host: "127.0.0.1", port }, { address: "127.0.0.1", port: 50007 });
        expect(client.openDirectTcpIpChannel).toHaveBeenCalledTimes(2);
        await channel.close();
      } finally {
        await service.dispose();
        await new Promise<void>((resolve) => lan.close(() => resolve()));
      }
    });
  });

  it("does not use a cached address for a different host or a literal address", async () => {
    vi.useFakeTimers();
    const client = new FakeSshClient("203.0.113.5");
    const dnsFailure = Object.assign(new Error("getaddrinfo ENOTFOUND other.example.com"), {
      code: "ENOTFOUND",
      syscall: "getaddrinfo"
    });
    const connect = vi.spyOn(SshLiveClient, "connect")
      .mockResolvedValueOnce(client.asClient())
      .mockRejectedValue(dnsFailure);
    mockProxy();
    const { service } = createService();
    await service.connect(connectRequest("dns"));
    // The session lives a while before anything happens to it.
    await vi.advanceTimersByTimeAsync(5_000);
    await service.connect(connectRequest("other"));
    expect(connect).toHaveBeenCalledTimes(2);
    expect(service.getStatus().state).toBe("Reconnecting");
    await service.dispose();
  });

  it("applies routing again at once when the TUN adapter dies under a connected session", async () => {
    // The helper's death takes the adapter and its capture routes with it,
    // and the Windows proxy setting went when TUN came up: selected traffic
    // leaves directly while the session still reads Connected.
    await withWin32(async () => {
      vi.useFakeTimers();
      vi.spyOn(SshLiveClient, "connect").mockResolvedValueOnce(new FakeSshClient("203.0.113.9").asClient());
      mockProxy();
      const dataplane = fakeDataplane();
      const { service, diagnostics } = createService({ dataplane, tun: true });
      await service.connect({ ...connectRequest("tun-death"), tunDataplaneEnabled: true });
      expect(service.getStatus().tunActive).toBe(true);

      dataplane.die("Native helper exited (3).");
      expect(service.getStatus().tunActive).toBe(false);
      await vi.advanceTimersByTimeAsync(0);

      // A fresh start brings the adapter back; the session never dropped.
      expect(dataplane.started).toHaveLength(2);
      expect(service.getStatus()).toMatchObject({ state: "Connected", tunActive: true });
      const warning = diagnostics.find((entry) => entry.startsWith("TUN dataplane stopped unexpectedly"));
      expect(warning).toContain("Native helper exited (3).");
      expect(warning).toContain("Routing is being applied again");
      await service.dispose();
    });
  });

  it("says traffic goes direct until the session is back when the adapter dies while it is down", async () => {
    // Nothing is applied again before the reconnect - the Windows proxy
    // setting went when TUN came up - so the routing hold holds nothing.
    await withWin32(async () => {
      vi.useFakeTimers();
      const client = new FakeSshClient("203.0.113.9");
      vi.spyOn(SshLiveClient, "connect")
        .mockResolvedValueOnce(client.asClient())
        .mockRejectedValue(new Error("connect ECONNREFUSED 203.0.113.9:22"));
      mockProxy();
      const dataplane = fakeDataplane();
      const { service, diagnostics } = createService({ dataplane, tun: true });
      await service.connect({ ...connectRequest("tun-death-held"), tunDataplaneEnabled: true });
      expect(service.getStatus().tunActive).toBe(true);

      client.emit({ type: "close" });
      expect(service.getStatus().state).toBe("Reconnecting");
      dataplane.die("Native helper exited (3).");

      const warning = diagnostics.find((entry) => entry.startsWith("TUN dataplane stopped unexpectedly"));
      expect(warning).toContain("Routing is applied again when the session is back");
      expect(warning).toContain("Until then apps connect directly.");
      expect(warning).not.toContain("Routing is being applied again");
      await service.dispose();
    });
  });

  it("falls back to the proxy path for the session once the adapter keeps dying", async () => {
    await withWin32(async () => {
      vi.useFakeTimers();
      vi.spyOn(SshLiveClient, "connect").mockResolvedValueOnce(new FakeSshClient("203.0.113.9").asClient());
      mockProxy();
      const dataplane = fakeDataplane();
      const { service, diagnostics, systemProxy } = createService({ dataplane, tun: true });
      await service.connect({ ...connectRequest("tun-flap"), tunDataplaneEnabled: true });
      expect(systemProxy.apply).not.toHaveBeenCalled();

      for (let death = 0; death < 3; death += 1) {
        dataplane.die("the adapter read failed");
        await vi.advanceTimersByTimeAsync(0);
      }

      // Two deaths were answered with a restart; the third ends the loop of
      // adapters coming and going, and the proxy path takes over.
      expect(dataplane.started).toHaveLength(3);
      expect(dataplane.isActive).toBe(false);
      expect(systemProxy.apply).toHaveBeenCalledTimes(1);
      expect(service.getStatus()).toMatchObject({ state: "Connected", tunActive: false });
      expect(diagnostics.some((entry) => entry.includes("Routing continues on the Windows proxy path"))).toBe(true);
      expect(diagnostics.some((entry) => entry.startsWith("TUN routing is unavailable") && entry.includes("stopped unexpectedly 3 times"))).toBe(true);
      await service.dispose();
    });
  });

  it("does not hold an adapter whose helper died while the session was down", async () => {
    await withWin32(async () => {
      vi.useFakeTimers();
      const clients = [new FakeSshClient("203.0.113.9"), new FakeSshClient("203.0.113.9")];
      const connect = vi.spyOn(SshLiveClient, "connect")
        .mockResolvedValueOnce(clients[0].asClient())
        .mockResolvedValueOnce(clients[1].asClient());
      mockProxy();
      const dataplane = fakeDataplane();
      const { service } = createService({ dataplane, tun: true });
      await service.connect({ ...connectRequest("tun-dead-hold"), tunDataplaneEnabled: true });
      await vi.advanceTimersByTimeAsync(5_000);

      clients[0].emit({ type: "close" });
      // The adapter is gone without a word (a controller that could not
      // report it); the hold has to check for itself.
      dataplane.isActive = false;
      await vi.advanceTimersByTimeAsync(10);
      await vi.advanceTimersByTimeAsync(0);

      // Nothing captures traffic any more, so there is no adapter to keep:
      // the server is reached the ordinary way and the adapter is rebuilt,
      // instead of reporting Connected with no routing at all.
      expect(connect.mock.calls[1][0].host).toBe("tun-dead-hold.example.com");
      expect(dataplane.started).toHaveLength(2);
      expect(service.getStatus()).toMatchObject({ state: "Connected", tunActive: true });
      await service.dispose();
    });
  });

  it("arms the routing hold when an attempt fails after routing went in", async () => {
    vi.useFakeTimers();
    vi.spyOn(SshLiveClient, "connect").mockImplementation(async () => new FakeSshClient().asClient());
    mockProxy();
    const { service, systemProxy } = createService();
    systemProxy.apply.mockRejectedValue(new Error("proxy apply failed"));
    await service.connect(connectRequest("routing-fails"));
    // A user Connect starts from direct routing: that is the one restore.
    expect(systemProxy.restore).toHaveBeenCalledTimes(1);
    expect(service.getStatus().state).toBe("Reconnecting");

    // The half-applied routing is kept for the retries, but only for the
    // hold window the UI promises; then the machine goes direct.
    await vi.advanceTimersByTimeAsync(29_000);
    expect(systemProxy.restore).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1_500);
    expect(systemProxy.restore).toHaveBeenCalledTimes(2);
    await service.dispose();
  });

  it("cancels a connect that hangs when the user disconnects", async () => {
    vi.useFakeTimers();
    let connectSignal: AbortSignal | undefined;
    vi.spyOn(SshLiveClient, "connect").mockImplementation((_options, signal) => {
      connectSignal = signal;
      return new Promise<SshLiveClient>((_resolve, reject) => {
        signal?.addEventListener("abort", () => reject(Object.assign(new Error("SSH connect was cancelled."), { name: "AbortError" })));
      });
    });
    mockProxy();
    const { service, diagnostics } = createService();
    const connecting = service.connect(connectRequest("hanging"));
    await vi.advanceTimersByTimeAsync(0);
    expect(connectSignal?.aborted).toBe(false);

    // No timer is advanced: the disconnect must not wait out the connect's
    // own timeouts behind the mutation queue.
    await service.disconnect();
    await connecting;
    expect(connectSignal?.aborted).toBe(true);
    expect(service.getStatus().state).toBe("Disconnected");
    // The cancelled attempt belongs to a superseded lifecycle and says nothing.
    expect(diagnostics.some((entry) => entry.includes("cancelled"))).toBe(false);
    await service.dispose();
  });
});

class FakeSshClient {
  private listener: ((event: SshLiveClientEvent) => void) | undefined;
  readonly disconnect = vi.fn(async () => undefined);
  readonly openShell = vi.fn(async () => undefined);
  readonly closeShell = vi.fn(async () => undefined);
  readonly writeShell = vi.fn(async () => undefined);
  readonly probeLiveness = vi.fn<(timeoutMs?: number) => Promise<void>>(async () => undefined);
  readonly openDirectTcpIpChannel = vi.fn(async () => fakeChannel(this));

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

function fakeChannel(owner: FakeSshClient): DirectTcpIpChannel & { owner: FakeSshClient } {
  return {
    owner,
    write: async () => undefined,
    close: async () => undefined,
    onData: () => () => undefined,
    onEnd: () => () => undefined,
    onClose: () => () => undefined,
    onError: () => () => undefined
  };
}

type ConnectChannel = Socks5ProxyOptions["connectChannel"];

/**
 * Mocks the listener and captures the `connectChannel` callback the service
 * hands it, so a test can play an accepted proxy connection.
 */
function mockProxy(): { connectChannel: () => ConnectChannel } {
  let captured: ConnectChannel | undefined;
  vi.spyOn(Socks5Proxy.prototype, "start").mockImplementation(async function (this: Socks5Proxy) {
    captured = (this as unknown as { options: Socks5ProxyOptions }).options.connectChannel;
    return { host: "127.0.0.1", port: 31090 };
  });
  vi.spyOn(Socks5Proxy.prototype, "stop").mockResolvedValue();
  return {
    connectChannel: () => {
      if (!captured) {
        throw new Error("the listener was never started");
      }
      return captured;
    }
  };
}

function createService(
  options: { dataplane?: DataplaneController; tun?: boolean } = {}
): { service: LiveSshServiceBridge; diagnostics: string[]; systemProxy: { apply: ReturnType<typeof vi.fn>; restore: ReturnType<typeof vi.fn> } } {
  const proxy = {
    apply: vi.fn(async () => ({ applied: true, message: "applied" })),
    restore: vi.fn(async () => undefined)
  };
  const systemProxy = proxy as unknown as WindowsSystemProxyManager;
  const service = new LiveSshServiceBridge(initialStatus(), {
    systemProxy,
    systemWakeDetection: false,
    ...(options.tun
      ? {
          dataplane: options.dataplane,
          processConnectionsProvider: async () => [],
          processDnsEntriesProvider: async () => [],
          protectedAddressResolver: async () => ["203.0.113.9"]
        }
      : {})
  });
  const diagnostics: string[] = [];
  service.onEvent((event: ServiceEvent) => {
    if (event.type === "diagnostics-appended") {
      diagnostics.push(event.entry.message);
    }
  });
  return { service, diagnostics, systemProxy: proxy };
}

function connectRequest(id: string): ConnectRequest {
  return {
    config: {
      id,
      name: id,
      host: `${id}.example.com`,
      port: 22,
      username: "user",
      authType: "password",
      expectedServerFingerprint: "SHA256:test",
      keepaliveIntervalSec: 60,
      note: "",
      createdAt: "",
      updatedAt: ""
    },
    routingMode: "proxy-all",
    routingRules: [],
    routingProxyDomains: [],
    routingDirectDomains: [],
    checkEndpoint: "example.com:443",
    secrets: { password: "secret" }
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

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void; reject(error: Error): void } {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((innerResolve, innerReject) => {
    resolve = innerResolve;
    reject = innerReject;
  });
  return { promise, resolve, reject };
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
