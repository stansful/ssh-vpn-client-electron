import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { SshLiveClient, hostKeysPresentedBeforeFailure, type SshLiveClientOptions } from "../src/core/ssh/live-client.js";
import { DEFAULT_KEX_INIT } from "../src/core/ssh/messages.js";
import { SshHostKeyMismatchError } from "../src/core/ssh/session-state.js";
import { createFakeHostKeys, FakeSshServer, type FakeHostKeys, type FakeServerOptions } from "./ssh-fake-server.js";

let hostKeys: FakeHostKeys;
const servers: FakeSshServer[] = [];
const clients: SshLiveClient[] = [];

beforeAll(() => {
  hostKeys = createFakeHostKeys();
});

afterEach(async () => {
  vi.useRealTimers();
  for (const client of clients.splice(0)) {
    client.destroy();
  }
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function startServer(options: Omit<FakeServerOptions, "hostKeys"> = {}): Promise<FakeSshServer> {
  const server = await FakeSshServer.start({ hostKeys, ...options });
  servers.push(server);
  return server;
}

async function connect(server: FakeSshServer, overrides: Partial<SshLiveClientOptions> = {}, signal?: AbortSignal): Promise<SshLiveClient> {
  const client = await SshLiveClient.connect(
    {
      host: "127.0.0.1",
      port: server.port,
      username: "alice",
      password: "secret",
      connectTimeoutMs: 5_000,
      operationTimeoutMs: 5_000,
      keepaliveIntervalSec: 0,
      rekeyIntervalMs: 0,
      rekeyAfterBytes: 0,
      ...overrides
    },
    signal
  );
  clients.push(client);
  return client;
}

describe("SSH host key algorithm preference", () => {
  it("asks for the Ed25519 host key first, then the RSA signature algorithms", () => {
    expect(DEFAULT_KEX_INIT.serverHostKeyAlgorithms).toEqual(["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"]);
  });

  it("verifies the Ed25519 key of a stock server without a pin and reports it", async () => {
    const server = await startServer();
    const client = await connect(server);

    expect(server.connections).toHaveLength(1);
    expect(server.connections[0].negotiatedHostKeyAlgorithms).toEqual(["ssh-ed25519"]);
    expect(client.hostKeyFingerprint).toBe(hostKeys.ed25519.fingerprint);
    expect(client.hostKeyAlgorithm).toBe("ssh-ed25519");
  });

  it("still talks to a server that only has an RSA host key", async () => {
    const server = await startServer({ hostKeyAlgorithms: ["rsa-sha2-256"] });
    const client = await connect(server);

    expect(server.connections[0].negotiatedHostKeyAlgorithms).toEqual(["rsa-sha2-256"]);
    expect(client.hostKeyFingerprint).toBe(hostKeys.rsa.fingerprint);
    expect(client.hostKeyAlgorithm).toBe("ssh-rsa");
  });
});

describe("SSH host key fallback for a pinned fingerprint", () => {
  it("connects once when the pin is the Ed25519 key the server shows first", async () => {
    const server = await startServer();
    const client = await connect(server, { expectedServerFingerprint: hostKeys.ed25519.fingerprint });

    expect(server.connections).toHaveLength(1);
    expect(client.hostKeyAlgorithm).toBe("ssh-ed25519");
  });

  it("keeps an RSA pin working: retries for the RSA key on a fresh connection before signing in", async () => {
    const server = await startServer();
    const client = await connect(server, { expectedServerFingerprint: hostKeys.rsa.fingerprint });

    expect(server.connections).toHaveLength(2);
    const [first, second] = server.connections;
    expect(first.clientHostKeyAlgorithms).toEqual([["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"]]);
    expect(first.negotiatedHostKeyAlgorithms).toEqual(["ssh-ed25519"]);
    expect(first.serviceRequested).toBe(false);
    expect(first.authenticated).toBe(false);
    await first.closed;

    expect(second.clientHostKeyAlgorithms).toEqual([["rsa-sha2-512", "rsa-sha2-256"]]);
    expect(second.negotiatedHostKeyAlgorithms).toEqual(["rsa-sha2-512"]);
    expect(second.authenticated).toBe(true);
    expect(client.hostKeyFingerprint).toBe(hostKeys.rsa.fingerprint);
    expect(client.hostKeyAlgorithm).toBe("ssh-rsa");

    // A rekey asks for the same key type again, so the session keeps its key.
    await client.rekey();
    expect(second.clientHostKeyAlgorithms[1]).toEqual(["rsa-sha2-512", "rsa-sha2-256"]);
    expect(second.negotiatedHostKeyAlgorithms[1]).toBe("rsa-sha2-512");
    await vi.waitFor(() => expect(second.keyExchanges).toBe(2));
  });

  it("connects once for an RSA pin when told the pin is an RSA key, and keeps the fallback", async () => {
    const server = await startServer();
    const client = await connect(server, { expectedServerFingerprint: hostKeys.rsa.fingerprint, preferredHostKeyType: "ssh-rsa" });

    expect(server.connections).toHaveLength(1);
    expect(server.connections[0].clientHostKeyAlgorithms).toEqual([["rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519"]]);
    expect(client.hostKeyAlgorithm).toBe("ssh-rsa");
    await client.rekey();
    expect(server.connections[0].negotiatedHostKeyAlgorithms[1]).toBe("rsa-sha2-512");

    // The preference says what the pin is: a key of that type that does not
    // match is another key, and no other type is asked for.
    const other = await startServer();
    const failure = await connect(other, { expectedServerFingerprint: hostKeys.ed25519.fingerprint, preferredHostKeyType: "ssh-rsa" })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(SshHostKeyMismatchError);
    expect(other.connections).toHaveLength(1);
  });

  it("stops at a key of the pin's known type that does not match, so a dropped second connection cannot hide it", async () => {
    // An impostor shows its own Ed25519 key where the pinned Ed25519 key was
    // expected, and offers RSA too. A retry for RSA could only fail - and a
    // reset or stalled retry used to replace the mismatch with an ordinary,
    // endlessly retried network error.
    const impostor = await startServer({ stall: (index) => (index >= 1 ? "identification" : undefined) });
    const pin = `SHA256:${"A".repeat(43)}`;

    const failure = await connect(impostor, { expectedServerFingerprint: pin, preferredHostKeyType: "ssh-ed25519" })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SshHostKeyMismatchError);
    expect((failure as Error).message).toBe(
      `SSH server fingerprint mismatch: expected ${pin}, got ${hostKeys.ed25519.fingerprint} (ssh-ed25519).`
    );
    expect(impostor.connections).toHaveLength(1);
    expect(impostor.connections[0].serviceRequested).toBe(false);
  });

  it("keeps a failed retry for a pin of unknown type retryable, but has it carry the key that did not match", async () => {
    // Without the pin's type the second connection may be the server's real
    // RSA key dropped by the network, so its failure stays an ordinary one;
    // the service still learns which key was presented before it.
    const impostor = await startServer({ stall: (index) => (index >= 1 ? "identification" : undefined) });
    const pin = `SHA256:${"A".repeat(43)}`;

    const failure = await connect(impostor, { expectedServerFingerprint: pin, connectTimeoutMs: 300 }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(Error);
    expect(failure).not.toBeInstanceOf(SshHostKeyMismatchError);
    expect((failure as Error).message).not.toMatch(/host key|fingerprint/iu);
    expect(hostKeysPresentedBeforeFailure(failure)).toEqual([{ fingerprint: hostKeys.ed25519.fingerprint, keyType: "ssh-ed25519" }]);
    expect(impostor.connections).toHaveLength(2);
    expect(impostor.connections.some((connection) => connection.serviceRequested)).toBe(false);
    // Any other failure carries nothing.
    expect(hostKeysPresentedBeforeFailure(new Error("Timed out waiting for SSH identification."))).toEqual([]);
    expect(hostKeysPresentedBeforeFailure(undefined)).toEqual([]);
  });

  it("fails with the mismatch, naming every key it saw, when no key type matches", async () => {
    const server = await startServer();
    const pin = `SHA256:${"A".repeat(43)}`;

    const failure = await connect(server, { expectedServerFingerprint: pin }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SshHostKeyMismatchError);
    const mismatch = failure as SshHostKeyMismatchError;
    expect(mismatch.message).toMatch(/^SSH server fingerprint mismatch: expected /u);
    expect(mismatch.message).toContain(`${hostKeys.ed25519.fingerprint} (ssh-ed25519)`);
    expect(mismatch.message).toContain(`${hostKeys.rsa.fingerprint} (ssh-rsa)`);
    expect(mismatch.presentedHostKeys.map((key) => key.keyType)).toEqual(["ssh-ed25519", "ssh-rsa"]);
    expect(server.connections).toHaveLength(2);
    expect(server.connections.some((connection) => connection.serviceRequested)).toBe(false);
  });

  it("does not retry when the server offers no other key type", async () => {
    const server = await startServer({ hostKeyAlgorithms: ["ssh-ed25519"] });

    await expect(connect(server, { expectedServerFingerprint: hostKeys.rsa.fingerprint })).rejects.toThrow(
      `SSH server fingerprint mismatch: expected ${hostKeys.rsa.fingerprint}, got ${hostKeys.ed25519.fingerprint} (ssh-ed25519).`
    );
    expect(server.connections).toHaveLength(1);
  });

  it("does not let the retry outlast the time one attempt may take before authentication", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    const budgetMs = 1_000 + 1_000 + 4 * 1_000;
    const startedAt = Date.now();
    const server = await startServer({
      stall: (index) => (index === 1 ? "kex-reply" : undefined),
      onClientKexInit: (connection) => {
        if (connection.index === 0) {
          // The first attempt was slow: only 50 ms of the budget are left.
          vi.setSystemTime(startedAt + budgetMs - 50);
        }
      }
    });

    const connecting = connect(server, {
      expectedServerFingerprint: hostKeys.rsa.fingerprint,
      connectTimeoutMs: 1_000,
      operationTimeoutMs: 1_000
    });
    const failure = connecting.catch((error: unknown) => error);
    // Real I/O, fake clock: poll on setImmediate, which stays real.
    await until(() => server.connections[1]?.clientHostKeyAlgorithms.length === 1);
    await vi.advanceTimersByTimeAsync(60);

    const error = (await failure) as Error;
    expect(error.message).toBe("SSH connect timed out before the key exchange finished.");
    // Retryable: the slow retry says nothing about the pin.
    expect(error.message).not.toMatch(/host key|fingerprint/iu);
    await server.connections[1].closed;
  });

  it("does not start a retry once that time is used up", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    const startedAt = Date.now();
    const server = await startServer({
      onClientKexInit: () => vi.setSystemTime(startedAt + 6_000)
    });

    await expect(
      connect(server, { expectedServerFingerprint: hostKeys.rsa.fingerprint, connectTimeoutMs: 1_000, operationTimeoutMs: 1_000 })
    ).rejects.toThrow("SSH connect timed out before the key exchange finished.");
    expect(server.connections).toHaveLength(1);
  });
});

describe("SSH connect cancellation", () => {
  it("rejects at once and opens no connection when already aborted", async () => {
    const server = await startServer();
    const controller = new AbortController();
    controller.abort();

    await expect(connect(server, {}, controller.signal)).rejects.toMatchObject({ name: "AbortError" });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(server.connections).toHaveLength(0);
  });

  it("stops a TCP connect that is still in flight", async () => {
    const server = await startServer();
    const controller = new AbortController();

    const connecting = connect(server, {}, controller.signal);
    controller.abort();

    await expect(connecting).rejects.toMatchObject({ name: "AbortError", message: "SSH connect was cancelled." });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(server.connections.every((connection) => !connection.identified || connection.clientHostKeyAlgorithms.length === 0)).toBe(true);
  });

  it.each(["identification", "kex-reply", "auth"] as const)("stops promptly while the server stalls at %s", async (stage) => {
    const server = await startServer({ stall: () => stage });
    const controller = new AbortController();
    const connecting = connect(server, { connectTimeoutMs: 30_000, operationTimeoutMs: 30_000 }, controller.signal);
    const failure = connecting.catch((error: unknown) => error);

    await vi.waitFor(() => {
      const connection = server.connections[0];
      expect(connection).toBeDefined();
      if (stage === "kex-reply") {
        expect(connection.clientHostKeyAlgorithms).toHaveLength(1);
      }
      if (stage === "auth") {
        expect(connection.serviceRequested).toBe(true);
      }
    });
    if (stage === "auth") {
      // Give the USERAUTH_REQUEST time to reach the stalled server.
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const abortedAt = Date.now();
    controller.abort();

    const error = (await failure) as Error;
    expect(error.name).toBe("AbortError");
    expect(Date.now() - abortedAt).toBeLessThan(1_000);
    await server.connections[0].closed;
  });

  it("leaves an established session alone when the signal aborts later", async () => {
    const server = await startServer();
    const controller = new AbortController();
    const client = await connect(server, {}, controller.signal);

    controller.abort();
    await client.rekey();
    await vi.waitFor(() => expect(server.connections[0].keyExchanges).toBe(2));
  });
});

describe("SSH client-initiated rekey under load", () => {
  it("keeps delivering channel data the server sent before its KEXINIT and holds window adjusts until NEWKEYS", async () => {
    // More packets than the old rekey queue allowed (2048), and more bytes
    // than half the channel window, so acknowledging them owes the server a
    // window adjust in the middle of the key exchange.
    const burst = { packets: 2_100, bytes: 4_096 };
    const server = await startServer({ rekeyBurst: burst });
    const client = await connect(server);
    const errors: string[] = [];
    client.onEvent((event) => {
      if (event.type === "error") {
        errors.push(event.error.message);
      }
    });
    const channel = await client.openDirectTcpIpChannel({ host: "example.com", port: 443 }, { address: "127.0.0.1", port: 50_000 });
    let receivedBytes = 0;
    let outOfOrder = 0;
    let packetIndex = 0;
    channel.onData((data) => {
      for (let offset = 0; offset < data.length; offset += burst.bytes) {
        if (data[offset] !== (packetIndex & 0xff)) {
          outOfOrder += 1;
        }
        packetIndex += 1;
      }
      receivedBytes += data.length;
      void channel.acknowledgeData?.(data.length);
    });

    await client.rekey();

    const connection = server.connections[0];
    expect(errors).toEqual([]);
    expect(receivedBytes).toBe(burst.packets * burst.bytes);
    expect(outOfOrder).toBe(0);
    await vi.waitFor(() => expect(connection.windowAdjusts).toBeGreaterThan(0));
    expect(connection.keyExchanges).toBe(2);
    expect(connection.kexViolations).toEqual([]);
  });
});

async function until(condition: () => boolean, limitMs = 5_000): Promise<void> {
  const startedAt = performance.now();
  while (!condition()) {
    if (performance.now() - startedAt > limitMs) {
      throw new Error("Condition was not met in time.");
    }
    await new Promise((resolve) => setImmediate(resolve));
  }
}
