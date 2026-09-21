import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { Socks5Proxy } from "../src/core/network/socks5-proxy.js";
import { MemoryDirectTcpIpChannel } from "../src/core/network/memory-direct-channel.js";

const proxies: Socks5Proxy[] = [];

afterEach(async () => {
  while (proxies.length > 0) {
    await proxies.pop()!.stop().catch(() => undefined);
  }
});

function once(emitter: net.Socket, event: string): Promise<void> {
  return new Promise((resolve) => emitter.once(event, () => resolve()));
}

/** Reads until `marker` has been seen, returning everything received. */
function readUntil(socket: net.Socket, marker: string): Promise<Buffer> {
  return new Promise((resolve) => {
    let buffer = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.toString("latin1").includes(marker)) {
        socket.off("data", onData);
        resolve(buffer);
      }
    };
    socket.on("data", onData);
  });
}

describe("socks5 proxy stats", () => {
  // These counters back the heartbeat that makes a data-plane stall legible, so
  // they have to move with real traffic in both directions.
  it("counts accepted, established, and bytes each way through a real connection", async () => {
    const channel = new MemoryDirectTcpIpChannel();
    const proxy = new Socks5Proxy({
      listenHost: "127.0.0.1",
      connectChannel: async () => channel
    });
    proxies.push(proxy);
    const endpoint = await proxy.start();

    expect(proxy.snapshotStats()).toMatchObject({ active: 0, accepted: 0, established: 0, bytesToClient: 0, bytesToChannel: 0 });

    const client = net.connect(endpoint.port, endpoint.host);
    await once(client, "connect");
    client.write("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
    await readUntil(client, "\r\n\r\n");

    // Upload: bytes from the client are forwarded into the channel.
    client.write(Buffer.alloc(1024, 0x61));
    await waitFor(() => channel.written.reduce((sum, part) => sum + part.length, 0) >= 1024);

    // Download: bytes the channel produces are written back to the client.
    const downloaded = readUntil(client, "DONE");
    channel.pushRemoteData(Buffer.concat([Buffer.alloc(2048, 0x62), Buffer.from("DONE")]));
    await downloaded;

    const stats = proxy.snapshotStats();
    expect(stats.accepted).toBe(1);
    expect(stats.established).toBe(1);
    expect(stats.active).toBe(1);
    expect(stats.bytesToChannel).toBe(1024);
    expect(stats.bytesToClient).toBe(2048 + 4);

    client.destroy();
    await waitFor(() => proxy.snapshotStats().active === 0);
    expect(proxy.snapshotStats().active).toBe(0);
    // Monotonic totals survive the close; only `active` falls back to zero.
    expect(proxy.snapshotStats().accepted).toBe(1);
  });
});

async function waitFor(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const startedAt = Date.now();
  while (!predicate()) {
    if (Date.now() - startedAt > timeoutMs) {
      throw new Error("Condition not met within timeout.");
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}
