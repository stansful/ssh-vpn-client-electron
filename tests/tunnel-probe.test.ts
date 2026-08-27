import { describe, expect, it } from "vitest";
import { MemoryDirectTcpIpChannel } from "../src/core/network/memory-direct-channel.js";
import type { DirectTcpIpChannel } from "../src/core/network/local-tcp-proxy.js";
import { buildTlsClientHello, probeTunnelEndpoint } from "../src/core/network/tunnel-probe.js";

/** A channel that answers a write on the next tick, the way a peer would. */
class ScriptedChannel extends MemoryDirectTcpIpChannel {
  constructor(private readonly reply: Buffer | "close" | "silence") {
    super();
  }

  override async write(data: Buffer): Promise<void> {
    await super.write(data);
    this.respond();
  }

  respond(): void {
    const reply = this.reply;
    if (reply === "silence") {
      return;
    }
    setTimeout(() => {
      if (reply === "close") {
        void this.close();
        return;
      }
      this.pushRemoteData(reply);
    }, 0);
  }
}

const serverHello = Buffer.from([0x16, 0x03, 0x03, 0x00, 0x2a, 0x02]);
const tlsAlert = Buffer.from([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);

function open(channel: DirectTcpIpChannel): () => Promise<DirectTcpIpChannel> {
  return async () => channel;
}

describe("tunnel probe", () => {
  it("passes only when the far end answers, not when the tunnel merely accepts the connection", async () => {
    const channel = new ScriptedChannel(serverHello);
    const result = await probeTunnelEndpoint(open(channel), { host: "youtube.com", port: 443 });
    expect(result.outcome).toBe("tls");
    expect(result.detail).toContain("answered the TLS handshake");
    expect(channel.written[0]?.[0]).toBe(0x16);
  });

  // The failure this check exists to catch: Xray answers the SOCKS CONNECT as
  // soon as it has picked an outbound, so a dead outbound used to look healthy.
  it("fails when the tunnel opens the connection but nothing comes back", async () => {
    const channel = new ScriptedChannel("silence");
    await expect(
      probeTunnelEndpoint(open(channel), { host: "youtube.com", port: 443 }, { timeoutMs: 25 })
    ).rejects.toThrow(/nothing came back/u);
  });

  it("fails when the far end closes without answering", async () => {
    const channel = new ScriptedChannel("close");
    await expect(
      probeTunnelEndpoint(open(channel), { host: "youtube.com", port: 443 }, { timeoutMs: 500 })
    ).rejects.toThrow(/nothing came back/u);
  });

  // An alert is still proof that both directions carried bytes, so it must not
  // be reported as a broken tunnel.
  it("treats a TLS alert as a working tunnel and says so", async () => {
    const result = await probeTunnelEndpoint(open(new ScriptedChannel(tlsAlert)), { host: "youtube.com", port: 443 });
    expect(result.outcome).toBe("tls-alert");
    expect(result.detail).toContain("the tunnel carries data");
  });

  it("flags non-TLS bytes on a TLS port instead of passing them silently", async () => {
    const result = await probeTunnelEndpoint(
      open(new ScriptedChannel(Buffer.from("blocked by policy", "utf8"))),
      { host: "youtube.com", port: 443 }
    );
    expect(result.outcome).toBe("bytes");
    expect(result.detail).toContain("not a TLS record");
  });

  it("speaks HTTP on an HTTP port and reports the status line", async () => {
    const channel = new ScriptedChannel(Buffer.from("HTTP/1.1 301 Moved Permanently\r\n\r\n", "utf8"));
    const result = await probeTunnelEndpoint(open(channel), { host: "example.com", port: 80 });
    expect(channel.written[0]?.toString("utf8")).toMatch(/^HEAD \/ HTTP\/1\.1\r\nHost: example\.com\r\n/u);
    expect(result.outcome).toBe("http");
    expect(result.detail).toContain("301 Moved Permanently");
  });

  // Guessing a protocol for an arbitrary port would produce a failure that says
  // nothing about the tunnel, so the check reports honestly instead.
  it("sends nothing on an unknown port and reports it as unverified", async () => {
    const channel = new ScriptedChannel("silence");
    const result = await probeTunnelEndpoint(open(channel), { host: "srv.example.com", port: 9001 }, { timeoutMs: 25 });
    expect(channel.written).toHaveLength(0);
    expect(result.outcome).toBe("unverified");
    expect(result.detail).toContain("could not be verified end to end");
  });

  it("closes the channel whether the probe passes or fails", async () => {
    const passing = new ScriptedChannel(serverHello);
    await probeTunnelEndpoint(open(passing), { host: "youtube.com", port: 443 });
    await expect(passing.write(Buffer.from("x"))).rejects.toThrow(/closed/u);

    const failing = new ScriptedChannel("silence");
    await probeTunnelEndpoint(open(failing), { host: "youtube.com", port: 443 }, { timeoutMs: 25 }).catch(() => undefined);
    await expect(failing.write(Buffer.from("x"))).rejects.toThrow(/closed/u);
  });
});

describe("TLS client hello", () => {
  it("carries SNI for a host name and omits it for an address literal", () => {
    const named = buildTlsClientHello("youtube.com");
    expect(named.includes(Buffer.from("youtube.com", "utf8"))).toBe(true);
    expect(named[0]).toBe(0x16);
    expect(buildTlsClientHello("93.184.216.34").length).toBeLessThan(named.length);
    expect(buildTlsClientHello("2606:4700::1111")[0]).toBe(0x16);
  });

  // Without a key share a TLS 1.3 server answers `handshake_failure` rather
  // than a ServerHello, which reads like a broken endpoint rather than a
  // healthy tunnel.
  it("offers an x25519 key share so a TLS 1.3 server can complete a handshake", () => {
    const hello = buildTlsClientHello("youtube.com");
    // key_share (0x0033), 38 bytes of extension data, one x25519 (0x001d)
    // entry of 32 bytes.
    expect(hello.includes(Buffer.from([0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]))).toBe(true);
  });

  it("declares a length that matches the record it produced", () => {
    const hello = buildTlsClientHello("youtube.com");
    expect(hello.readUInt16BE(3)).toBe(hello.length - 5);
    expect(hello[5]).toBe(0x01);
    expect((hello[6] << 16) | (hello[7] << 8) | hello[8]).toBe(hello.length - 9);
  });
});
