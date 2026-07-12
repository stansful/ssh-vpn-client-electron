import { EventEmitter } from "node:events";
import type { Socket } from "node:net";
import { runInNewContext } from "node:vm";
import { describe, expect, it, vi } from "vitest";
import { MemoryDirectTcpIpChannel } from "../src/core/network/memory-direct-channel.js";
import { LocalTcpProxy, type DirectTcpIpChannel } from "../src/core/network/local-tcp-proxy.js";
import { Socks5Proxy, formatProxyTunnelError, readProxyConnectRequest, readSocksConnectRequest } from "../src/core/network/socks5-proxy.js";
import { buildProxyPac } from "../src/core/network/windows-system-proxy.js";
import { normalizeProxyDomain, parseDomainProxyList } from "../src/core/routing/domain-proxy-list.js";
import {
  DEFAULT_PROXY_CONNECTION_QUEUE_BYTES,
  DEFAULT_PROXY_TOTAL_QUEUE_BYTES
} from "../src/core/network/socket-io.js";

describe("proxy memory policy", () => {
  it("keeps one full SSH receive window but bounds aggregate stalled downloads", () => {
    expect(DEFAULT_PROXY_CONNECTION_QUEUE_BYTES).toBe(16 * 1024 * 1024);
    expect(DEFAULT_PROXY_TOTAL_QUEUE_BYTES).toBe(64 * 1024 * 1024);
  });
});

describe("SOCKS5 proxy", () => {
  it("parses no-auth CONNECT requests for direct-tcpip channel opening", async () => {
    const socket = new FlowingFakeSocket() as unknown as Socket;
    const request = readSocksConnectRequest(socket);
    const fake = socket as unknown as FlowingFakeSocket;

    fake.pushInput(Buffer.from([0x05, 0x01]));
    await Promise.resolve();
    fake.pushInput(Buffer.from([0x00]));
    await waitForParser();
    expect(fake.writes).toEqual([Buffer.from([0x05, 0x00])]);

    const host = Buffer.from("example.com", "utf8");
    fake.pushInput(Buffer.from([0x05, 0x01, 0x00, 0x03]));
    await Promise.resolve();
    fake.pushInput(Buffer.from([host.length]));
    await Promise.resolve();
    fake.pushInput(host);
    await Promise.resolve();
    fake.pushInput(Buffer.from([0x01, 0xbb]));
    await expect(request).resolves.toEqual({ host: "example.com", port: 443 });
  });

  it("parses HTTP CONNECT requests from Windows system proxy clients", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

    fake.pushInput(Buffer.from("C", "utf8"));
    await Promise.resolve();
    fake.pushInput(Buffer.from("ONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", "utf8"));

    await expect(request).resolves.toEqual({
      protocol: "http-connect",
      target: { host: "example.com", port: 443 }
    });
  });

  it("parses HTTP CONNECT requests delivered in one TCP chunk", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

    fake.pushInput(Buffer.from("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", "utf8"));

    await expect(request).resolves.toEqual({
      protocol: "http-connect",
      target: { host: "example.com", port: 443 }
    });
  });

  it("classifies malformed HTTP handshakes as HTTP and flushes a 502 response", async () => {
    const connectChannel = vi.fn(async () => new MemoryDirectTcpIpChannel());
    const proxy = new Socks5Proxy({ listenPort: 0, connectChannel });
    const socket = new FlowingFakeSocket() as unknown as Socket;
    const handling = (proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(socket);
    const fake = socket as unknown as FlowingFakeSocket;

    fake.pushInput(Buffer.from("GET /missing-host HTTP/1.1\r\nUser-Agent: test\r\n\r\n", "latin1"));
    await handling;

    expect(Buffer.concat(fake.writes).toString("latin1")).toContain("HTTP/1.1 502 Bad Gateway");
    expect(connectChannel).not.toHaveBeenCalled();
  });

  it("rejects an oversized HTTP header even when its terminator is in the same chunk", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

    fake.pushInput(
      Buffer.from(
        `CONNECT example.com:443 HTTP/1.1\r\nX-Oversized: ${"x".repeat(66 * 1024)}\r\n\r\n`,
        "latin1"
      )
    );

    await expect(request).rejects.toThrow("HTTP proxy request header is too large");
  });

  it("preserves early bytes sent with an HTTP CONNECT header", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

    fake.pushInput(Buffer.from("C", "utf8"));
    await Promise.resolve();
    fake.pushInput(Buffer.from("ONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nEARLY", "utf8"));

    await expect(request).resolves.toEqual({
      protocol: "http-connect",
      target: { host: "example.com", port: 443 },
      initialData: Buffer.from("EARLY", "utf8")
    });
  });

  it("does not lose queued chunks while a fragmented HTTP handshake is parsed", async () => {
    const socket = new FlowingFakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FlowingFakeSocket;

    fake.pushInput(Buffer.from("C", "latin1"));
    fake.pushInput(Buffer.from("ONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n", "latin1"));
    fake.pushInput(Buffer.from("\r\nEARLY-BYTES", "latin1"));

    await expect(request).resolves.toEqual({
      protocol: "http-connect",
      target: { host: "example.com", port: 443 },
      initialData: Buffer.from("EARLY-BYTES", "latin1")
    });
  });

  it("parses SOCKS5 CONNECT requests delivered in one TCP chunk", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;
    const host = Buffer.from("example.com", "utf8");

    fake.pushInput(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, host.length]), host, Buffer.from([0x01, 0xbb])]));

    await expect(request).resolves.toEqual({
      protocol: "socks5",
      target: { host: "example.com", port: 443 }
    });
    expect(fake.writes).toEqual([Buffer.from([0x05, 0x00])]);
  });

  it("preserves early bytes sent with a SOCKS5 CONNECT request", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;
    const host = Buffer.from("example.com", "utf8");
    const early = Buffer.from("TLS-CLIENT-HELLO", "utf8");

    fake.pushInput(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, host.length]), host, Buffer.from([0x01, 0xbb]), early]));

    await expect(request).resolves.toEqual({
      protocol: "socks5",
      target: { host: "example.com", port: 443 },
      initialData: early
    });
    expect(fake.writes).toEqual([Buffer.from([0x05, 0x00])]);
  });

  it("rejects a SOCKS5 CONNECT target with port zero", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

    fake.pushInput(Buffer.from([0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0]));

    await expect(request).rejects.toThrow("target port must be between 1 and 65535");
  });

  it("normalizes bracketed IPv6 absolute-form HTTP targets", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

    fake.pushInput(Buffer.from("GET http://[2001:db8::1]/v6 HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n", "latin1"));

    await expect(request).resolves.toMatchObject({
      protocol: "http-forward",
      target: { host: "2001:db8::1", port: 80 }
    });
  });

  it("rejects HTTPS absolute-form forwarding because TLS requires CONNECT", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

    fake.pushInput(Buffer.from("GET https://secure.example/private HTTP/1.1\r\nHost: secure.example\r\n\r\n", "latin1"));

    await expect(request).rejects.toThrow("require HTTP CONNECT");
  });

  it("parses absolute-form HTTP proxy requests and rewrites them for the origin server", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

    fake.pushInput(Buffer.from("G", "utf8"));
    await Promise.resolve();
    fake.pushInput(
      Buffer.from(
        "ET http://example.com:8080/path?q=1 HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Connection: keep-alive\r\n\r\n",
        "utf8"
      )
    );

    await expect(request).resolves.toEqual({
      protocol: "http-forward",
      target: { host: "example.com", port: 8080 },
      initialData: Buffer.from("GET /path?q=1 HTTP/1.1\r\nHost: example.com:8080\r\nConnection: close\r\n\r\n", "latin1"),
      httpForwardBody: { mode: "none", initialData: Buffer.alloc(0) }
    });
  });

  it("does not forward proxy credentials to an HTTP origin", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

    fake.pushInput(
      Buffer.from(
        "GET http://example.com/private HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic c2VjcmV0\r\n\r\n",
        "latin1"
      )
    );

    await expect(request).resolves.toEqual({
      protocol: "http-forward",
      target: { host: "example.com", port: 80 },
      initialData: Buffer.from("GET /private HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n", "latin1"),
      httpForwardBody: { mode: "none", initialData: Buffer.alloc(0) }
    });
  });

  it("preserves WebSocket absolute-form target path and upgrade headers", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

    fake.pushInput(Buffer.from("G", "utf8"));
    await Promise.resolve();
    fake.pushInput(
      Buffer.from(
        [
          "ET ws://socket.example.com/realtime/events?room=1 HTTP/1.1",
          "Host: socket.example.com",
          "Upgrade: websocket",
          "Connection: Upgrade",
          "Sec-WebSocket-Key: test-key",
          "Sec-WebSocket-Version: 13",
          "Proxy-Connection: keep-alive",
          "",
          ""
        ].join("\r\n"),
        "utf8"
      )
    );

    await expect(request).resolves.toEqual({
      protocol: "http-forward",
      target: { host: "socket.example.com", port: 80 },
      initialData: Buffer.from(
        [
          "GET /realtime/events?room=1 HTTP/1.1",
          "Host: socket.example.com",
          "Upgrade: websocket",
          "Connection: Upgrade",
          "Sec-WebSocket-Key: test-key",
          "Sec-WebSocket-Version: 13",
          "",
          ""
        ].join("\r\n"),
        "latin1"
      ),
      httpForwardBody: { mode: "stream", initialData: Buffer.alloc(0) }
    });
  });

  it("does not let WebSocket upgrades bypass ambiguous HTTP body framing checks", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

    fake.pushInput(
      Buffer.from(
        [
          "GET ws://socket.example.com/realtime HTTP/1.1",
          "Host: socket.example.com",
          "Upgrade: websocket",
          "Connection: Upgrade",
          "Transfer-Encoding: chunked",
          "Content-Length: 4",
          "",
          ""
        ].join("\r\n"),
        "latin1"
      )
    );

    await expect(request).rejects.toThrow("ambiguous body framing");
  });

  it("includes the proxy target when tunnel opening fails", async () => {
    expect(
      formatProxyTunnelError(
        {
          protocol: "http-connect",
          target: { host: "refused.example", port: 443 }
        },
        "Connection refused"
      )
    ).toBe("HTTP CONNECT tunnel failed for refused.example:443: Connection refused");
  });

  it("preserves upload bytes that arrive while the SSH channel is opening", async () => {
    const channel = new MemoryDirectTcpIpChannel();
    const channelOpening = deferred<void>();
    const releaseChannel = deferred<void>();
    const proxy = new Socks5Proxy({
      listenPort: 0,
      connectChannel: async () => {
        channelOpening.resolve(undefined);
        await releaseChannel.promise;
        return channel;
      }
    });
    const socket = new FlowingFakeSocket() as unknown as Socket;
    const handling = (proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(socket);
    const fake = socket as unknown as FlowingFakeSocket;

    fake.pushInput(Buffer.from("POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n", "latin1"));
    await channelOpening.promise;

    // This is deliberately a later TCP chunk. A real Node socket remains in
    // flowing mode after the one-shot handshake listener is removed, so this
    // chunk would be discarded unless handleSocket explicitly pauses it.
    fake.pushInput(Buffer.from("BODY", "latin1"));
    releaseChannel.resolve(undefined);
    await handling;

    await waitFor(() => Buffer.concat(channel.written).includes(Buffer.from("BODY", "latin1")));
    expect(Buffer.concat(channel.written).toString("latin1")).toBe(
      "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nConnection: close\r\n\r\nBODY"
    );
  });

  it("never forwards a second HTTP request to the first request's origin", async () => {
    const channel = new MemoryDirectTcpIpChannel();
    const proxy = new Socks5Proxy({ listenPort: 0, connectChannel: async () => channel });
    const socket = new FlowingFakeSocket() as unknown as Socket;
    const handling = (proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(socket);
    const fake = socket as unknown as FlowingFakeSocket;

    fake.pushInput(
      Buffer.from(
        "GET http://first.example/one HTTP/1.1\r\nHost: first.example\r\n\r\n" +
          "GET http://second.example/private HTTP/1.1\r\nHost: second.example\r\nCookie: secret\r\n\r\n",
        "latin1"
      )
    );
    await handling;

    const forwarded = Buffer.concat(channel.written).toString("latin1");
    expect(forwarded).toContain("GET /one HTTP/1.1");
    expect(forwarded).not.toContain("second.example");
    expect(forwarded).not.toContain("Cookie: secret");
  });

  it("streams one chunked HTTP upload but drops a pipelined next request", async () => {
    const channel = new MemoryDirectTcpIpChannel();
    const proxy = new Socks5Proxy({ listenPort: 0, connectChannel: async () => channel });
    const socket = new FlowingFakeSocket() as unknown as Socket;
    const handling = (proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(socket);
    const fake = socket as unknown as FlowingFakeSocket;

    fake.pushInput(
      Buffer.from(
        "POST http://first.example/upload HTTP/1.1\r\nHost: first.example\r\nTransfer-Encoding: chunked\r\n\r\n" +
          "4\r\nBODY\r\n0\r\n\r\n" +
          "GET http://second.example/ HTTP/1.1\r\nHost: second.example\r\n\r\n",
        "latin1"
      )
    );
    await handling;

    const forwarded = Buffer.concat(channel.written).toString("latin1");
    expect(forwarded).toContain("4\r\nBODY\r\n0\r\n\r\n");
    expect(forwarded).not.toContain("second.example");
  });

  it("closes a channel that finishes opening after its local client disconnected", async () => {
    const channel = new MemoryDirectTcpIpChannel();
    const channelOpening = deferred<void>();
    const releaseChannel = deferred<void>();
    const channelClosed = deferred<void>();
    channel.onClose(() => channelClosed.resolve(undefined));
    const proxy = new Socks5Proxy({
      listenPort: 0,
      connectChannel: async () => {
        channelOpening.resolve(undefined);
        await releaseChannel.promise;
        return channel;
      }
    });
    const socket = new FlowingFakeSocket() as unknown as Socket;
    const handling = (proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(socket);
    const fake = socket as unknown as FlowingFakeSocket;

    fake.pushInput(Buffer.from("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", "latin1"));
    await channelOpening.promise;
    fake.destroy();
    releaseChannel.resolve(undefined);

    await handling;
    await channelClosed.promise;
  });

  it("retains SOCKS pending-open leases after local socket churn and closes late channels", async () => {
    const pending: Array<ReturnType<typeof deferred<DirectTcpIpChannel>>> = [];
    const connectChannel = vi.fn(() => {
      const open = deferred<DirectTcpIpChannel>();
      pending.push(open);
      return open.promise;
    });
    const proxy = new Socks5Proxy({
      listenPort: 0,
      maxConnections: 8,
      maxPendingChannelOpens: 2,
      connectChannel
    });
    const handlings: Promise<void>[] = [];

    for (let index = 0; index < 2; index += 1) {
      const fake = new FlowingFakeSocket();
      handlings.push((proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(fake as unknown as Socket));
      fake.pushInput(socksConnectRequest());
      await waitFor(() => connectChannel.mock.calls.length === index + 1);
      fake.closeInput();
    }

    const rejected = new FlowingFakeSocket();
    const rejectedHandling = (proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(rejected as unknown as Socket);
    rejected.pushInput(socksConnectRequest());
    await rejectedHandling;

    expect(connectChannel).toHaveBeenCalledTimes(2);
    expect((proxy as unknown as { pendingChannelOpens: number }).pendingChannelOpens).toBe(2);
    expect(Buffer.concat(rejected.writes)).toEqual(
      Buffer.concat([Buffer.from([0x05, 0x00]), Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])])
    );

    const lateChannels = pending.map(() => new MemoryDirectTcpIpChannel());
    const closed = lateChannels.map((channel) => {
      const result = deferred<void>();
      channel.onClose(() => result.resolve(undefined));
      return result.promise;
    });
    pending.forEach((open, index) => open.resolve(lateChannels[index]));
    await Promise.all([...handlings, ...closed]);
    expect((proxy as unknown as { pendingChannelOpens: number }).pendingChannelOpens).toBe(0);
  });

  it("retains local TCP pending-open leases after local socket churn", async () => {
    const pending: Array<ReturnType<typeof deferred<DirectTcpIpChannel>>> = [];
    const connectChannel = vi.fn(() => {
      const open = deferred<DirectTcpIpChannel>();
      pending.push(open);
      return open.promise;
    });
    const proxy = new LocalTcpProxy({
      listenPort: 0,
      target: { host: "example.com", port: 443 },
      maxConnections: 8,
      maxPendingChannelOpens: 2,
      connectChannel
    });
    const handlings: Promise<void>[] = [];

    for (let index = 0; index < 2; index += 1) {
      const fake = new FlowingFakeSocket();
      handlings.push((proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(fake as unknown as Socket));
      await waitFor(() => connectChannel.mock.calls.length === index + 1);
      fake.closeInput();
    }

    const rejected = new FlowingFakeSocket();
    await (proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(rejected as unknown as Socket);
    expect(connectChannel).toHaveBeenCalledTimes(2);
    expect(rejected.destroyed).toBe(true);
    expect((proxy as unknown as { pendingChannelOpens: number }).pendingChannelOpens).toBe(2);

    const lateChannels = pending.map(() => new MemoryDirectTcpIpChannel());
    const closed = lateChannels.map((channel) => {
      const result = deferred<void>();
      channel.onClose(() => result.resolve(undefined));
      return result.promise;
    });
    pending.forEach((open, index) => open.resolve(lateChannels[index]));
    await Promise.all([...handlings, ...closed]);
    expect((proxy as unknown as { pendingChannelOpens: number }).pendingChannelOpens).toBe(0);
  });

});

describe("Windows PAC generation", () => {
  it("routes enabled domain and IPv4 CIDR rules to the SOCKS proxy", () => {
    const pac = buildProxyPac(
      [
        { id: "1", type: "domain", value: "*.example.com", enabled: true, createdAt: "", updatedAt: "" },
        { id: "2", type: "ip", value: "10.10.25.7/16", enabled: true, createdAt: "", updatedAt: "" },
        { id: "3", type: "ip", value: "192.0.2.10", enabled: true, createdAt: "", updatedAt: "" },
        { id: "4", type: "domain", value: "disabled.test", enabled: false, createdAt: "", updatedAt: "" }
      ],
      "127.0.0.1",
      1080
    );

    expect(pac).toContain("Shadow SSH routing PAC");
    expect(pac).toContain("PROXY 127.0.0.1:1080");
    expect(pac).toContain("SOCKS5 127.0.0.1:1080");
    expect(pac).toContain('var proxyWildcardDomains = {"example.com":1};');
    expect(pac).toContain("dnsResolve(host)");
    expect(pac).toContain('isInNet(resolvedHost, "10.10.0.0", "255.255.0.0")');
    expect(pac).toContain('hostNoBrackets == "192.0.2.10"');
    expect(pac).toContain('resolvedHost == "192.0.2.10"');
    expect(pac).not.toContain("resolvedHostEx.indexOf");
    expect(pac).not.toContain("disabled.test");
  });

  it("omits invalid enabled routing rules from generated PAC content", () => {
    const pac = buildProxyPac(
      [
        { id: "valid", type: "domain", value: "valid.example", enabled: true, createdAt: "", updatedAt: "" },
        { id: "bad-domain", type: "domain", value: "not-a-domain", enabled: true, createdAt: "", updatedAt: "" },
        { id: "bad-ip", type: "ip", value: "999.1.1.1/24", enabled: true, createdAt: "", updatedAt: "" }
      ],
      "127.0.0.1",
      1080
    );

    expect(pac).toContain("valid.example");
    expect(pac).not.toContain("not-a-domain");
    expect(pac).not.toContain("999.1.1.1");
  });

  it("uses the shared strict proxy-domain normalizer for PAC lists", () => {
    const pac = buildProxyPac([], "127.0.0.1", 1080, "mixed", {
      mode: "selected-rules",
      proxyDomains: ["valid.example", "aa..bb", "aa.-bad.com", "localhost"],
      directDomains: ["direct.example", "bad-.example"]
    });

    expect(pac).toContain('var directDomains = {"direct.example":1};');
    expect(pac).toContain('var proxyListDomains = {"valid.example":1};');
    expect(pac).not.toContain("aa..bb");
    expect(pac).not.toContain("aa.-bad.com");
    expect(pac).not.toContain("localhost");
    expect(pac).not.toContain("bad-.example");
  });

  it("can generate HTTP-only PAC entries for Xray system proxy routing", () => {
    const pac = buildProxyPac(
      [{ id: "1", type: "domain", value: "youtube.com", enabled: true, createdAt: "", updatedAt: "" }],
      "127.0.0.1",
      19080,
      "http"
    );

    expect(pac).toContain("PROXY 127.0.0.1:19080");
    expect(pac).not.toContain("SOCKS5 127.0.0.1:19080");
  });

  it("adds proxy-list checks to selected-rules routing", () => {
    const pac = buildProxyPac([], "127.0.0.1", 1080, "mixed", {
      mode: "selected-rules",
      proxyDomains: [".ru", "gosuslugi.ru"]
    });

    expect(pac).toContain('var proxyListDomains = {"ru":1,"gosuslugi.ru":1};');
    expect(pac).toContain("matchesDomainOrParent(hostNoBrackets, proxyListDomains)");
    expect(pac).toContain('return "PROXY 127.0.0.1:1080; SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080";');
    expect(evaluatePac(pac, "api.gosuslugi.ru")).toContain("PROXY 127.0.0.1:1080");
  });

  it("checks direct-list domains before proxy-list domains", () => {
    const pac = buildProxyPac([], "127.0.0.1", 1080, "mixed", {
      mode: "selected-rules",
      proxyDomains: ["example.com"],
      directDomains: ["direct.example.com"]
    });

    expect(pac.indexOf("matchesDomainOrParent(hostNoBrackets, directDomains)")).toBeLessThan(
      pac.indexOf("matchesDomainOrParent(hostNoBrackets, proxyListDomains)")
    );
    expect(pac).toContain('return "DIRECT";');
    expect(pac).toContain('return "PROXY 127.0.0.1:1080; SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080";');
    expect(evaluatePac(pac, "direct.example.com")).toBe("DIRECT");
    expect(evaluatePac(pac, "www.example.com")).toContain("PROXY 127.0.0.1:1080");
  });

  it("uses PAC for proxy-all when a direct list is present", () => {
    const pac = buildProxyPac([], "127.0.0.1", 1080, "mixed", {
      mode: "proxy-all",
      directDomains: [".ru"]
    });

    expect(pac).toContain('return "DIRECT";');
    expect(pac).toContain('return "PROXY 127.0.0.1:1080; SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080";');
    expect(evaluatePac(pac, "service.ru")).toBe("DIRECT");
    expect(evaluatePac(pac, "example.com")).toContain("PROXY 127.0.0.1:1080");
  });

  it("does not perform local DNS resolution for domain-only routing", () => {
    const pac = buildProxyPac(
      [{ id: "1", type: "domain", value: "*.example.com", enabled: true, createdAt: "", updatedAt: "" }],
      "127.0.0.1",
      1080
    );

    expect(pac).not.toContain("dnsResolve(");
    expect(pac).not.toContain("dnsResolveEx(");
    expect(evaluatePac(pac, "api.example.com")).toContain("PROXY 127.0.0.1:1080");
    expect(evaluatePac(pac, "example.com")).toBe("DIRECT");
  });

  it("matches equivalent IPv6 spellings for an exact /128 rule", () => {
    const pac = buildProxyPac(
      [{ id: "v6", type: "ip", value: "2001:0db8:0:0:0:0:0:1", enabled: true, createdAt: "", updatedAt: "" }],
      "127.0.0.1",
      1080
    );
    const context: {
      result?: string;
      dnsResolveEx: () => string;
      isInNetEx: (address: string, range: string) => boolean;
    } = {
      dnsResolveEx: () => "2001:db8::1",
      isInNetEx: (address, range) => address === "2001:db8::1" && range.endsWith("/128")
    };

    runInNewContext(`${pac}\nresult = FindProxyForURL("https://ipv6.example/", "ipv6.example");`, context);

    expect(pac).toContain("resolvedIsInNetEx(resolvedHostEx");
    expect(pac).toContain('"2001:db8::1/128"');
    expect(context.result).toContain("PROXY 127.0.0.1:1080");
  });
});

describe("domain proxy list parser", () => {
  it("parses whitespace-separated inside-raw domains", () => {
    expect(parseDomainProxyList(".ua  gosuslugi.ru\n*.example.com https://ignored.test/path #comment")).toEqual([
      ".example.com",
      ".ua",
      "gosuslugi.ru"
    ]);
  });

  it.each(["aa..bb", "aa.-bad.com", "aa.bad-.com", "localhost", "*example.com"])(
    "rejects invalid label-wise proxy domain %s",
    (domain) => {
      expect(normalizeProxyDomain(domain)).toBeUndefined();
    }
  );

  it("shares normalization for parsing while preserving intentional dot-prefixed TLD suffixes", () => {
    expect(parseDomainProxyList("aa..bb aa.-bad.com localhost Valid.Example. .ru")).toEqual([".ru", "valid.example"]);
  });
});

function waitForParser(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

function socksConnectRequest(): Buffer {
  return Buffer.from([0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb]);
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T | PromiseLike<T>) => void } {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
}

async function waitFor(predicate: () => boolean, timeoutMs = 1000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) {
      throw new Error("Timed out waiting for proxy data.");
    }
    await waitForParser();
  }
}

function evaluatePac(pac: string, host: string): string {
  const context: { result?: string } = {};
  runInNewContext(`${pac}\nresult = FindProxyForURL("https://${host}/", ${JSON.stringify(host)});`, context);
  if (typeof context.result !== "string") {
    throw new Error("PAC did not return a routing result.");
  }
  return context.result;
}

class FakeSocket extends EventEmitter {
  readonly writes: Buffer[] = [];
  private readonly pendingData: Buffer[] = [];
  destroyed = false;
  private flowing = false;

  override on(eventName: string | symbol, listener: (...args: unknown[]) => void): this {
    return super.on(eventName, listener);
  }

  override once(eventName: string | symbol, listener: (...args: unknown[]) => void): this {
    return super.once(eventName, listener);
  }

  write(data: Buffer): boolean {
    this.writes.push(Buffer.from(data));
    return true;
  }

  pushInput(data: Buffer): void {
    if (this.flowing && this.listenerCount("data") > 0) {
      this.emit("data", data);
      return;
    }
    this.pendingData.push(data);
  }

  unshift(): void {
    throw new Error("Proxy parser should not depend on socket.unshift().");
  }

  pause(): this {
    this.flowing = false;
    return this;
  }

  resume(): this {
    this.flowing = true;
    this.flushPendingData();
    return this;
  }

  private flushPendingData(): void {
    if (!this.flowing || this.pendingData.length === 0 || this.listenerCount("data") === 0) {
      return;
    }
    const chunk = this.pendingData.shift()!;
    queueMicrotask(() => {
      if (this.flowing && this.listenerCount("data") > 0) {
        this.emit("data", chunk);
      } else {
        this.pendingData.unshift(chunk);
      }
    });
  }
}

class FlowingFakeSocket extends EventEmitter {
  readonly writes: Buffer[] = [];
  private readonly pendingData: Buffer[] = [];
  private flowing = false;
  private deliveryScheduled = false;
  destroyed = false;
  writable = true;
  writableEnded = false;
  remoteAddress = "127.0.0.1";
  remotePort = 54321;

  override on(eventName: string | symbol, listener: (...args: unknown[]) => void): this {
    const result = super.on(eventName, listener);
    if (eventName === "data") {
      this.flowing = true;
      this.flushPendingData();
    }
    return result;
  }

  override once(eventName: string | symbol, listener: (...args: unknown[]) => void): this {
    const result = super.once(eventName, listener);
    if (eventName === "data") {
      this.flowing = true;
      this.flushPendingData();
    }
    return result;
  }

  pushInput(data: Buffer): void {
    this.pendingData.push(data);
    this.flushPendingData();
  }

  pause(): this {
    this.flowing = false;
    return this;
  }

  resume(): this {
    this.flowing = true;
    this.flushPendingData();
    return this;
  }

  setTimeout(): this {
    return this;
  }

  setNoDelay(): this {
    return this;
  }

  setKeepAlive(): this {
    return this;
  }

  write(data: Buffer | string): boolean {
    this.writes.push(Buffer.isBuffer(data) ? Buffer.from(data) : Buffer.from(data));
    return true;
  }

  end(): this {
    this.writableEnded = true;
    this.writable = false;
    return this;
  }

  destroy(): this {
    this.destroyed = true;
    this.writable = false;
    return this;
  }

  closeInput(): void {
    if (this.destroyed) {
      return;
    }
    this.destroyed = true;
    this.writable = false;
    this.emit("close");
  }

  private flushPendingData(): void {
    if (!this.flowing || this.listenerCount("data") === 0 || this.pendingData.length === 0 || this.deliveryScheduled) {
      return;
    }
    this.deliveryScheduled = true;
    queueMicrotask(() => {
      this.deliveryScheduled = false;
      if (this.flowing && this.listenerCount("data") > 0 && this.pendingData.length > 0) {
        this.emit("data", this.pendingData.shift()!);
      }
      this.flushPendingData();
    });
  }
}
