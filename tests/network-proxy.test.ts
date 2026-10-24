import { EventEmitter } from "node:events";
import net, { type Socket } from "node:net";
import { runInNewContext } from "node:vm";
import { describe, expect, it, vi } from "vitest";
import { createSocketBackedChannel, openDirectEgressChannel } from "../src/core/network/direct-tcp-channel.js";
import { MemoryDirectTcpIpChannel } from "../src/core/network/memory-direct-channel.js";
import type { RoutingRule } from "../src/shared/types.js";
import type { DirectTcpIpChannel } from "../src/core/network/local-tcp-proxy.js";
import {
  Socks5Proxy,
  formatProxyTunnelError,
  readProxyConnectRequest,
  readSocksConnectRequest,
  type Socks5ProxyEvent,
  type Socks5ProxyOptions
} from "../src/core/network/socks5-proxy.js";
import { buildProxyPac } from "../src/core/network/windows-system-proxy.js";
import { buildSelectedRulesWithProcessIps } from "../src/service/process-route-learning.js";
import { normalizeProxyDomain, parseDomainProxyList } from "../src/core/routing/domain-proxy-list.js";
import {
  DEFAULT_PROXY_CONNECTION_QUEUE_BYTES,
  DEFAULT_PROXY_TOTAL_QUEUE_BYTES,
  ESTABLISHED_TUNNEL_KEEPALIVE_DELAY_MS
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

  it("returns HTTP 502 when opening a parsed CONNECT target fails", async () => {
    const connectChannel = vi.fn<Socks5ProxyOptions["connectChannel"]>(async () => {
      throw new Error("Connection refused");
    });
    const proxy = new Socks5Proxy({ listenPort: 0, connectChannel });
    const socket = new FlowingFakeSocket() as unknown as Socket;
    const handling = (proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(socket);
    const fake = socket as unknown as FlowingFakeSocket;

    fake.pushInput(Buffer.from("CONNECT gateway.discord.gg:443 HTTP/1.1\r\nHost: gateway.discord.gg:443\r\n\r\n", "latin1"));
    await handling;

    const channelOpenSignal = connectChannel.mock.calls[0]?.[2];
    expect(channelOpenSignal).toBeInstanceOf(AbortSignal);
    expect(channelOpenSignal?.aborted).toBe(false);
    expect(connectChannel).toHaveBeenCalledWith(
      { host: "gateway.discord.gg", port: 443 },
      { address: "127.0.0.1", port: 54321 },
      channelOpenSignal
    );
    const response = Buffer.concat(fake.writes);
    expect(response.toString("latin1")).toBe(
      "HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: Shadow\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    expect(response.subarray(0, 2)).not.toEqual(Buffer.from([0x05, 0x01]));
  });

  it("does not append a plaintext 502 after a CONNECT success reply", async () => {
    const channel = new MemoryDirectTcpIpChannel();
    vi.spyOn(channel, "write").mockRejectedValueOnce(new Error("initial channel write failed"));
    const proxy = new Socks5Proxy({ listenPort: 0, connectChannel: async () => channel });
    const socket = new FlowingFakeSocket() as unknown as Socket;
    const handling = (proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(socket);
    const fake = socket as unknown as FlowingFakeSocket;

    fake.pushInput(Buffer.from(
      "CONNECT gateway.discord.gg:443 HTTP/1.1\r\nHost: gateway.discord.gg:443\r\n\r\nTLS-CLIENT-HELLO",
      "latin1"
    ));
    await handling;

    expect(Buffer.concat(fake.writes).toString("latin1")).toBe(
      "HTTP/1.1 200 Connection Established\r\nProxy-Agent: Shadow\r\n\r\n"
    );
  });

  it("leaves an established tunnel without an inactivity deadline", async () => {
    // A WebSocket, an MTProto session or an IRC chat is legitimately silent for
    // long stretches. A deadline measured on silence would disconnect them
    // mid-session, which is what a user sees as "the chat loaded and then
    // stopped receiving messages". Liveness is TCP keepalive's job instead.
    const channel = new MemoryDirectTcpIpChannel();
    const proxy = new Socks5Proxy({ listenPort: 0, connectChannel: async () => channel });
    const socket = new FlowingFakeSocket() as unknown as Socket;
    const handling = (proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(socket);
    const fake = socket as unknown as FlowingFakeSocket;

    fake.pushInput(socksConnectRequest());
    await waitFor(() => fake.writes.length > 0);

    expect(fake.timeouts.filter((timeoutMs) => timeoutMs > 0)).toEqual([]);
    expect(fake.keepAlives.at(-1)).toEqual({
      enabled: true,
      initialDelayMs: ESTABLISHED_TUNNEL_KEEPALIVE_DELAY_MS
    });

    fake.closeInput();
    await handling;
  });

  it("still arms an inactivity deadline when a caller asks for one", async () => {
    const channel = new MemoryDirectTcpIpChannel();
    const proxy = new Socks5Proxy({ listenPort: 0, idleTimeoutMs: 90_000, connectChannel: async () => channel });
    const socket = new FlowingFakeSocket() as unknown as Socket;
    const handling = (proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(socket);
    const fake = socket as unknown as FlowingFakeSocket;

    fake.pushInput(socksConnectRequest());
    await waitFor(() => fake.writes.length > 0);

    expect(fake.timeouts).toContain(90_000);

    fake.closeInput();
    await handling;
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

  // Windows can only spell one SOCKS endpoint in its proxy settings, and every
  // major client reads it as SOCKS4. Rejecting the greeting at the first byte
  // dropped whole applications, so both SOCKS4 forms are parsed here.
  it("parses SOCKS4 CONNECT requests to a literal address", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

    fake.pushInput(Buffer.from([0x04, 0x01, 0x01, 0xbb, 93, 184, 216, 34, 0x00]));

    await expect(request).resolves.toEqual({
      protocol: "socks4",
      target: { host: "93.184.216.34", port: 443 }
    });
  });

  it("parses SOCKS4a CONNECT requests carrying a host name after the user id", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

    fake.pushInput(Buffer.concat([
      Buffer.from([0x04, 0x01, 0x01, 0xbb, 0, 0, 0, 1]),
      Buffer.from("shadow\u0000", "latin1"),
      Buffer.from("it-is.ktalk.ru\u0000", "latin1")
    ]));

    await expect(request).resolves.toEqual({
      protocol: "socks4",
      target: { host: "it-is.ktalk.ru", port: 443 }
    });
  });

  it("preserves early bytes sent with a SOCKS4 CONNECT request", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readProxyConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;
    const early = Buffer.from("TLS-CLIENT-HELLO", "utf8");

    fake.pushInput(Buffer.concat([
      Buffer.from([0x04, 0x01, 0x01, 0xbb, 127, 0, 0, 1, 0x00]),
      early
    ]));

    await expect(request).resolves.toEqual({
      protocol: "socks4",
      target: { host: "127.0.0.1", port: 443 },
      initialData: early
    });
  });

  it("answers a SOCKS4 CONNECT with a granted reply and its failure code", async () => {
    const channel = new MemoryDirectTcpIpChannel();
    const granted = new Socks5Proxy({ listenPort: 0, connectChannel: async () => channel });
    const grantedSocket = new FlowingFakeSocket() as unknown as Socket;
    const grantedHandling = (granted as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(grantedSocket);
    (grantedSocket as unknown as FlowingFakeSocket).pushInput(
      Buffer.from([0x04, 0x01, 0x01, 0xbb, 93, 184, 216, 34, 0x00])
    );
    await waitForParser();
    expect(Buffer.concat((grantedSocket as unknown as FlowingFakeSocket).writes)).toEqual(
      Buffer.from([0x00, 0x5a, 0, 0, 0, 0, 0, 0])
    );

    const refused = new Socks5Proxy({
      listenPort: 0,
      connectChannel: async () => {
        throw new Error("Connection refused");
      }
    });
    const refusedSocket = new FlowingFakeSocket() as unknown as Socket;
    const refusedHandling = (refused as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(refusedSocket);
    (refusedSocket as unknown as FlowingFakeSocket).pushInput(
      Buffer.from([0x04, 0x01, 0x01, 0xbb, 93, 184, 216, 34, 0x00])
    );
    await refusedHandling;
    expect(Buffer.concat((refusedSocket as unknown as FlowingFakeSocket).writes)).toEqual(
      Buffer.from([0x00, 0x5b, 0, 0, 0, 0, 0, 0])
    );

    grantedSocket.destroy();
    await grantedHandling;
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

  // Many origins - a default Node HTTP server among them - read a client FIN
  // as an abort and answer with nothing. The forwarded request already says
  // `Connection: close`, so the origin ends the exchange itself.
  it("does not half-close the upstream once a forwarded HTTP request is complete", async () => {
    const channel = new MemoryDirectTcpIpChannel();
    const end = vi.fn(async () => undefined);
    const halfClosable = Object.assign(channel, { end });
    const proxy = new Socks5Proxy({ listenPort: 0, connectChannel: async () => halfClosable });
    const socket = new FlowingFakeSocket() as unknown as Socket;
    const handling = (proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(socket);
    const fake = socket as unknown as FlowingFakeSocket;

    fake.pushInput(Buffer.from("GET http://origin.example/page HTTP/1.1\r\nHost: origin.example\r\n\r\n", "latin1"));
    await handling;
    fake.pushInput(Buffer.from("POST http://origin.example/upload HTTP/1.1\r\nHost: origin.example\r\nContent-Length: 2\r\n\r\nok", "latin1"));
    await waitForParser();

    expect(Buffer.concat(channel.written).toString("latin1")).toBe(
      "GET /page HTTP/1.1\r\nHost: origin.example\r\nConnection: close\r\n\r\n"
    );
    expect(end).not.toHaveBeenCalled();

    // The response still reaches the client, and the origin's own close ends it.
    channel.pushRemoteData(Buffer.from("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello", "latin1"));
    await channel.close();
    await waitFor(() => fake.writableEnded);
    expect(Buffer.concat(fake.writes).toString("latin1")).toContain("hello");
  });

  it("answers a plain HTTP request from a real origin that treats a client FIN as an abort", async () => {
    const origin = net.createServer({ allowHalfOpen: true }, (socket) => {
      let request = "";
      let aborted = false;
      socket.on("end", () => {
        aborted = true;
      });
      socket.on("data", (chunk: Buffer) => {
        request += chunk.toString("latin1");
        if (request.includes("\r\n\r\n")) {
          // An origin that gives up on a client that has already gone away.
          setTimeout(() => {
            socket.end(aborted ? "" : "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
          }, 30);
        }
      });
    });
    await new Promise<void>((resolve) => origin.listen(0, "127.0.0.1", resolve));
    const originPort = (origin.address() as net.AddressInfo).port;
    const proxy = new Socks5Proxy({
      listenHost: "127.0.0.1",
      connectChannel: (target) => openDirectEgressChannel({ host: "127.0.0.1", port: target.port })
    });
    const endpoint = await proxy.start();
    try {
      const response = await new Promise<string>((resolve, reject) => {
        const client = net.connect(endpoint.port, endpoint.host);
        let received = "";
        client.on("data", (chunk: Buffer) => {
          received += chunk.toString("latin1");
        });
        client.on("end", () => resolve(received));
        client.on("error", reject);
        client.write(`GET http://origin.test:${originPort}/ HTTP/1.1\r\nHost: origin.test:${originPort}\r\n\r\n`);
      });
      expect(response).toContain("200 OK");
      expect(response.endsWith("ok")).toBe(true);
    } finally {
      await proxy.stop();
      await new Promise<void>((resolve) => origin.close(() => resolve()));
    }
  });

  it("reads IPv4-mapped IPv6 targets as the IPv4 address they carry", async () => {
    const socks = new FlowingFakeSocket() as unknown as Socket;
    const socksRequest = readSocksConnectRequest(socks);
    const mapped = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 7]);
    (socks as unknown as FlowingFakeSocket).pushInput(
      Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x04]), mapped, Buffer.from([0x01, 0xbb])])
    );
    await expect(socksRequest).resolves.toEqual({ host: "192.0.2.7", port: 443 });

    const connect = new FlowingFakeSocket() as unknown as Socket;
    const connectRequest = readProxyConnectRequest(connect);
    (connect as unknown as FlowingFakeSocket).pushInput(
      Buffer.from("CONNECT [::ffff:198.51.100.4]:8443 HTTP/1.1\r\nHost: [::ffff:198.51.100.4]:8443\r\n\r\n", "latin1")
    );
    await expect(connectRequest).resolves.toMatchObject({ target: { host: "198.51.100.4", port: 8443 } });

    const forward = new FlowingFakeSocket() as unknown as Socket;
    const forwardRequest = readProxyConnectRequest(forward);
    (forward as unknown as FlowingFakeSocket).pushInput(
      Buffer.from("GET http://[::ffff:c633:6404]/ HTTP/1.1\r\nHost: [::ffff:c633:6404]\r\n\r\n", "latin1")
    );
    await expect(forwardRequest).resolves.toMatchObject({ target: { host: "198.51.100.4", port: 80 } });
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
    let channelOpenSignal: AbortSignal | undefined;
    channel.onClose(() => channelClosed.resolve(undefined));
    const proxy = new Socks5Proxy({
      listenPort: 0,
      connectChannel: async (_target, _originator, signal) => {
        channelOpenSignal = signal;
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
    expect(channelOpenSignal?.aborted).toBe(false);
    fake.closeInput();
    expect(channelOpenSignal?.aborted).toBe(true);
    releaseChannel.resolve(undefined);

    await handling;
    await channelClosed.promise;
  });

  it("treats an abandoned pending channel open as normal local cleanup", async () => {
    const channelOpening = deferred<void>();
    const events: Socks5ProxyEvent[] = [];
    const proxy = new Socks5Proxy({
      listenPort: 0,
      connectChannel: (_target, _originator, signal) => {
        channelOpening.resolve(undefined);
        return new Promise<DirectTcpIpChannel>((_resolve, reject) => {
          const onAbort = (): void => {
            const error = new Error("cancelled by local client");
            error.name = "AbortError";
            reject(error);
          };
          if (signal?.aborted) {
            onAbort();
          } else {
            signal?.addEventListener("abort", onAbort, { once: true });
          }
        });
      }
    });
    proxy.onEvent((event) => events.push(event));
    const socket = new FlowingFakeSocket() as unknown as Socket;
    const handling = (proxy as unknown as { handleSocket(socket: Socket): Promise<void> }).handleSocket(socket);
    const fake = socket as unknown as FlowingFakeSocket;

    fake.pushInput(Buffer.from("CONNECT media.example:443 HTTP/1.1\r\nHost: media.example:443\r\n\r\n", "latin1"));
    await channelOpening.promise;
    fake.endInput();
    await handling;

    expect(fake.destroyed).toBe(true);
    expect(events.some((event) => event.type === "error")).toBe(false);
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

});

describe("socket-backed channels", () => {
  it("pause their socket while too much is unacknowledged and resume at half the window", async () => {
    const socket = new PausableFakeSocket();
    const channel = createSocketBackedChannel(socket as unknown as Socket, 1_000, 100);
    const received: number[] = [];
    channel.onData((data) => received.push(data.length));

    socket.emit("data", Buffer.alloc(60));
    expect(socket.pauses).toBe(0);
    socket.emit("data", Buffer.alloc(60));
    expect(socket.pauses).toBe(1);
    expect(received).toEqual([60, 60]);

    await channel.acknowledgeData?.(60);
    expect(socket.resumes).toBe(0);
    await channel.acknowledgeData?.(60);
    expect(socket.resumes).toBe(1);

    socket.emit("data", Buffer.alloc(99));
    expect(socket.pauses).toBe(1);
  });

  // A direct or Xray-upstream connection used to read everything the far end
  // sent while the local client was not reading, until the proxy's 16 MiB
  // per-connection queue limit destroyed it.
  it("slow the far end down instead of overflowing the proxy queue for a slow local reader", async () => {
    const totalBytes = 24 * 1024 * 1024;
    const upstream = net.createServer((socket) => {
      const chunk = Buffer.alloc(64 * 1024, 0x61);
      let sent = 0;
      const pump = (): void => {
        while (sent < totalBytes) {
          sent += chunk.length;
          if (!socket.write(chunk)) {
            socket.once("drain", pump);
            return;
          }
        }
        socket.end();
      };
      pump();
    });
    await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
    const upstreamPort = (upstream.address() as net.AddressInfo).port;
    const events: Socks5ProxyEvent[] = [];
    const proxy = new Socks5Proxy({
      listenHost: "127.0.0.1",
      connectChannel: () => openDirectEgressChannel({ host: "127.0.0.1", port: upstreamPort })
    });
    proxy.onEvent((event) => events.push(event));
    const endpoint = await proxy.start();
    const client = net.connect(endpoint.port, endpoint.host);
    try {
      await new Promise<void>((resolve) => client.once("connect", () => resolve()));
      let received = 0;
      let headerSeen = false;
      const done = new Promise<void>((resolve, reject) => {
        client.on("data", (chunk: Buffer) => {
          if (!headerSeen) {
            const text = chunk.toString("latin1");
            const headerEnd = text.indexOf("\r\n\r\n");
            if (headerEnd >= 0) {
              headerSeen = true;
              received += chunk.length - headerEnd - 4;
              // Stop reading: the local application is busy.
              client.pause();
            }
            return;
          }
          received += chunk.length;
          if (received >= totalBytes) {
            resolve();
          }
        });
        client.on("error", reject);
        client.on("close", () => (received >= totalBytes ? resolve() : reject(new Error(`closed after ${received} bytes`))));
      });
      // Observed by the await below; this only keeps an early failure from
      // also surfacing as an unhandled rejection.
      done.catch(() => undefined);
      client.write("CONNECT bulk.example:443 HTTP/1.1\r\nHost: bulk.example:443\r\n\r\n");

      await new Promise((resolve) => setTimeout(resolve, 400));
      expect(events.filter((event) => /queue limit/u.test(event.message))).toEqual([]);
      expect(client.destroyed).toBe(false);

      client.resume();
      await done;
      expect(received).toBe(totalBytes);
    } finally {
      client.destroy();
      await proxy.stop();
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    }
  }, 20_000);
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

    expect(pac).toContain("Shadow routing PAC");
    expect(pac).toContain("PROXY 127.0.0.1:1080");
    expect(pac).not.toContain("SOCKS5 127.0.0.1:1080");
    expect(pac).toContain('var proxyWildcardDomains = {"example.com":1};');
    expect(pac).toContain("dnsResolve(host)");
    expect(pac).toContain('isInNet(resolvedHost, "10.10.0.0", "255.255.0.0")');
    expect(pac).toContain('var proxyExactIps = {"192.0.2.10":1};');
    expect(pac).toContain("resolvedHasOwn(resolvedHosts, proxyResolvedExactIps)");
    expect(pac).not.toContain("resolvedHostEx.indexOf");
    expect(pac).not.toContain("disabled.test");
  });

  // A plain domain rule was emitted as an exact-host lookup while curated
  // proxy-list entries matched a domain together with its subdomains. Custom
  // rules therefore missed `www.` and every API/CDN subdomain and looked dead
  // next to the lists.
  it("routes subdomains of a plain domain rule, ahead of the direct list", () => {
    const pac = buildProxyPac(
      [{ id: "1", type: "domain", value: "example.com", enabled: true, createdAt: "", updatedAt: "" }],
      "127.0.0.1",
      1080,
      "mixed",
      { directDomains: ["cdn.example.com", "direct.example"], mode: "selected-rules" }
    );
    const findProxyForURL = new Function(
      "dnsResolveEx",
      "dnsResolve",
      "isInNetEx",
      `${pac}; return FindProxyForURL;`
    )(() => "", () => "", () => false) as (url: string, host: string) => string;

    for (const host of ["example.com", "www.example.com", "api.example.com"]) {
      expect(findProxyForURL(`https://${host}/`, host)).toBe("PROXY 127.0.0.1:1080");
    }
    // A rule the user wrote outranks the curated direct list, as it does on
    // the local listener and in the TUN policy.
    expect(findProxyForURL("https://cdn.example.com/", "cdn.example.com")).toBe("PROXY 127.0.0.1:1080");
    expect(findProxyForURL("https://direct.example/", "direct.example")).toBe("DIRECT");
    expect(findProxyForURL("https://notexample.com/", "notexample.com")).toBe("DIRECT");
  });

  it("keeps local and private destinations direct when no rule names them", () => {
    // A public IP rule makes the PAC look hosts up, local ones included.
    const rules: RoutingRule[] = [
      { id: "public", type: "ip", value: "203.0.113.0/24", enabled: true, createdAt: "", updatedAt: "" },
      { id: "site", type: "domain", value: "example.org", enabled: true, createdAt: "", updatedAt: "" }
    ];
    const answers = { intranet: "10.1.2.3", "printer.local": "192.168.1.5", localhost: "127.0.0.1" };
    for (const mode of ["proxy-all", "selected-rules"] as const) {
      const pac = buildProxyPac(rules, "127.0.0.1", 1080, "mixed", { mode, directDomains: ["direct.example"] });
      for (const host of [
        "127.0.0.1",
        "10.20.30.40",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "169.254.10.10",
        "100.64.0.1",
        "100.127.255.255",
        "0.0.0.0",
        "localhost",
        "intranet",
        "printer.local",
        "wiki.corp.local",
        "[::1]",
        "[fe80::1]",
        "[fd12:3456::1]",
        "[::ffff:192.168.1.1]",
        "[::ffff:a00:1]"
      ]) {
        expect(evaluatePacWithDns(pac, host, answers), `${mode} ${host}`).toBe("DIRECT");
      }
    }

    const proxyAll = buildProxyPac([], "127.0.0.1", 1080, "mixed", { mode: "proxy-all", directDomains: ["direct.example"] });
    for (const host of ["172.32.0.1", "100.128.0.1", "8.8.8.8", "example.com", "[2001:db8::1]", "[fd::1]"]) {
      expect(evaluatePac(proxyAll, host), host).toBe("PROXY 127.0.0.1:1080");
    }
  });

  it("lets a user rule for the local network win over it, so it reaches the network behind the server", () => {
    // 10.0.0.0/8 was the rules form's own example: an explicit rule wins.
    const rules: RoutingRule[] = [
      { id: "lan", type: "ip", value: "10.0.0.0/8", enabled: true, createdAt: "", updatedAt: "" },
      { id: "intranet", type: "domain", value: "corp.local", enabled: true, createdAt: "", updatedAt: "" }
    ];
    const answers = { nas: "10.1.2.3", "printer.local": "192.168.1.5", localhost: "127.0.0.1" };
    for (const mode of ["proxy-all", "selected-rules"] as const) {
      const pac = buildProxyPac(rules, "127.0.0.1", 1080, "mixed", { mode, directDomains: ["direct.example"] });
      for (const host of ["10.1.2.3", "10.20.30.40", "wiki.corp.local", "corp.local", "nas"]) {
        expect(evaluatePacWithDns(pac, host, answers), `${mode} ${host}`).toBe("PROXY 127.0.0.1:1080");
      }
      // The rest of the local network still stays direct.
      for (const host of ["192.168.1.1", "printer.local", "localhost", "[::1]", "172.16.0.1"]) {
        expect(evaluatePacWithDns(pac, host, answers), `${mode} ${host}`).toBe("DIRECT");
      }
    }
    // Without the rule, 10.1.2.3 stays direct.
    const withoutRule = buildProxyPac([rules[1]], "127.0.0.1", 1080, "mixed", { mode: "selected-rules" });
    expect(evaluatePacWithDns(withoutRule, "10.1.2.3", answers)).toBe("DIRECT");
  });

  it("ranks an address process discovery learned after the direct list, since the PAC cannot tell which application asks", () => {
    // Chrome, selected by a process rule, was seen at yandex.ru's address.
    // As a user IP rule that address pulled every application's yandex.ru -
    // and any direct-list site sharing it - into the tunnel.
    const rules = buildSelectedRulesWithProcessIps(
      [{ id: "chrome", type: "process.name", value: "chrome.exe", enabled: true, createdAt: "", updatedAt: "" }],
      new Set(["77.88.55.88"])
    );
    expect(rules.some((rule) => rule.id === "process-ip:77.88.55.88")).toBe(true);
    const answers = { "yandex.ru": "77.88.55.88", "mail.yandex.ru": "77.88.55.88", "cdn-neighbour.example": "77.88.55.88" };
    const pac = buildProxyPac(rules, "127.0.0.1", 1080, "mixed", { mode: "selected-rules", directDomains: ["yandex.ru"] });
    expect(evaluatePacWithDns(pac, "yandex.ru", answers)).toBe("DIRECT");
    expect(evaluatePacWithDns(pac, "mail.yandex.ru", answers)).toBe("DIRECT");
    // It still selects what the direct list does not keep out, by name or as written.
    expect(evaluatePacWithDns(pac, "cdn-neighbour.example", answers)).toBe("PROXY 127.0.0.1:1080");
    expect(evaluatePacWithDns(pac, "77.88.55.88", answers)).toBe("PROXY 127.0.0.1:1080");
    // A user's own rule for that address still beats the direct list.
    const userRule = buildProxyPac(
      [{ id: "mine", type: "ip", value: "77.88.55.88", enabled: true, createdAt: "", updatedAt: "" }],
      "127.0.0.1",
      1080,
      "mixed",
      { mode: "selected-rules", directDomains: ["yandex.ru"] }
    );
    expect(evaluatePacWithDns(userRule, "yandex.ru", answers)).toBe("PROXY 127.0.0.1:1080");
  });

  it("lets user rules win over the direct list in proxy-all and resolves only hosts that would go direct", () => {
    const pac = buildProxyPac(
      [
        { id: "domain", type: "domain", value: "mail.service.ru", enabled: true, createdAt: "", updatedAt: "" },
        { id: "ip", type: "ip", value: "203.0.113.0/24", enabled: true, createdAt: "", updatedAt: "" }
      ],
      "127.0.0.1",
      1080,
      "mixed",
      { mode: "proxy-all", directDomains: [".ru"] }
    );
    let dnsCalls = 0;
    const context: Record<string, unknown> = {
      dnsResolveEx: (host: string) => {
        dnsCalls += 1;
        return host === "cdn.service.ru" ? "203.0.113.9" : "198.51.100.1";
      },
      isInNet: () => false,
      isInNetEx: (address: string, range: string) => range === "203.0.113.0/24" && address.startsWith("203.0.113.")
    };
    const route = (host: string): string => {
      runInNewContext(`${pac}\nresult = FindProxyForURL("https://${host}/", ${JSON.stringify(host)});`, context);
      return context.result as string;
    };

    expect(route("example.com")).toBe("PROXY 127.0.0.1:1080");
    expect(dnsCalls).toBe(0);
    expect(route("mail.service.ru")).toBe("PROXY 127.0.0.1:1080");
    expect(dnsCalls).toBe(0);
    expect(route("cdn.service.ru")).toBe("PROXY 127.0.0.1:1080");
    expect(route("news.service.ru")).toBe("DIRECT");
    expect(dnsCalls).toBe(2);
  });

  it("lets the direct list win over the proxy list in split routing", () => {
    const pac = buildProxyPac([], "127.0.0.1", 1080, "mixed", {
      mode: "selected-rules",
      proxyDomains: ["example.com"],
      directDomains: ["direct.example.com"]
    });

    expect(evaluatePac(pac, "direct.example.com")).toBe("DIRECT");
    expect(evaluatePac(pac, "api.direct.example.com")).toBe("DIRECT");
    expect(evaluatePac(pac, "www.example.com")).toBe("PROXY 127.0.0.1:1080");
  });

  it("preserves DNS matching for a user-authored exact IPv4 rule", () => {
    const pac = buildProxyPac(
      [{ id: "user-exact-ip", type: "ip", value: "203.0.113.2", enabled: true, createdAt: "", updatedAt: "" }],
      "127.0.0.1",
      1080
    );
    const context: {
      result?: string;
      dnsResolve: () => string;
      dnsResolveEx: () => string;
      dnsResolveCalls: number;
      dnsResolveExCalls: number;
    } = {
      dnsResolveCalls: 0,
      dnsResolveExCalls: 0,
      dnsResolve: () => {
        context.dnsResolveCalls += 1;
        return "203.0.113.1";
      },
      dnsResolveEx: () => {
        context.dnsResolveExCalls += 1;
        return "203.0.113.1;203.0.113.2";
      }
    };

    runInNewContext(`${pac}\nresult = FindProxyForURL("https://cdn.example/", "cdn.example");`, context);

    expect(pac).toContain("dnsResolveEx(host)");
    expect(context.result).toContain("PROXY 127.0.0.1:1080");
    expect(context.dnsResolveExCalls).toBe(1);
    expect(context.dnsResolveCalls).toBe(0);
  });

  it("matches a dynamic process IP literally and caches its generic hostname fallback", () => {
    const pac = buildProxyPac(
      [{ id: "process-ip:203.0.113.2", type: "ip", value: "203.0.113.2", enabled: true, createdAt: "", updatedAt: "" }],
      "127.0.0.1",
      1080
    );
    let dnsCalls = 0;
    const context: {
      literalResult?: string;
      hostnameResult?: string;
      hostnameResultAgain?: string;
      dnsResolve: () => string;
      dnsResolveEx: () => string;
    } = {
      dnsResolve: () => {
        dnsCalls += 1;
        return "203.0.113.2";
      },
      dnsResolveEx: () => {
        dnsCalls += 1;
        return "203.0.113.2";
      }
    };

    runInNewContext(
      `${pac}\nliteralResult = FindProxyForURL("https://203.0.113.2/", "203.0.113.2");\n` +
        "hostnameResult = FindProxyForURL(\"https://cdn.example/\", \"cdn.example\");\n" +
        "hostnameResultAgain = FindProxyForURL(\"https://cdn.example/second\", \"cdn.example\");",
      context
    );

    expect(pac).toContain('var proxyExactIps = {"203.0.113.2":1};');
    expect(pac).toContain("hasOwn(proxyExactIps, hostNoBrackets)");
    expect(pac).toContain("resolvedHostCache");
    expect(pac).toContain("dnsResolveEx(host)");
    expect(context.literalResult).toBe("PROXY 127.0.0.1:1080");
    expect(context.hostnameResult).toBe("PROXY 127.0.0.1:1080");
    expect(context.hostnameResultAgain).toBe("PROXY 127.0.0.1:1080");
    expect(dnsCalls).toBe(1);
  });

  it("retries a transient unresolved PAC lookup instead of caching DIRECT", () => {
    const pac = buildProxyPac(
      [{ id: "process-ip:203.0.113.2", type: "ip", value: "203.0.113.2", enabled: true, createdAt: "", updatedAt: "" }],
      "127.0.0.1",
      1080
    );
    let extendedCalls = 0;
    let fallbackCalls = 0;
    const context: {
      firstResult?: string;
      secondResult?: string;
      dnsResolve: () => string;
      dnsResolveEx: () => string;
    } = {
      dnsResolve: () => {
        fallbackCalls += 1;
        return "";
      },
      dnsResolveEx: () => {
        extendedCalls += 1;
        return extendedCalls === 1 ? "" : "203.0.113.2";
      }
    };

    runInNewContext(
      `${pac}\nfirstResult = FindProxyForURL("https://recover.example/", "recover.example");\n` +
        "secondResult = FindProxyForURL(\"https://recover.example/retry\", \"recover.example\");",
      context
    );

    expect(context.firstResult).toBe("DIRECT");
    expect(context.secondResult).toBe("PROXY 127.0.0.1:1080");
    expect(extendedCalls).toBe(2);
    expect(fallbackCalls).toBe(1);
  });

  it("keeps the learned process hostname fallback alongside a user CIDR", () => {
    const pac = buildProxyPac(
      [
        { id: "process-ip:203.0.113.2", type: "ip", value: "203.0.113.2", enabled: true, createdAt: "", updatedAt: "" },
        { id: "user-cidr", type: "ip", value: "198.51.100.0/24", enabled: true, createdAt: "", updatedAt: "" }
      ],
      "127.0.0.1",
      1080
    );
    const context: {
      result?: string;
      dnsResolve: () => string;
      dnsResolveEx: () => string;
      isInNet: () => boolean;
      isInNetEx: () => boolean;
    } = {
      dnsResolve: () => "203.0.113.2",
      dnsResolveEx: () => "203.0.113.2",
      isInNet: () => false,
      isInNetEx: () => false
    };

    runInNewContext(`${pac}\nresult = FindProxyForURL("https://cdn.example/", "cdn.example");`, context);

    // Learned addresses rank after the direct list, so they have a table of their own.
    expect(pac).toContain('var learnedResolvedExactIps = {"203.0.113.2":1};');
    expect(context.result).toBe("PROXY 127.0.0.1:1080");
  });

  it("matches an IPv4 CIDR across every extended DNS result", () => {
    const pac = buildProxyPac(
      [{ id: "process-cidr", type: "ip", value: "203.0.113.0/24", enabled: true, createdAt: "", updatedAt: "" }],
      "127.0.0.1",
      1080
    );
    const context: {
      result?: string;
      dnsResolve: () => string;
      dnsResolveEx: () => string;
      isInNet: () => boolean;
      isInNetEx: (address: string, range: string) => boolean;
    } = {
      dnsResolve: () => "198.51.100.10",
      dnsResolveEx: () => "198.51.100.10;203.0.113.77",
      isInNet: () => false,
      isInNetEx: (address, range) => address === "203.0.113.77" && range === "203.0.113.0/24"
    };

    runInNewContext(`${pac}\nresult = FindProxyForURL("https://cdn.example/", "cdn.example");`, context);

    expect(pac).toContain('resolvedIsInNetEx(resolvedHosts, "203.0.113.0/24")');
    expect(context.result).toContain("PROXY 127.0.0.1:1080");
  });

  it("falls back to one legacy DNS lookup when extended PAC DNS is unavailable", () => {
    const pac = buildProxyPac(
      [{ id: "user-exact-ip", type: "ip", value: "203.0.113.2", enabled: true, createdAt: "", updatedAt: "" }],
      "127.0.0.1",
      1080
    );
    let dnsCalls = 0;
    const context: { result?: string; dnsResolve: () => string } = {
      dnsResolve: () => {
        dnsCalls += 1;
        return "203.0.113.2";
      }
    };

    runInNewContext(`${pac}\nresult = FindProxyForURL("https://legacy.example/", "legacy.example");`, context);

    expect(context.result).toContain("PROXY 127.0.0.1:1080");
    expect(dnsCalls).toBe(1);
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

  it("uses one SOCKS5 route without retrying SOCKS4 on the same endpoint", () => {
    const pac = buildProxyPac(
      [{ id: "1", type: "domain", value: "example.com", enabled: true, createdAt: "", updatedAt: "" }],
      "127.0.0.1",
      1080,
      "socks"
    );

    expect(evaluatePac(pac, "example.com")).toBe("SOCKS5 127.0.0.1:1080");
    expect(pac).not.toContain("; SOCKS");
  });

  it("adds proxy-list checks to selected-rules routing", () => {
    const pac = buildProxyPac([], "127.0.0.1", 1080, "mixed", {
      mode: "selected-rules",
      proxyDomains: [".ru", "gosuslugi.ru"]
    });

    expect(pac).toContain('var proxyListDomains = {"ru":1,"gosuslugi.ru":1};');
    expect(pac).toContain("matchesDomainOrParent(hostNoBrackets, proxyListDomains)");
    expect(pac).toContain('return "PROXY 127.0.0.1:1080";');
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
    expect(pac).toContain('return "PROXY 127.0.0.1:1080";');
    expect(evaluatePac(pac, "direct.example.com")).toBe("DIRECT");
    expect(evaluatePac(pac, "www.example.com")).toContain("PROXY 127.0.0.1:1080");
  });

  it("uses PAC for proxy-all when a direct list is present", () => {
    const pac = buildProxyPac([], "127.0.0.1", 1080, "mixed", {
      mode: "proxy-all",
      directDomains: [".ru"]
    });

    expect(pac).toContain('return "DIRECT";');
    expect(pac).toContain('return "PROXY 127.0.0.1:1080";');
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

  it("returns a matching process domain before evaluating unrelated IP rules", () => {
    const pac = buildProxyPac(
      [
        { id: "discord", type: "domain", value: "*.discord.gg", enabled: true, createdAt: "", updatedAt: "" },
        { id: "process-ip:203.0.113.8", type: "ip", value: "203.0.113.8", enabled: true, createdAt: "", updatedAt: "" }
      ],
      "127.0.0.1",
      1080
    );
    let dnsCalls = 0;
    const context: {
      result?: string;
      dnsResolve: () => string;
      dnsResolveEx: () => string;
    } = {
      dnsResolve: () => {
        dnsCalls += 1;
        return "203.0.113.1";
      },
      dnsResolveEx: () => {
        dnsCalls += 1;
        return "203.0.113.1";
      }
    };

    runInNewContext(`${pac}\nresult = FindProxyForURL("https://gateway.discord.gg/", "gateway.discord.gg");`, context);

    expect(context.result).toContain("PROXY 127.0.0.1:1080");
    expect(dnsCalls).toBe(0);
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

    expect(pac).toContain("resolvedIsInNetEx(resolvedHosts");
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

/**
 * Runs the PAC with the DNS and network helpers a browser's PAC engine
 * provides, IPv4 only: names resolve from `answers`, literals to themselves.
 */
function evaluatePacWithDns(pac: string, host: string, answers: Record<string, string>): string {
  const ipv4 = (value: string): number | undefined => {
    const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u.exec(value);
    return match ? match.slice(1).reduce((sum, octet) => sum * 256 + Number(octet), 0) : undefined;
  };
  const inRange = (address: string, network: string, prefix: number): boolean => {
    const value = ipv4(address);
    const base = ipv4(network);
    if (value === undefined || base === undefined) {
      return false;
    }
    const size = 2 ** (32 - prefix);
    return Math.floor(value / size) === Math.floor(base / size);
  };
  const resolve = (name: string): string => answers[name] ?? (ipv4(name) !== undefined || name.includes(":") ? name : "");
  const context: Record<string, unknown> = {
    dnsResolve: resolve,
    dnsResolveEx: resolve,
    isInNet: (address: string, network: string, mask: string) => {
      const bits = (ipv4(mask) ?? 0).toString(2).replace(/0+$/u, "").length;
      return inRange(address, network, bits);
    },
    isInNetEx: (address: string, range: string) => {
      const [network = "", prefix = "32"] = range.split("/");
      return inRange(address, network, Number(prefix));
    }
  };
  runInNewContext(`${pac}\nresult = FindProxyForURL("https://${host}/", ${JSON.stringify(host)});`, context);
  if (typeof context.result !== "string") {
    throw new Error("PAC did not return a routing result.");
  }
  return context.result;
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
  readableEnded = false;
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

  readonly timeouts: number[] = [];
  readonly keepAlives: { enabled: boolean; initialDelayMs?: number }[] = [];

  setTimeout(timeoutMs: number): this {
    this.timeouts.push(timeoutMs);
    return this;
  }

  setNoDelay(): this {
    return this;
  }

  setKeepAlive(enabled: boolean, initialDelayMs?: number): this {
    this.keepAlives.push({ enabled, initialDelayMs });
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

  endInput(): void {
    if (this.destroyed || this.readableEnded) {
      return;
    }
    this.readableEnded = true;
    this.emit("end");
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

class PausableFakeSocket extends EventEmitter {
  destroyed = false;
  pauses = 0;
  resumes = 0;

  pause(): this {
    this.pauses += 1;
    return this;
  }

  resume(): this {
    this.resumes += 1;
    return this;
  }
}
