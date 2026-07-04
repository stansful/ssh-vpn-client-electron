import { EventEmitter } from "node:events";
import type { Socket } from "node:net";
import { describe, expect, it } from "vitest";
import { readProxyConnectRequest, readSocksConnectRequest } from "../src/core/network/socks5-proxy.js";
import { buildProxyPac } from "../src/core/network/windows-system-proxy.js";
import { parseDomainProxyList } from "../src/core/routing/domain-proxy-list.js";

describe("SOCKS5 proxy", () => {
  it("parses no-auth CONNECT requests for direct-tcpip channel opening", async () => {
    const socket = new FakeSocket() as unknown as Socket;
    const request = readSocksConnectRequest(socket);
    const fake = socket as unknown as FakeSocket;

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
      initialData: Buffer.from("GET /path?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n", "latin1")
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
      )
    });
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
    expect(pac).toContain('dnsDomainIs(hostNoBrackets, ".example.com")');
    expect(pac).toContain("dnsResolve(hostNoBrackets)");
    expect(pac).toContain('isInNet(resolvedHost, "10.10.0.0", "255.255.0.0")');
    expect(pac).toContain('hostNoBrackets == "192.0.2.10"');
    expect(pac).toContain('resolvedHost == "192.0.2.10"');
    expect(pac).not.toContain("disabled.test");
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

    expect(pac).toContain('if (hostNoBrackets == "ru" || dnsDomainIs(hostNoBrackets, ".ru")');
    expect(pac).toContain('hostNoBrackets == "gosuslugi.ru"');
    expect(pac).toContain('return "PROXY 127.0.0.1:1080; SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080";');
  });

  it("checks direct-list domains before proxy-list domains", () => {
    const pac = buildProxyPac([], "127.0.0.1", 1080, "mixed", {
      mode: "selected-rules",
      proxyDomains: ["example.com"],
      directDomains: ["direct.example.com"]
    });

    expect(pac.indexOf('hostNoBrackets == "direct.example.com"')).toBeLessThan(pac.indexOf('hostNoBrackets == "example.com"'));
    expect(pac).toContain('return "DIRECT";');
    expect(pac).toContain('return "PROXY 127.0.0.1:1080; SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080";');
  });

  it("uses PAC for proxy-all when a direct list is present", () => {
    const pac = buildProxyPac([], "127.0.0.1", 1080, "mixed", {
      mode: "proxy-all",
      directDomains: [".ru"]
    });

    expect(pac.indexOf('dnsDomainIs(hostNoBrackets, ".ru")')).toBeLessThan(pac.indexOf('return "PROXY 127.0.0.1:1080'));
    expect(pac).toContain('return "DIRECT";');
    expect(pac).toContain('return "PROXY 127.0.0.1:1080; SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080";');
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
});

function waitForParser(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

class FakeSocket extends EventEmitter {
  readonly writes: Buffer[] = [];
  private readonly pendingData: Buffer[] = [];
  destroyed = false;

  override on(eventName: string | symbol, listener: (...args: unknown[]) => void): this {
    const result = super.on(eventName, listener);
    if (eventName === "data") {
      this.flushPendingData();
    }
    return result;
  }

  override once(eventName: string | symbol, listener: (...args: unknown[]) => void): this {
    if (eventName === "data" && this.pendingData.length > 0) {
      const chunk = this.pendingData.shift()!;
      queueMicrotask(() => listener.call(this, chunk));
      return this;
    }
    return super.once(eventName, listener);
  }

  write(data: Buffer): boolean {
    this.writes.push(Buffer.from(data));
    return true;
  }

  pushInput(data: Buffer): void {
    if (this.listenerCount("data") > 0) {
      this.emit("data", data);
      return;
    }
    this.pendingData.push(data);
  }

  unshift(): void {
    throw new Error("Proxy parser should not depend on socket.unshift().");
  }

  private flushPendingData(): void {
    if (this.pendingData.length === 0) {
      return;
    }
    const chunks = this.pendingData.splice(0);
    for (const chunk of chunks) {
      queueMicrotask(() => this.emit("data", chunk));
    }
  }
}
