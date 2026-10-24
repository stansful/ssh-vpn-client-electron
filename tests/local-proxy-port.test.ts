import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryDirectTcpIpChannel } from "../src/core/network/memory-direct-channel.js";
import { Socks5Proxy } from "../src/core/network/socks5-proxy.js";
import {
  forgetLocalProxyPort,
  forgetXrayInboundPorts,
  preferredLocalProxyPort,
  preferredXrayInboundPorts,
  rememberLocalProxyPort,
  rememberXrayInboundPorts
} from "../src/service/local-proxy-port.js";
import { reserveDistinctLocalTcpPorts } from "../src/service/xray/process-utils.js";

afterEach(() => {
  forgetLocalProxyPort();
  forgetXrayInboundPorts();
});

describe("local proxy port memory", () => {
  it("remembers the last bound port so both transports reuse one endpoint", () => {
    expect(preferredLocalProxyPort()).toBeUndefined();
    rememberLocalProxyPort(51_234);
    expect(preferredLocalProxyPort()).toBe(51_234);
  });

  it("ignores ports that cannot be bound later", () => {
    rememberLocalProxyPort(0);
    rememberLocalProxyPort(-1);
    rememberLocalProxyPort(70_000);
    rememberLocalProxyPort(1.5);
    expect(preferredLocalProxyPort()).toBeUndefined();
  });

  it("remembers the pair of ports Xray's own inbounds last listened on", () => {
    expect(preferredXrayInboundPorts()).toBeUndefined();
    rememberXrayInboundPorts({ socksPort: 52_000, httpPort: 52_001 });
    const remembered = preferredXrayInboundPorts();
    expect(remembered).toEqual({ socksPort: 52_000, httpPort: 52_001 });

    // A copy: a caller cannot change what the next connect prefers.
    remembered!.socksPort = 1;
    expect(preferredXrayInboundPorts()).toEqual({ socksPort: 52_000, httpPort: 52_001 });

    forgetXrayInboundPorts();
    expect(preferredXrayInboundPorts()).toBeUndefined();
  });

  it("ignores an Xray pair that could not be bound again", () => {
    rememberXrayInboundPorts({ socksPort: 0, httpPort: 52_001 });
    rememberXrayInboundPorts({ socksPort: 52_000, httpPort: 70_000 });
    rememberXrayInboundPorts({ socksPort: 52_000, httpPort: 52_000 });
    expect(preferredXrayInboundPorts()).toBeUndefined();
  });
});

describe("Xray inbound port selection", () => {
  it("rebinds the remembered ports, and gives a taken one a fresh port in its own slot", async () => {
    const [socks, http] = await reserveDistinctLocalTcpPorts(2);
    rememberXrayInboundPorts({ socksPort: socks.port, httpPort: http.port });
    const preferred = preferredXrayInboundPorts()!;

    await expect(reserveDistinctLocalTcpPorts(2, undefined, {
      preferredPorts: [preferred.socksPort, preferred.httpPort]
    })).resolves.toEqual([socks, http]);

    const squatter = net.createServer();
    await new Promise<void>((resolve) => squatter.listen(socks.port, "127.0.0.1", resolve));
    try {
      const [nextSocks, nextHttp] = await reserveDistinctLocalTcpPorts(2, undefined, {
        preferredPorts: [preferred.socksPort, preferred.httpPort]
      });
      expect(nextSocks.port).not.toBe(socks.port);
      expect(nextSocks.port).not.toBe(http.port);
      expect(nextHttp).toEqual(http);
    } finally {
      await new Promise<void>((resolve) => squatter.close(() => resolve()));
    }
  });
});

describe("SOCKS5 proxy port selection", () => {
  it("rebinds the preferred port so a restarted listener keeps its endpoint", async () => {
    const first = new Socks5Proxy({ connectChannel: async () => new MemoryDirectTcpIpChannel() });
    const initial = await first.start();
    await first.stop();

    const second = new Socks5Proxy({
      preferredListenPort: initial.port,
      connectChannel: async () => new MemoryDirectTcpIpChannel()
    });
    try {
      await expect(second.start()).resolves.toMatchObject({ port: initial.port });
    } finally {
      await second.stop();
    }
  });

  it("falls back to an ephemeral port rather than failing when the preferred port is taken", async () => {
    const squatter = net.createServer();
    await new Promise<void>((resolve) => squatter.listen(0, "127.0.0.1", resolve));
    const address = squatter.address();
    if (typeof address !== "object" || !address) {
      throw new Error("Test server did not bind a TCP address.");
    }

    const proxy = new Socks5Proxy({
      preferredListenPort: address.port,
      connectChannel: async () => new MemoryDirectTcpIpChannel()
    });
    try {
      const endpoint = await proxy.start();
      expect(endpoint.port).toBeGreaterThan(0);
      expect(endpoint.port).not.toBe(address.port);
    } finally {
      await proxy.stop();
      await new Promise<void>((resolve) => squatter.close(() => resolve()));
    }
  });

  it("still fails when an explicitly required port is unavailable", async () => {
    const squatter = net.createServer();
    await new Promise<void>((resolve) => squatter.listen(0, "127.0.0.1", resolve));
    const address = squatter.address();
    if (typeof address !== "object" || !address) {
      throw new Error("Test server did not bind a TCP address.");
    }

    const proxy = new Socks5Proxy({
      listenPort: address.port,
      connectChannel: async () => new MemoryDirectTcpIpChannel()
    });
    try {
      await expect(proxy.start()).rejects.toThrow();
    } finally {
      await new Promise<void>((resolve) => squatter.close(() => resolve()));
    }
  });
});
