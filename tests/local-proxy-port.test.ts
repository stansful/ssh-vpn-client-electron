import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryDirectTcpIpChannel } from "../src/core/network/memory-direct-channel.js";
import { Socks5Proxy } from "../src/core/network/socks5-proxy.js";
import {
  forgetLocalProxyPort,
  preferredLocalProxyPort,
  rememberLocalProxyPort
} from "../src/service/local-proxy-port.js";

afterEach(() => {
  forgetLocalProxyPort();
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
