import net from "node:net";

export function parseEndpoint(endpoint: string): { host: string; port: number } {
  const trimmed = endpoint.trim();
  const bracketMatch = trimmed.match(/^\[([^\]]+)\]:(\d+)$/u);
  const host = bracketMatch ? bracketMatch[1] : trimmed.replace(/:(\d+)$/u, "");
  const portRaw = bracketMatch ? bracketMatch[2] : trimmed.match(/:(\d+)$/u)?.[1];
  const port = Number(portRaw);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Tunnel check endpoint must be host:port.");
  }
  return { host, port };
}

export function checkSocks5Connect(proxy: { host: string; port: number }, target: { host: string; port: number }): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(proxy.port, proxy.host);
    const timeout = setTimeout(() => socket.destroy(new Error("SOCKS tunnel check timed out.")), 12_000);
    timeout.unref();
    let stage: "greeting" | "connect" = "greeting";

    const fail = (error: Error): void => {
      clearTimeout(timeout);
      socket.destroy();
      reject(error);
    };
    socket.once("error", fail);
    socket.once("connect", () => {
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    socket.on("data", (data) => {
      if (stage === "greeting") {
        if (data.length < 2 || data[0] !== 0x05 || data[1] !== 0x00) {
          fail(new Error("SOCKS proxy rejected no-auth handshake."));
          return;
        }
        stage = "connect";
        socket.write(buildSocksConnectRequest(target));
        return;
      }
      if (data.length < 2 || data[1] !== 0x00) {
        fail(new Error(`SOCKS proxy connect failed with code ${data[1] ?? "unknown"}.`));
        return;
      }
      clearTimeout(timeout);
      socket.end();
      resolve();
    });
  });
}

function buildSocksConnectRequest(target: { host: string; port: number }): Buffer {
  const host = target.host.trim();
  const port = Buffer.alloc(2);
  port.writeUInt16BE(target.port);
  if (net.isIPv4(host)) {
    return Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x01]), Buffer.from(host.split(".").map((part) => Number(part))), port]);
  }
  const encodedHost = Buffer.from(host, "utf8");
  if (encodedHost.length > 255) {
    throw new Error("SOCKS target host is too long.");
  }
  return Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, encodedHost.length]), encodedHost, port]);
}
