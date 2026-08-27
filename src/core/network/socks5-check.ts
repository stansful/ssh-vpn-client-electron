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

export function buildSocks5ConnectRequest(target: { host: string; port: number }): Buffer {
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
