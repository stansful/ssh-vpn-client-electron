import { EventEmitter } from "node:events";
import net from "node:net";
import type { DirectTcpIpChannel, DirectTcpIpTarget } from "./local-tcp-proxy.js";
import { configureLowLatencySocket, isSocketWritable, writeSocketWithBackpressure } from "./socket-io.js";

export interface Socks5ProxyOptions {
  listenHost?: string;
  listenPort?: number;
  idleTimeoutMs?: number;
  handshakeTimeoutMs?: number;
  socketWriteTimeoutMs?: number;
  maxQueuedSocketBytes?: number;
  connectChannel(target: DirectTcpIpTarget, originator: { address: string; port: number }): Promise<DirectTcpIpChannel>;
}

export interface Socks5ProxyEvent {
  type: "listening" | "connection" | "tunnel-opened" | "connection-closed" | "error";
  message: string;
}

export type ProxyProtocol = "socks5" | "http-connect" | "http-forward";

export interface ProxyConnectRequest {
  protocol: ProxyProtocol;
  target: DirectTcpIpTarget;
  initialData?: Buffer;
}

export class Socks5Proxy {
  private readonly events = new EventEmitter();
  private readonly sockets = new Set<net.Socket>();
  private server?: net.Server;

  constructor(private readonly options: Socks5ProxyOptions) {}

  onEvent(listener: (event: Socks5ProxyEvent) => void): () => void {
    this.events.on("event", listener);
    return () => this.events.off("event", listener);
  }

  async start(): Promise<{ host: string; port: number }> {
    if (this.server) {
      const address = this.server.address();
      if (typeof address === "object" && address) {
        return { host: normalizeListenAddress(address.address), port: address.port };
      }
      throw new Error("SOCKS5 proxy is already started without a TCP address.");
    }

    this.server = net.createServer((socket) => {
      void this.handleSocket(socket);
    });

    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(this.options.listenPort ?? 0, this.options.listenHost ?? "127.0.0.1", () => {
        this.server!.off("error", reject);
        resolve();
      });
    });

    const address = this.server.address();
    if (typeof address !== "object" || !address) {
      throw new Error("SOCKS5 proxy did not bind a TCP address.");
    }
    const bound = { host: normalizeListenAddress(address.address), port: address.port };
    this.events.emit("event", { type: "listening", message: `SOCKS5 proxy listening on ${bound.host}:${bound.port}.` } satisfies Socks5ProxyEvent);
    return bound;
  }

  async stop(): Promise<void> {
    for (const socket of this.sockets) {
      socket.destroy();
    }
    this.sockets.clear();

    if (!this.server) {
      return;
    }
    const server = this.server;
    this.server = undefined;
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });
  }

  private async handleSocket(socket: net.Socket): Promise<void> {
    this.sockets.add(socket);
    configureLowLatencySocket(socket);
    let request: ProxyConnectRequest | undefined;
    const handshakeTimeoutMs = this.options.handshakeTimeoutMs ?? 30_000;
    socket.setTimeout(handshakeTimeoutMs, () => {
      socket.destroy(new ProxyHandshakeError("SOCKS/HTTP proxy handshake timed out.", "unknown"));
    });
    const onHandshakeSocketError = (error: Error): void => {
      this.events.emit("event", { type: "error", message: error.message } satisfies Socks5ProxyEvent);
    };
    socket.on("error", onHandshakeSocketError);

    try {
      request = await readProxyConnectRequest(socket);
      socket.setTimeout(0);
      const originator = {
        address: socket.remoteAddress ?? "127.0.0.1",
        port: socket.remotePort ?? 0
      };
      this.events.emit("event", {
        type: "connection",
        message: `${formatProtocol(request.protocol)} ${request.target.host}:${request.target.port} from ${originator.address}:${originator.port}.`
      } satisfies Socks5ProxyEvent);

      const channel = await this.options.connectChannel(request.target, originator);
      this.events.emit("event", {
        type: "tunnel-opened",
        message: `${formatProtocol(request.protocol)} tunnel opened for ${request.target.host}:${request.target.port}.`
      } satisfies Socks5ProxyEvent);
      let idleTimer = this.createIdleTimer(socket);
      const refreshIdleTimer = (): void => {
        if (idleTimer) {
          clearTimeout(idleTimer);
        }
        idleTimer = this.createIdleTimer(socket);
      };
      socket.off("error", onHandshakeSocketError);
      let queuedSocketBytes = 0;
      let socketWriteQueue = Promise.resolve();
      const maxQueuedSocketBytes = this.options.maxQueuedSocketBytes ?? 32 * 1024 * 1024;
      const socketWriteTimeoutMs = this.options.socketWriteTimeoutMs ?? 120_000;
      const enqueueSocketWrite = (data: Buffer): void => {
        if (!isSocketWritable(socket)) {
          return;
        }
        queuedSocketBytes += data.length;
        if (queuedSocketBytes > maxQueuedSocketBytes) {
          socket.destroy(new Error("Local client is not reading proxied data fast enough."));
          return;
        }
        socketWriteQueue = socketWriteQueue
          .then(async () => {
            queuedSocketBytes -= data.length;
            await writeSocketWithBackpressure(socket, data, { timeoutMs: socketWriteTimeoutMs });
          })
          .catch((error: unknown) => {
            queuedSocketBytes = 0;
            if (!socket.destroyed) {
              socket.destroy(error instanceof Error ? error : new Error(String(error)));
            }
          });
      };
      const endSocketAfterQueuedWrites = (): void => {
        void socketWriteQueue.finally(() => {
          if (isSocketWritable(socket)) {
            socket.end();
          }
        });
      };
      const offData = channel.onData((data) => {
        refreshIdleTimer();
        enqueueSocketWrite(data);
      });
      const offEnd = channel.onEnd(() => {
        endSocketAfterQueuedWrites();
      });
      const offClose = channel.onClose(() => {
        endSocketAfterQueuedWrites();
      });
      const offError = channel.onError((error) => {
        this.events.emit("event", { type: "error", message: formatProxyTunnelError(request, error.message) } satisfies Socks5ProxyEvent);
        socket.destroy();
      });

      if (request.protocol === "socks5") {
        socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      } else if (request.protocol === "http-connect") {
        socket.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: Shadow SSH\r\n\r\n", "utf8");
      }

      const writeToChannel = (data: Buffer): void => {
        refreshIdleTimer();
        socket.pause();
        void channel
          .write(data)
          .then(() => {
            if (!socket.destroyed) {
              socket.resume();
            }
          })
          .catch((error: unknown) => {
            if (!socket.destroyed) {
              socket.destroy(error instanceof Error ? error : new Error(String(error)));
            }
          });
      };
      socket.on("data", writeToChannel);
      socket.on("close", () => {
        if (idleTimer) {
          clearTimeout(idleTimer);
        }
        offData();
        offEnd();
        offClose();
        offError();
        this.sockets.delete(socket);
        void channel.close();
        this.events.emit("event", { type: "connection-closed", message: "SOCKS5 connection closed." } satisfies Socks5ProxyEvent);
      });
      socket.on("error", (error) => {
        this.events.emit("event", { type: "error", message: formatProxyTunnelError(request, error.message) } satisfies Socks5ProxyEvent);
      });

      if (request.initialData && request.initialData.length > 0) {
        writeToChannel(request.initialData);
      }
    } catch (error) {
      socket.setTimeout(0);
      socket.off("error", onHandshakeSocketError);
      this.sockets.delete(socket);
      writeProxyFailure(socket, isHttpHandshakeError(error) ? "http" : "socks5");
      socket.destroy();
      this.events.emit("event", {
        type: "error",
        message: formatProxyTunnelError(request, error instanceof Error ? error.message : String(error))
      } satisfies Socks5ProxyEvent);
    }
  }

  private createIdleTimer(socket: net.Socket): NodeJS.Timeout | undefined {
    const idleTimeoutMs = this.options.idleTimeoutMs ?? 5 * 60 * 1000;
    if (idleTimeoutMs <= 0) {
      return undefined;
    }
    const timer = setTimeout(() => {
      if (!socket.destroyed) {
        socket.destroy(new Error("SOCKS5 connection idle timeout."));
      }
    }, idleTimeoutMs);
    timer.unref();
    return timer;
  }
}

export async function readProxyConnectRequest(socket: net.Socket): Promise<ProxyConnectRequest> {
  const reader = new ProxySocketReader(socket);
  const firstByte = (await reader.read(1))[0];
  if (firstByte === 0x05) {
    const target = await readSocksConnectRequestFromReader(reader, firstByte);
    const rest = reader.takeBuffered();
    return {
      protocol: "socks5",
      target,
      initialData: rest.length > 0 ? rest : undefined
    };
  }
  if (isHttpMethodStart(firstByte)) {
    return readHttpProxyRequest(reader, firstByte);
  }
  throw new ProxyHandshakeError(`Unsupported proxy protocol first byte 0x${firstByte.toString(16).padStart(2, "0")}.`, "unknown");
}

export async function readSocksConnectRequest(socket: net.Socket, firstByte?: number): Promise<DirectTcpIpTarget> {
  const reader = new ProxySocketReader(socket);
  return readSocksConnectRequestFromReader(reader, firstByte);
}

async function readSocksConnectRequestFromReader(reader: ProxySocketReader, firstByte?: number): Promise<DirectTcpIpTarget> {
  const greeting =
    firstByte === undefined
      ? await reader.read(2)
      : Buffer.concat([Buffer.from([firstByte]), await reader.read(1)]);
  if (greeting[0] !== 0x05) {
    throw new Error("Unsupported SOCKS version.");
  }
  const methods = await reader.read(greeting[1]);
  if (!methods.includes(0x00)) {
    reader.write(Buffer.from([0x05, 0xff]));
    throw new Error("SOCKS5 client does not support no-auth mode.");
  }
  reader.write(Buffer.from([0x05, 0x00]));

  const header = await reader.read(4);
  if (header[0] !== 0x05 || header[1] !== 0x01 || header[2] !== 0x00) {
    throw new Error("Only SOCKS5 CONNECT requests are supported.");
  }

  const addressType = header[3];
  let host: string;
  if (addressType === 0x01) {
    host = Array.from(await reader.read(4)).join(".");
  } else if (addressType === 0x03) {
    const length = (await reader.read(1))[0];
    host = (await reader.read(length)).toString("utf8");
  } else if (addressType === 0x04) {
    host = formatIpv6(await reader.read(16));
  } else {
    throw new Error(`Unsupported SOCKS5 address type ${addressType}.`);
  }
  const portBytes = await reader.read(2);
  return { host, port: portBytes.readUInt16BE(0) };
}

async function readHttpProxyRequest(reader: ProxySocketReader, firstByte: number): Promise<ProxyConnectRequest> {
  const { header, rest } = await readHttpHeader(reader, Buffer.from([firstByte]));
  const headerText = header.toString("latin1");
  const lines = headerText.split("\r\n");
  const requestLine = lines.shift() ?? "";
  const requestMatch = requestLine.match(/^([A-Z]+)\s+(\S+)\s+HTTP\/(\d+(?:\.\d+)?)$/u);
  if (!requestMatch) {
    throw new Error("Unsupported HTTP proxy request line.");
  }

  const method = requestMatch[1];
  const requestTarget = requestMatch[2];
  const headers = parseHttpHeaders(lines);

  if (method === "CONNECT") {
    return {
      protocol: "http-connect",
      target: parseHostPort(requestTarget, 443),
      initialData: rest.length > 0 ? rest : undefined
    };
  }

  const parsed = parseHttpForwardTarget(requestTarget, headers.get("host"));
  const rewrittenHeader = rewriteHttpProxyHeader(requestLine, lines, parsed.path);
  return {
    protocol: "http-forward",
    target: parsed.target,
    initialData: Buffer.concat([Buffer.from(rewrittenHeader, "latin1"), rest])
  };
}

class ProxySocketReader {
  private buffer = Buffer.alloc(0);

  constructor(private readonly socket: net.Socket) {}

  write(data: Buffer): void {
    this.socket.write(data);
  }

  async read(length: number): Promise<Buffer> {
    if (length === 0) {
      return Buffer.alloc(0);
    }

    while (this.buffer.length < length) {
      this.buffer = Buffer.concat([this.buffer, await this.readSocketChunk("SOCKS/HTTP proxy socket closed during handshake.")]);
    }
    const exact = this.buffer.subarray(0, length);
    this.buffer = this.buffer.subarray(length);
    return exact;
  }

  async readHttpHeader(initial: Buffer, maxHeaderBytes: number): Promise<{ header: Buffer; rest: Buffer }> {
    let headerBuffer = initial;
    for (;;) {
      const headerEnd = headerBuffer.indexOf("\r\n\r\n");
      if (headerEnd >= 0) {
        return {
          header: headerBuffer.subarray(0, headerEnd + 4),
          rest: headerBuffer.subarray(headerEnd + 4)
        };
      }
      if (headerBuffer.length > maxHeaderBytes) {
        throw new ProxyHandshakeError("HTTP proxy request header is too large.", "http");
      }
      const buffered = this.takeBuffered();
      headerBuffer = Buffer.concat([
        headerBuffer,
        buffered.length > 0 ? buffered : await this.readSocketChunk("HTTP proxy socket closed during handshake.", "http")
      ]);
    }
  }

  private readSocketChunk(closeMessage: string, closeProtocol: "http" | "socks5" = "socks5"): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      const cleanup = (): void => {
        this.socket.off("data", onData);
        this.socket.off("error", onError);
        this.socket.off("close", onClose);
      };
      const onData = (chunk: Buffer): void => {
        cleanup();
        resolve(chunk);
      };
      const onError = (error: Error): void => {
        cleanup();
        reject(error);
      };
      const onClose = (): void => {
        cleanup();
        reject(new ProxyHandshakeError(closeMessage, closeProtocol));
      };

      this.socket.once("data", onData);
      this.socket.once("error", onError);
      this.socket.once("close", onClose);
    });
  }

  takeBuffered(): Buffer {
    const chunk = this.buffer;
    this.buffer = Buffer.alloc(0);
    return chunk;
  }
}

function readHttpHeader(reader: ProxySocketReader, initial: Buffer): Promise<{ header: Buffer; rest: Buffer }> {
  const maxHeaderBytes = 64 * 1024;
  return reader.readHttpHeader(initial, maxHeaderBytes);
}

function writeProxyFailure(socket: net.Socket, protocol: "http" | "socks5"): void {
  if (!socket.destroyed) {
    if (protocol === "http") {
      socket.write("HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: Shadow SSH\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", "utf8");
      return;
    }
    socket.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
  }
}

function formatIpv6(bytes: Buffer): string {
  const groups: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 2) {
    groups.push(bytes.readUInt16BE(offset).toString(16));
  }
  return groups.join(":");
}

function normalizeListenAddress(address: string): string {
  return address === "::" ? "::1" : address;
}

function formatProtocol(protocol: ProxyProtocol): string {
  if (protocol === "socks5") {
    return "SOCKS5 CONNECT";
  }
  if (protocol === "http-connect") {
    return "HTTP CONNECT";
  }
  return "HTTP proxy";
}

export function formatProxyTunnelError(request: ProxyConnectRequest | undefined, message: string): string {
  if (!request) {
    return message;
  }
  return `${formatProtocol(request.protocol)} tunnel failed for ${request.target.host}:${request.target.port}: ${message}`;
}

function isHttpMethodStart(byte: number): boolean {
  return byte >= 0x41 && byte <= 0x5a;
}

function parseHttpHeaders(lines: string[]): Map<string, string> {
  const headers = new Map<string, string>();
  for (const line of lines) {
    if (!line) {
      continue;
    }
    const separator = line.indexOf(":");
    if (separator <= 0) {
      continue;
    }
    headers.set(line.slice(0, separator).trim().toLowerCase(), line.slice(separator + 1).trim());
  }
  return headers;
}

function parseHttpForwardTarget(requestTarget: string, hostHeader: string | undefined): { target: DirectTcpIpTarget; path: string } {
  if (/^(?:http|ws)s?:\/\//iu.test(requestTarget)) {
    const url = new URL(requestTarget);
    return {
      target: {
        host: url.hostname,
        port: url.port ? Number(url.port) : url.protocol === "https:" || url.protocol === "wss:" ? 443 : 80
      },
      path: `${url.pathname || "/"}${url.search}`
    };
  }
  if (!hostHeader) {
    throw new Error("HTTP proxy request is missing Host header.");
  }
  return {
    target: parseHostPort(hostHeader, 80),
    path: requestTarget.startsWith("/") ? requestTarget : "/"
  };
}

function rewriteHttpProxyHeader(requestLine: string, lines: string[], path: string): string {
  const [method, , version] = requestLine.split(/\s+/u);
  const filteredHeaders = lines.filter((line) => !/^proxy-connection\s*:/iu.test(line));
  return [`${method} ${path} ${version}`, ...filteredHeaders].join("\r\n");
}

function parseHostPort(value: string, defaultPort: number): DirectTcpIpTarget {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error("Proxy target host is empty.");
  }
  if (trimmed.startsWith("[")) {
    const end = trimmed.indexOf("]");
    if (end <= 1) {
      throw new Error("Invalid IPv6 proxy target.");
    }
    const host = trimmed.slice(1, end);
    const rest = trimmed.slice(end + 1);
    return { host, port: rest.startsWith(":") ? parsePort(rest.slice(1), defaultPort) : defaultPort };
  }
  const separator = trimmed.lastIndexOf(":");
  if (separator > 0 && trimmed.indexOf(":") === separator) {
    return { host: trimmed.slice(0, separator), port: parsePort(trimmed.slice(separator + 1), defaultPort) };
  }
  return { host: trimmed, port: defaultPort };
}

function parsePort(value: string, defaultPort: number): number {
  if (!value) {
    return defaultPort;
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid proxy target port ${value}.`);
  }
  return port;
}

function isHttpHandshakeError(error: unknown): boolean {
  return error instanceof ProxyHandshakeError && error.protocol === "http";
}

class ProxyHandshakeError extends Error {
  constructor(
    message: string,
    readonly protocol: "http" | "socks5" | "unknown"
  ) {
    super(message);
  }
}
