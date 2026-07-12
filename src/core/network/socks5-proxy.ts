import { EventEmitter } from "node:events";
import net from "node:net";
import type { DirectTcpIpChannel, DirectTcpIpTarget } from "./local-tcp-proxy.js";
import {
  configureLowLatencySocket,
  DEFAULT_PROXY_CONNECTION_QUEUE_BYTES,
  DEFAULT_PROXY_TOTAL_QUEUE_BYTES,
  isSocketWritable,
  writeSocketWithBackpressure
} from "./socket-io.js";

export interface Socks5ProxyOptions {
  listenHost?: string;
  listenPort?: number;
  idleTimeoutMs?: number;
  handshakeTimeoutMs?: number;
  socketWriteTimeoutMs?: number;
  maxQueuedSocketBytes?: number;
  maxTotalQueuedSocketBytes?: number;
  maxConnections?: number;
  maxPendingChannelOpens?: number;
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
  httpForwardBody?: {
    mode: "none" | "content-length" | "chunked" | "stream";
    contentLength?: number;
    initialData: Buffer;
  };
}

export class Socks5Proxy {
  private readonly events = new EventEmitter();
  private readonly sockets = new Set<net.Socket>();
  private totalQueuedSocketBytes = 0;
  private pendingChannelOpens = 0;
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

    this.server = net.createServer({ allowHalfOpen: true }, (socket) => {
      void this.handleSocket(socket);
    });
    this.server.on("error", (error) => {
      this.events.emit("event", { type: "error", message: `SOCKS/HTTP proxy server error: ${error.message}` } satisfies Socks5ProxyEvent);
    });

    try {
      await new Promise<void>((resolve, reject) => {
        this.server!.once("error", reject);
        this.server!.listen(this.options.listenPort ?? 0, this.options.listenHost ?? "127.0.0.1", () => {
          this.server!.off("error", reject);
          resolve();
        });
      });
    } catch (error) {
      this.server = undefined;
      throw error;
    }

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
    const maxConnections = this.options.maxConnections ?? 512;
    if (this.sockets.size >= maxConnections) {
      socket.destroy();
      this.events.emit("event", { type: "error", message: `SOCKS/HTTP proxy connection limit ${maxConnections} reached.` } satisfies Socks5ProxyEvent);
      return;
    }
    this.sockets.add(socket);
    configureLowLatencySocket(socket, { keepAlive: false });
    let request: ProxyConnectRequest | undefined;
    const handshakeTimeoutMs = this.options.handshakeTimeoutMs ?? 30_000;
    const handshakeDeadline = handshakeTimeoutMs > 0
      ? setTimeout(() => {
          socket.destroy(new ProxyHandshakeError("SOCKS/HTTP proxy handshake timed out.", "unknown"));
        }, handshakeTimeoutMs)
      : undefined;
    handshakeDeadline?.unref();
    const onHandshakeSocketError = (error: Error): void => {
      this.events.emit("event", { type: "error", message: error.message } satisfies Socks5ProxyEvent);
    };
    socket.on("error", onHandshakeSocketError);

    try {
      request = await readProxyConnectRequest(socket);
      if (handshakeDeadline) {
        clearTimeout(handshakeDeadline);
      }
      // ProxySocketReader temporarily switches the socket into flowing mode while
      // it parses the handshake. Keep it paused until the SSH channel and the
      // permanent data handler are ready; otherwise bytes arriving during
      // connectChannel() are emitted without a listener and are irretrievably
      // dropped (most visibly as a POST/PUT body that never reaches the server).
      socket.pause();
      const originator = {
        address: socket.remoteAddress ?? "127.0.0.1",
        port: socket.remotePort ?? 0
      };
      this.events.emit("event", {
        type: "connection",
        message: `${formatProtocol(request.protocol)} ${request.target.host}:${request.target.port} from ${originator.address}:${originator.port}.`
      } satisfies Socks5ProxyEvent);

      const onCloseWhileOpening = (): void => {
        this.sockets.delete(socket);
      };
      socket.once("close", onCloseWhileOpening);
      const releasePendingOpen = this.acquirePendingChannelOpen();
      if (!releasePendingOpen) {
        const limit = this.options.maxPendingChannelOpens ?? this.options.maxConnections ?? 512;
        throw new ProxyHandshakeError(
          `SOCKS/HTTP proxy pending SSH channel-open limit ${limit} reached.`,
          request.protocol === "socks5" ? "socks5" : "http"
        );
      }
      let channel: DirectTcpIpChannel;
      try {
        channel = await this.options.connectChannel(request.target, originator);
      } finally {
        releasePendingOpen();
      }
      if (socket.destroyed) {
        socket.off("close", onCloseWhileOpening);
        socket.off("error", onHandshakeSocketError);
        await channel.close();
        return;
      }
      socket.off("close", onCloseWhileOpening);
      this.events.emit("event", {
        type: "tunnel-opened",
        message: `${formatProtocol(request.protocol)} tunnel opened for ${request.target.host}:${request.target.port}.`
      } satisfies Socks5ProxyEvent);
      this.configureIdleTimeout(socket);
      socket.off("error", onHandshakeSocketError);
      let queuedSocketBytes = 0;
      let socketWriteQueue = Promise.resolve();
      // Match the default 16 MiB SSH receive window so a legitimate remote
      // burst can be drained with backpressure instead of being disconnected.
      const maxQueuedSocketBytes = this.options.maxQueuedSocketBytes ?? DEFAULT_PROXY_CONNECTION_QUEUE_BYTES;
      const maxTotalQueuedSocketBytes = this.options.maxTotalQueuedSocketBytes ?? DEFAULT_PROXY_TOTAL_QUEUE_BYTES;
      const socketWriteTimeoutMs = this.options.socketWriteTimeoutMs ?? 120_000;
      const enqueueSocketWrite = (data: Buffer): void => {
        if (data.length === 0 || !isSocketWritable(socket)) {
          return;
        }
        if (queuedSocketBytes + data.length > maxQueuedSocketBytes || this.totalQueuedSocketBytes + data.length > maxTotalQueuedSocketBytes) {
          socket.destroy(new Error("Proxy downstream queue limit reached."));
          return;
        }
        queuedSocketBytes += data.length;
        this.totalQueuedSocketBytes += data.length;
        socketWriteQueue = socketWriteQueue
          .then(async () => {
            if (!isSocketWritable(socket)) {
              return;
            }
            await writeSocketWithBackpressure(socket, data, { timeoutMs: socketWriteTimeoutMs });
            await channel.acknowledgeData?.(data.length);
          })
          .finally(() => {
            queuedSocketBytes = Math.max(0, queuedSocketBytes - data.length);
            this.totalQueuedSocketBytes = Math.max(0, this.totalQueuedSocketBytes - data.length);
          })
          .catch((error: unknown) => {
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

      const httpBodyGate = request.httpForwardBody ? new HttpForwardBodyGate(request.httpForwardBody) : undefined;
      let requestUploadComplete = false;
      const forwardClientData = async (data: Buffer): Promise<boolean> => {
        if (!httpBodyGate) {
          await channel.write(data);
          return false;
        }
        const result = httpBodyGate.consume(data);
        if (result.forward.length > 0) {
          await channel.write(result.forward);
        }
        if (!result.complete) {
          return false;
        }
        requestUploadComplete = true;
        await (channel.end?.() ?? channel.close());
        if (result.extra.length > 0) {
          this.events.emit("event", {
            type: "error",
            message: "HTTP proxy connection attempted another request after its one-request upstream was half-closed."
          } satisfies Socks5ProxyEvent);
        }
        return true;
      };
      const writeToChannel = (data: Buffer): void => {
        socket.pause();
        void forwardClientData(data)
          .then((complete) => {
            if (!complete && !socket.destroyed) {
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
      socket.on("end", () => {
        void (channel.end?.() ?? channel.close()).catch((error: unknown) => {
          if (!socket.destroyed) {
            socket.destroy(error instanceof Error ? error : new Error(String(error)));
          }
        });
      });
      socket.on("close", () => {
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
        await channel.write(request.initialData);
      }
      if (request.httpForwardBody) {
        await forwardClientData(request.httpForwardBody.initialData);
      }
      if (!requestUploadComplete && !socket.destroyed) {
        socket.resume();
      }
    } catch (error) {
      if (handshakeDeadline) {
        clearTimeout(handshakeDeadline);
      }
      socket.off("error", onHandshakeSocketError);
      this.sockets.delete(socket);
      const responseAlreadySent = error instanceof ProxyHandshakeError && error.responseAlreadySent;
      if (!responseAlreadySent) {
        writeProxyFailure(socket, isHttpHandshakeError(error) ? "http" : "socks5");
      }
      if (!socket.destroyed) {
        // Flush the small protocol error response before tearing down the
        // socket. destroy() immediately after write() commonly turns a useful
        // 502/SOCKS failure into an opaque ECONNRESET for the local client.
        socket.end(() => socket.destroy());
      }
      this.events.emit("event", {
        type: "error",
        message: formatProxyTunnelError(request, error instanceof Error ? error.message : String(error))
      } satisfies Socks5ProxyEvent);
    }
  }

  private configureIdleTimeout(socket: net.Socket): void {
    const idleTimeoutMs = this.options.idleTimeoutMs ?? 5 * 60 * 1000;
    if (idleTimeoutMs <= 0) {
      return;
    }
    // Let net.Socket maintain one native inactivity deadline instead of
    // allocating and cancelling a JavaScript timer for every traffic chunk.
    socket.setTimeout(idleTimeoutMs, () => {
      if (!socket.destroyed) {
        socket.destroy(new Error("SOCKS5 connection idle timeout."));
      }
    });
  }

  private acquirePendingChannelOpen(): (() => void) | undefined {
    const maximum = this.options.maxPendingChannelOpens ?? this.options.maxConnections ?? 512;
    if (!Number.isInteger(maximum) || maximum <= 0 || this.pendingChannelOpens >= maximum) {
      return undefined;
    }
    this.pendingChannelOpens += 1;
    let released = false;
    return () => {
      if (released) {
        return;
      }
      released = true;
      this.pendingChannelOpens = Math.max(0, this.pendingChannelOpens - 1);
    };
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
    try {
      return await readHttpProxyRequest(reader, firstByte);
    } catch (error) {
      if (error instanceof ProxyHandshakeError) {
        throw error;
      }
      throw new ProxyHandshakeError(error instanceof Error ? error.message : String(error), "http");
    }
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
    throw new ProxyHandshakeError("SOCKS5 client does not support no-auth mode.", "socks5", true);
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
    if (length === 0) {
      throw new Error("SOCKS5 target host is empty.");
    }
    host = (await reader.read(length)).toString("utf8");
  } else if (addressType === 0x04) {
    host = formatIpv6(await reader.read(16));
  } else {
    throw new Error(`Unsupported SOCKS5 address type ${addressType}.`);
  }
  const portBytes = await reader.read(2);
  const port = portBytes.readUInt16BE(0);
  if (port === 0) {
    throw new Error("SOCKS5 target port must be between 1 and 65535.");
  }
  return { host, port };
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
  const websocketUpgrade = isWebSocketUpgrade(headers);
  const body = describeHttpForwardBody(lines, headers, websocketUpgrade);
  const rewrittenHeader = rewriteHttpProxyHeader(requestLine, lines, parsed.path, !websocketUpgrade);
  return {
    protocol: "http-forward",
    target: parsed.target,
    initialData: Buffer.from(rewrittenHeader, "latin1"),
    httpForwardBody: {
      ...body,
      initialData: rest
    }
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
        if (headerEnd + 4 > maxHeaderBytes) {
          throw new ProxyHandshakeError("HTTP proxy request header is too large.", "http");
        }
        return {
          header: headerBuffer.subarray(0, headerEnd + 4),
          rest: headerBuffer.subarray(headerEnd + 4)
        };
      }
      if (headerBuffer.length >= maxHeaderBytes) {
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
        // A one-shot `data` listener leaves a Node socket in flowing mode after
        // it removes itself. Pause before resolving so a following TCP chunk
        // cannot be emitted (and discarded) while the parser is between reads.
        this.socket.pause();
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
      this.socket.resume();
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
    if (/^[ \t]/u.test(line)) {
      throw new ProxyHandshakeError("Obsolete folded HTTP proxy headers are not supported.", "http");
    }
    const separator = line.indexOf(":");
    if (separator <= 0) {
      throw new ProxyHandshakeError("Malformed HTTP proxy request header.", "http");
    }
    const rawName = line.slice(0, separator);
    if (rawName !== rawName.trim() || !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u.test(rawName)) {
      throw new ProxyHandshakeError("Malformed HTTP proxy request header name.", "http");
    }
    const name = rawName.toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (/[^\t\x20-\x7e\x80-\xff]/u.test(value)) {
      throw new ProxyHandshakeError("Malformed HTTP proxy request header value.", "http");
    }
    if (headers.has(name) && (name === "host" || name === "transfer-encoding")) {
      throw new ProxyHandshakeError(`Duplicate HTTP proxy ${name} header.`, "http");
    }
    if (headers.has(name) && name === "connection") {
      headers.set(name, `${headers.get(name)},${value}`);
      continue;
    }
    headers.set(name, value);
  }
  return headers;
}

function parseHttpForwardTarget(requestTarget: string, hostHeader: string | undefined): { target: DirectTcpIpTarget; path: string } {
  if (/^(?:http|ws)s?:\/\//iu.test(requestTarget)) {
    const url = new URL(requestTarget);
    if (url.protocol !== "http:" && url.protocol !== "ws:") {
      throw new ProxyHandshakeError("HTTPS/WSS absolute-form requests require HTTP CONNECT.", "http");
    }
    return {
      target: {
        host: url.hostname.replace(/^\[(.*)\]$/u, "$1"),
        port: url.port ? Number(url.port) : 80
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

function rewriteHttpProxyHeader(requestLine: string, lines: string[], path: string, forceClose: boolean): string {
  const [method, , version] = requestLine.split(/\s+/u);
  const filteredHeaders = lines.filter(
    (line) => Boolean(line) &&
      !/^proxy-(?:authorization|connection)\s*:/iu.test(line) &&
      (!forceClose || !/^connection\s*:/iu.test(line))
  );
  if (forceClose) {
    filteredHeaders.push("Connection: close");
  }
  return [`${method} ${path} ${version}`, ...filteredHeaders, "", ""].join("\r\n");
}

function isWebSocketUpgrade(headers: Map<string, string>): boolean {
  return headers.get("upgrade")?.toLowerCase() === "websocket" &&
    headers.get("connection")?.toLowerCase().split(",").some((token) => token.trim() === "upgrade") === true;
}

function describeHttpForwardBody(
  lines: string[],
  headers: Map<string, string>,
  stream: boolean
): { mode: "none" | "content-length" | "chunked" | "stream"; contentLength?: number } {
  const hasTransferEncoding = headers.has("transfer-encoding");
  const transferEncoding = headers.get("transfer-encoding")?.toLowerCase() ?? "";
  const contentLengthValues = lines
    .filter((line) => /^content-length\s*:/iu.test(line))
    .map((line) => line.slice(line.indexOf(":") + 1).trim());
  if (hasTransferEncoding && contentLengthValues.length > 0) {
    throw new ProxyHandshakeError("HTTP proxy request has ambiguous body framing.", "http");
  }
  let chunked = false;
  if (hasTransferEncoding) {
    const encodings = transferEncoding.split(",").map((value) => value.trim()).filter(Boolean);
    if (encodings.at(-1) !== "chunked") {
      throw new ProxyHandshakeError("Unsupported HTTP proxy Transfer-Encoding.", "http");
    }
    chunked = true;
  }
  let contentLength = 0;
  if (contentLengthValues.length > 0) {
    if (new Set(contentLengthValues).size !== 1 || !/^\d+$/u.test(contentLengthValues[0])) {
      throw new ProxyHandshakeError("Invalid HTTP proxy Content-Length.", "http");
    }
    contentLength = Number(contentLengthValues[0]);
    if (!Number.isSafeInteger(contentLength) || contentLength < 0) {
      throw new ProxyHandshakeError("Invalid HTTP proxy Content-Length.", "http");
    }
  }
  if (stream) {
    if (chunked || contentLength > 0) {
      throw new ProxyHandshakeError("WebSocket proxy upgrades cannot include an HTTP request body.", "http");
    }
    return { mode: "stream" };
  }
  if (chunked) {
    return { mode: "chunked" };
  }
  return contentLength === 0 ? { mode: "none" } : { mode: "content-length", contentLength };
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
    if (rest === "") {
      return { host, port: defaultPort };
    }
    if (!rest.startsWith(":")) {
      throw new Error("Invalid IPv6 proxy target.");
    }
    return { host, port: parsePort(rest.slice(1)) };
  }
  const separator = trimmed.lastIndexOf(":");
  if (separator > 0 && trimmed.indexOf(":") === separator) {
    return { host: trimmed.slice(0, separator), port: parsePort(trimmed.slice(separator + 1)) };
  }
  if (separator >= 0) {
    throw new Error("IPv6 proxy targets must use bracket notation.");
  }
  return { host: trimmed, port: defaultPort };
}

function parsePort(value: string): number {
  if (!value) {
    throw new Error("Proxy target port is empty.");
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

class HttpForwardBodyGate {
  private readonly mode: "none" | "content-length" | "chunked" | "stream";
  private remainingContentBytes: number;
  private chunkState: "size" | "data" | "data-crlf" | "trailers" = "size";
  private remainingChunkBytes = 0;
  private lineBuffer = "";
  private dataCrlfOffset = 0;
  private trailerBytes = 0;
  private completed = false;

  constructor(spec: NonNullable<ProxyConnectRequest["httpForwardBody"]>) {
    this.mode = spec.mode;
    this.remainingContentBytes = spec.contentLength ?? 0;
    this.completed = spec.mode === "none";
  }

  consume(data: Buffer): { forward: Buffer; extra: Buffer; complete: boolean } {
    if (this.mode === "stream") {
      return { forward: data, extra: Buffer.alloc(0), complete: false };
    }
    if (this.completed) {
      return { forward: Buffer.alloc(0), extra: data, complete: true };
    }
    if (this.mode === "content-length") {
      const forwardedBytes = Math.min(this.remainingContentBytes, data.length);
      this.remainingContentBytes -= forwardedBytes;
      this.completed = this.remainingContentBytes === 0;
      return {
        forward: data.subarray(0, forwardedBytes),
        extra: data.subarray(forwardedBytes),
        complete: this.completed
      };
    }

    let offset = 0;
    while (offset < data.length && !this.completed) {
      if (this.chunkState === "data") {
        const consumed = Math.min(this.remainingChunkBytes, data.length - offset);
        this.remainingChunkBytes -= consumed;
        offset += consumed;
        if (this.remainingChunkBytes === 0) {
          this.chunkState = "data-crlf";
        }
        continue;
      }
      if (this.chunkState === "data-crlf") {
        const expected = this.dataCrlfOffset === 0 ? 0x0d : 0x0a;
        if (data[offset] !== expected) {
          throw new ProxyHandshakeError("Malformed chunked HTTP proxy request body.", "http");
        }
        offset += 1;
        this.dataCrlfOffset += 1;
        if (this.dataCrlfOffset === 2) {
          this.dataCrlfOffset = 0;
          this.chunkState = "size";
        }
        continue;
      }

      const character = data[offset];
      offset += 1;
      this.lineBuffer += String.fromCharCode(character);
      if (this.chunkState === "trailers") {
        this.trailerBytes += 1;
        if (this.trailerBytes > 64 * 1024) {
          throw new ProxyHandshakeError("Chunked HTTP proxy trailers are too large.", "http");
        }
      }
      if (this.lineBuffer.length > 8 * 1024) {
        throw new ProxyHandshakeError("Chunked HTTP proxy line is too large.", "http");
      }
      if (!this.lineBuffer.endsWith("\r\n")) {
        continue;
      }
      const line = this.lineBuffer.slice(0, -2);
      this.lineBuffer = "";
      if (this.chunkState === "trailers") {
        if (line === "") {
          this.completed = true;
        }
        continue;
      }

      const sizeToken = line.split(";", 1)[0].trim();
      if (!/^[0-9a-f]+$/iu.test(sizeToken)) {
        throw new ProxyHandshakeError("Malformed chunked HTTP proxy request size.", "http");
      }
      const size = Number.parseInt(sizeToken, 16);
      if (!Number.isSafeInteger(size) || size < 0) {
        throw new ProxyHandshakeError("Invalid chunked HTTP proxy request size.", "http");
      }
      if (size === 0) {
        this.chunkState = "trailers";
      } else {
        this.remainingChunkBytes = size;
        this.chunkState = "data";
      }
    }

    return {
      forward: data.subarray(0, offset),
      extra: data.subarray(offset),
      complete: this.completed
    };
  }
}

class ProxyHandshakeError extends Error {
  constructor(
    message: string,
    readonly protocol: "http" | "socks5" | "unknown",
    readonly responseAlreadySent = false
  ) {
    super(message);
  }
}
