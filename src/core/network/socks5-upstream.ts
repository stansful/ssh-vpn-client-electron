import net from "node:net";
import {
  createSocketBackedChannel,
  DEFAULT_DIRECT_WRITE_TIMEOUT_MS,
  waitForConnect
} from "./direct-tcp-channel.js";
import type { DirectTcpIpChannel, DirectTcpIpTarget } from "./local-tcp-proxy.js";
import { buildSocks5ConnectRequest } from "./socks5-check.js";
import { configureLowLatencySocket } from "./socket-io.js";

export interface Socks5UpstreamOptions {
  connectTimeoutMs?: number;
  handshakeTimeoutMs?: number;
  socketWriteTimeoutMs?: number;
  signal?: AbortSignal;
  createConnection?: (proxy: { host: string; port: number }) => net.Socket;
}

const DEFAULT_UPSTREAM_CONNECT_TIMEOUT_MS = 12_000;
const DEFAULT_UPSTREAM_HANDSHAKE_TIMEOUT_MS = 12_000;
/** A SOCKS5 reply is at most 262 bytes; anything larger is a protocol fault. */
const MAX_HANDSHAKE_BUFFER_BYTES = 512;

/**
 * Opens a channel to `target` through a local SOCKS5 proxy.
 *
 * Per-process routing has to place our own listener in front of the transport's
 * proxy, so that the owning process can be identified before the destination is
 * chosen. Traffic that must be tunnelled is then handed to the transport
 * through its ordinary SOCKS5 inbound with this channel.
 */
export async function openSocks5UpstreamChannel(
  proxy: { host: string; port: number },
  target: DirectTcpIpTarget,
  options: Socks5UpstreamOptions = {}
): Promise<DirectTcpIpChannel> {
  const handshakeTimeoutMs = options.handshakeTimeoutMs ?? DEFAULT_UPSTREAM_HANDSHAKE_TIMEOUT_MS;
  options.signal?.throwIfAborted();

  const socket = options.createConnection
    ? options.createConnection(proxy)
    : net.connect({ host: proxy.host, port: proxy.port, allowHalfOpen: true });

  try {
    await waitForConnect(
      socket,
      { host: proxy.host, port: proxy.port },
      options.connectTimeoutMs ?? DEFAULT_UPSTREAM_CONNECT_TIMEOUT_MS,
      options.signal
    );
    configureLowLatencySocket(socket, { keepAlive: true });
    await performSocks5Handshake(socket, target, handshakeTimeoutMs, options.signal);
  } catch (error) {
    socket.destroy();
    throw error;
  }

  return createSocketBackedChannel(socket, options.socketWriteTimeoutMs ?? DEFAULT_DIRECT_WRITE_TIMEOUT_MS);
}

async function performSocks5Handshake(
  socket: net.Socket,
  target: DirectTcpIpTarget,
  timeoutMs: number,
  signal: AbortSignal | undefined
): Promise<void> {
  const reader = new HandshakeReader(socket, timeoutMs, signal);
  try {
    socket.write(Buffer.from([0x05, 0x01, 0x00]));
    const greeting = await reader.readAtLeast(2);
    if (greeting[0] !== 0x05 || greeting[1] !== 0x00) {
      throw new Error("Upstream SOCKS5 proxy rejected the no-auth handshake.");
    }
    reader.consume(2);

    socket.write(buildSocks5ConnectRequest(target));
    const header = await reader.readAtLeast(5);
    if (header[0] !== 0x05) {
      throw new Error("Upstream SOCKS5 proxy returned an unsupported reply version.");
    }
    if (header[1] !== 0x00) {
      throw new Error(
        `Upstream SOCKS5 proxy refused ${target.host}:${target.port} with code ${header[1]}.`
      );
    }
    const replyLength = socks5ReplyLength(header);
    if (replyLength === undefined) {
      throw new Error("Upstream SOCKS5 proxy returned an unsupported address type.");
    }
    await reader.readAtLeast(replyLength);
    reader.consume(replyLength);
  } finally {
    // Bytes that arrived in the same segment after the reply already belong to
    // the payload stream, so they are pushed back before the channel starts
    // reading; dropping them would silently corrupt the first response.
    reader.release();
  }
}

function socks5ReplyLength(header: Buffer): number | undefined {
  const addressType = header[3];
  if (addressType === 0x01) {
    return 4 + 4 + 2;
  }
  if (addressType === 0x04) {
    return 4 + 16 + 2;
  }
  if (addressType === 0x03) {
    return 4 + 1 + header[4] + 2;
  }
  return undefined;
}

/**
 * Reads the handshake without putting the socket into flowing mode, so that
 * leftover payload bytes can be returned to the stream afterwards.
 */
class HandshakeReader {
  private buffer = Buffer.alloc(0);

  constructor(
    private readonly socket: net.Socket,
    private readonly timeoutMs: number,
    private readonly signal: AbortSignal | undefined
  ) {}

  async readAtLeast(byteCount: number): Promise<Buffer> {
    while (this.buffer.length < byteCount) {
      const chunk = await this.readChunk();
      this.buffer = Buffer.concat([this.buffer, chunk]);
      if (this.buffer.length > MAX_HANDSHAKE_BUFFER_BYTES) {
        throw new Error("Upstream SOCKS5 proxy sent an oversized handshake reply.");
      }
    }
    return this.buffer;
  }

  consume(byteCount: number): void {
    this.buffer = this.buffer.subarray(byteCount);
  }

  release(): void {
    if (this.buffer.length > 0 && !this.socket.destroyed) {
      this.socket.unshift(this.buffer);
    }
    this.buffer = Buffer.alloc(0);
  }

  private readChunk(): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      let settled = false;
      const timer = this.timeoutMs > 0
        ? setTimeout(() => finish(new Error("Upstream SOCKS5 handshake timed out.")), this.timeoutMs)
        : undefined;
      timer?.unref();
      const onAbort = (): void => finish(new Error("Upstream SOCKS5 handshake was aborted."));
      const onReadable = (): void => {
        const chunk = this.socket.read() as Buffer | null;
        if (chunk && chunk.length > 0) {
          finish(undefined, chunk);
        }
      };
      const onEnd = (): void => finish(new Error("Upstream SOCKS5 proxy closed the connection during the handshake."));
      const onError = (error: Error): void => finish(new Error(`Upstream SOCKS5 proxy failed: ${error.message}`));
      const finish = (error?: Error, chunk?: Buffer): void => {
        if (settled) {
          return;
        }
        settled = true;
        if (timer) {
          clearTimeout(timer);
        }
        this.signal?.removeEventListener("abort", onAbort);
        this.socket.off("readable", onReadable);
        this.socket.off("end", onEnd);
        this.socket.off("error", onError);
        if (error) {
          reject(error);
        } else {
          resolve(chunk ?? Buffer.alloc(0));
        }
      };

      this.socket.on("readable", onReadable);
      this.socket.once("end", onEnd);
      this.socket.once("error", onError);
      this.signal?.addEventListener("abort", onAbort, { once: true });
      if (this.signal?.aborted) {
        onAbort();
        return;
      }
      onReadable();
    });
  }
}
