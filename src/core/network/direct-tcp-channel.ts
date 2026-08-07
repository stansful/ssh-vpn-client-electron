import { EventEmitter } from "node:events";
import net from "node:net";
import type { DirectTcpIpChannel, DirectTcpIpTarget } from "./local-tcp-proxy.js";
import { configureLowLatencySocket, isSocketWritable, writeSocketWithBackpressure } from "./socket-io.js";

export interface DirectEgressChannelOptions {
  connectTimeoutMs?: number;
  socketWriteTimeoutMs?: number;
  signal?: AbortSignal;
  createConnection?: (target: DirectTcpIpTarget) => net.Socket;
}

const DEFAULT_DIRECT_CONNECT_TIMEOUT_MS = 12_000;
const DEFAULT_DIRECT_WRITE_TIMEOUT_MS = 120_000;

/**
 * A {@link DirectTcpIpChannel} that leaves the machine directly instead of
 * entering the SSH tunnel.
 *
 * Per-process routing has to send every proxy-aware TCP connection to the local
 * listener, because Windows PAC cannot express process identity. Traffic that
 * does not match any routing rule must therefore be given an unchanged path to
 * its destination, and this channel is that path: an ordinary outbound socket,
 * created without consulting the system proxy, so non-selected applications
 * behave exactly as they would with the tunnel switched off.
 */
export async function openDirectEgressChannel(
  target: DirectTcpIpTarget,
  options: DirectEgressChannelOptions = {}
): Promise<DirectTcpIpChannel> {
  const connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_DIRECT_CONNECT_TIMEOUT_MS;
  const socketWriteTimeoutMs = options.socketWriteTimeoutMs ?? DEFAULT_DIRECT_WRITE_TIMEOUT_MS;
  options.signal?.throwIfAborted();

  const socket = options.createConnection
    ? options.createConnection(target)
    : net.connect({ host: target.host, port: target.port, allowHalfOpen: true });

  try {
    await waitForConnect(socket, target, connectTimeoutMs, options.signal);
  } catch (error) {
    socket.destroy();
    throw error;
  }

  configureLowLatencySocket(socket, { keepAlive: true });
  return new DirectEgressChannel(socket, socketWriteTimeoutMs);
}

class DirectEgressChannel implements DirectTcpIpChannel {
  private readonly events = new EventEmitter();
  private writeQueue: Promise<void> = Promise.resolve();
  private closed = false;

  constructor(
    private readonly socket: net.Socket,
    private readonly socketWriteTimeoutMs: number
  ) {
    // Listeners are attached once and re-emitted through an EventEmitter so the
    // proxy can subscribe and unsubscribe with the same semantics as an SSH
    // channel, without ever leaving the socket without an "error" listener.
    this.socket.on("data", (data: Buffer) => this.events.emit("data", data));
    this.socket.on("end", () => this.events.emit("end"));
    this.socket.on("close", () => {
      this.closed = true;
      this.events.emit("close");
    });
    this.socket.on("error", (error: Error) => this.events.emit("error", error));
  }

  write(data: Buffer): Promise<void> {
    if (data.length === 0) {
      return Promise.resolve();
    }
    const write = this.writeQueue.then(async () => {
      if (!isSocketWritable(this.socket)) {
        return;
      }
      await writeSocketWithBackpressure(this.socket, data, { timeoutMs: this.socketWriteTimeoutMs });
    });
    this.writeQueue = write.catch(() => undefined);
    return write;
  }

  async end(): Promise<void> {
    // Flush what the client already sent before signalling FIN, so a half-close
    // cannot truncate an in-flight request body.
    await this.writeQueue.catch(() => undefined);
    if (isSocketWritable(this.socket)) {
      this.socket.end();
    }
  }

  async close(): Promise<void> {
    await this.writeQueue.catch(() => undefined);
    if (!this.closed && !this.socket.destroyed) {
      this.socket.destroy();
    }
    this.closed = true;
  }

  onData(listener: (data: Buffer) => void): () => void {
    this.events.on("data", listener);
    return () => this.events.off("data", listener);
  }

  onEnd(listener: () => void): () => void {
    this.events.on("end", listener);
    return () => this.events.off("end", listener);
  }

  onClose(listener: () => void): () => void {
    this.events.on("close", listener);
    return () => this.events.off("close", listener);
  }

  onError(listener: (error: Error) => void): () => void {
    this.events.on("error", listener);
    return () => this.events.off("error", listener);
  }
}

function waitForConnect(
  socket: net.Socket,
  target: DirectTcpIpTarget,
  timeoutMs: number,
  signal: AbortSignal | undefined
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const timer = timeoutMs > 0
      ? setTimeout(() => finish(new Error(`Direct connection to ${target.host}:${target.port} timed out.`)), timeoutMs)
      : undefined;
    timer?.unref();
    const onAbort = (): void => finish(new Error(`Direct connection to ${target.host}:${target.port} was aborted.`));
    const finish = (error?: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (timer) {
        clearTimeout(timer);
      }
      signal?.removeEventListener("abort", onAbort);
      socket.off("connect", onConnect);
      socket.off("error", onError);
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    };
    const onConnect = (): void => finish();
    const onError = (error: Error): void =>
      finish(new Error(`Direct connection to ${target.host}:${target.port} failed: ${error.message}`));

    socket.once("connect", onConnect);
    socket.once("error", onError);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) {
      onAbort();
    }
  });
}
