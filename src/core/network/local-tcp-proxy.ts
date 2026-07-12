import { EventEmitter } from "node:events";
import net from "node:net";
import {
  configureLowLatencySocket,
  DEFAULT_PROXY_CONNECTION_QUEUE_BYTES,
  DEFAULT_PROXY_TOTAL_QUEUE_BYTES,
  isSocketWritable,
  writeSocketWithBackpressure
} from "./socket-io.js";

export interface DirectTcpIpTarget {
  host: string;
  port: number;
}

export interface DirectTcpIpChannel {
  write(data: Buffer): Promise<void>;
  acknowledgeData?(bytes: number): Promise<void>;
  end?(): Promise<void>;
  close(): Promise<void>;
  onData(listener: (data: Buffer) => void): () => void;
  onEnd(listener: () => void): () => void;
  onClose(listener: () => void): () => void;
  onError(listener: (error: Error) => void): () => void;
}

export interface LocalTcpProxyOptions {
  listenHost?: string;
  listenPort: number;
  target: DirectTcpIpTarget;
  socketWriteTimeoutMs?: number;
  idleTimeoutMs?: number;
  maxQueuedSocketBytes?: number;
  maxTotalQueuedSocketBytes?: number;
  maxConnections?: number;
  maxPendingChannelOpens?: number;
  connectChannel(target: DirectTcpIpTarget, originator: { address: string; port: number }): Promise<DirectTcpIpChannel>;
}

export interface LocalTcpProxyConnectionEvent {
  type: "connection" | "connection-closed" | "error";
  message: string;
}

export class LocalTcpProxy {
  private readonly events = new EventEmitter();
  private readonly sockets = new Set<net.Socket>();
  private totalQueuedSocketBytes = 0;
  private pendingChannelOpens = 0;
  private server?: net.Server;

  constructor(private readonly options: LocalTcpProxyOptions) {}

  onEvent(listener: (event: LocalTcpProxyConnectionEvent) => void): () => void {
    this.events.on("event", listener);
    return () => this.events.off("event", listener);
  }

  async start(): Promise<{ host: string; port: number }> {
    if (this.server) {
      const address = this.server.address();
      if (typeof address === "object" && address) {
        return { host: address.address, port: address.port };
      }
      throw new Error("Local TCP proxy is already started without a TCP address.");
    }

    this.server = net.createServer({ allowHalfOpen: true }, (socket) => {
      void this.handleSocket(socket);
    });
    this.server.on("error", (error) => {
      this.events.emit("event", { type: "error", message: `Local TCP proxy server error: ${error.message}` } satisfies LocalTcpProxyConnectionEvent);
    });

    try {
      await new Promise<void>((resolve, reject) => {
        this.server!.once("error", reject);
        this.server!.listen(this.options.listenPort, this.options.listenHost ?? "127.0.0.1", () => {
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
      throw new Error("Local TCP proxy did not bind a TCP address.");
    }
    return { host: address.address, port: address.port };
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
      this.events.emit("event", { type: "error", message: `Local TCP proxy connection limit ${maxConnections} reached.` } satisfies LocalTcpProxyConnectionEvent);
      return;
    }
    this.sockets.add(socket);
    configureLowLatencySocket(socket, { keepAlive: false });
    const onSocketError = (error: Error): void => {
      this.events.emit("event", { type: "error", message: error.message } satisfies LocalTcpProxyConnectionEvent);
    };
    const onCloseWhileOpening = (): void => {
      this.sockets.delete(socket);
    };
    socket.on("error", onSocketError);
    socket.once("close", onCloseWhileOpening);
    const originator = {
      address: socket.remoteAddress ?? "127.0.0.1",
      port: socket.remotePort ?? 0
    };
    this.events.emit("event", {
      type: "connection",
      message: `Accepted local TCP connection from ${originator.address}:${originator.port}.`
    } satisfies LocalTcpProxyConnectionEvent);

    try {
      const releasePendingOpen = this.acquirePendingChannelOpen();
      if (!releasePendingOpen) {
        const limit = this.options.maxPendingChannelOpens ?? this.options.maxConnections ?? 512;
        throw new Error(`Local TCP proxy pending SSH channel-open limit ${limit} reached.`);
      }
      let channel: DirectTcpIpChannel;
      try {
        channel = await this.options.connectChannel(this.options.target, originator);
      } finally {
        releasePendingOpen();
      }
      if (socket.destroyed) {
        socket.off("close", onCloseWhileOpening);
        socket.off("error", onSocketError);
        await channel.close();
        return;
      }
      socket.off("close", onCloseWhileOpening);
      this.configureIdleTimeout(socket);
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
          socket.destroy(new Error("Local proxy downstream queue limit reached."));
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
        this.events.emit("event", { type: "error", message: error.message } satisfies LocalTcpProxyConnectionEvent);
        socket.destroy(error);
      });

      socket.on("data", (data) => {
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
      });
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
        socket.off("error", onSocketError);
        void channel.close();
        this.events.emit("event", { type: "connection-closed", message: "Local TCP connection closed." } satisfies LocalTcpProxyConnectionEvent);
      });
    } catch (error) {
      socket.off("close", onCloseWhileOpening);
      socket.off("error", onSocketError);
      this.sockets.delete(socket);
      socket.destroy();
      this.events.emit("event", {
        type: "error",
        message: error instanceof Error ? error.message : String(error)
      } satisfies LocalTcpProxyConnectionEvent);
    }
  }

  private configureIdleTimeout(socket: net.Socket): void {
    const idleTimeoutMs = this.options.idleTimeoutMs ?? 5 * 60 * 1000;
    if (idleTimeoutMs <= 0) {
      return;
    }
    // net.Socket refreshes this native inactivity deadline on reads and writes,
    // avoiding a clearTimeout/setTimeout pair for every proxied data chunk.
    socket.setTimeout(idleTimeoutMs, () => {
      if (!socket.destroyed) {
        socket.destroy(new Error("Local TCP proxy connection idle timeout."));
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
