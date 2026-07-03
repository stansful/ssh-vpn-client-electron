import { EventEmitter } from "node:events";
import net from "node:net";
import { configureLowLatencySocket, isSocketWritable, writeSocketWithBackpressure } from "./socket-io.js";

export interface DirectTcpIpTarget {
  host: string;
  port: number;
}

export interface DirectTcpIpChannel {
  write(data: Buffer): Promise<void>;
  close(): Promise<void>;
  onData(listener: (data: Buffer) => void): () => void;
  onClose(listener: () => void): () => void;
  onError(listener: (error: Error) => void): () => void;
}

export interface LocalTcpProxyOptions {
  listenHost?: string;
  listenPort: number;
  target: DirectTcpIpTarget;
  socketWriteTimeoutMs?: number;
  maxQueuedSocketBytes?: number;
  connectChannel(target: DirectTcpIpTarget, originator: { address: string; port: number }): Promise<DirectTcpIpChannel>;
}

export interface LocalTcpProxyConnectionEvent {
  type: "connection" | "connection-closed" | "error";
  message: string;
}

export class LocalTcpProxy {
  private readonly events = new EventEmitter();
  private readonly sockets = new Set<net.Socket>();
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

    this.server = net.createServer((socket) => {
      void this.handleSocket(socket);
    });

    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(this.options.listenPort, this.options.listenHost ?? "127.0.0.1", () => {
        this.server!.off("error", reject);
        resolve();
      });
    });

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
    this.sockets.add(socket);
    configureLowLatencySocket(socket);
    const originator = {
      address: socket.remoteAddress ?? "127.0.0.1",
      port: socket.remotePort ?? 0
    };
    this.events.emit("event", {
      type: "connection",
      message: `Accepted local TCP connection from ${originator.address}:${originator.port}.`
    } satisfies LocalTcpProxyConnectionEvent);

    try {
      const channel = await this.options.connectChannel(this.options.target, originator);
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
        enqueueSocketWrite(data);
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
      socket.on("close", () => {
        offData();
        offClose();
        offError();
        this.sockets.delete(socket);
        void channel.close();
        this.events.emit("event", { type: "connection-closed", message: "Local TCP connection closed." } satisfies LocalTcpProxyConnectionEvent);
      });
      socket.on("error", (error) => {
        this.events.emit("event", { type: "error", message: error.message } satisfies LocalTcpProxyConnectionEvent);
      });
    } catch (error) {
      this.sockets.delete(socket);
      socket.destroy(error instanceof Error ? error : new Error(String(error)));
      this.events.emit("event", {
        type: "error",
        message: error instanceof Error ? error.message : String(error)
      } satisfies LocalTcpProxyConnectionEvent);
    }
  }
}
