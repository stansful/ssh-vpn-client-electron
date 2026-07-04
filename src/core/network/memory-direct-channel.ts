import { EventEmitter } from "node:events";
import type { DirectTcpIpChannel } from "./local-tcp-proxy.js";

export class MemoryDirectTcpIpChannel implements DirectTcpIpChannel {
  private readonly events = new EventEmitter();
  private closed = false;
  readonly written: Buffer[] = [];

  async write(data: Buffer): Promise<void> {
    if (this.closed) {
      throw new Error("Direct TCP channel is closed.");
    }
    this.written.push(Buffer.from(data));
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.events.emit("close");
  }

  pushRemoteData(data: Buffer): void {
    if (!this.closed) {
      this.events.emit("data", data);
    }
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
