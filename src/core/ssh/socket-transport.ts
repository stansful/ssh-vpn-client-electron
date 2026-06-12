import net from "node:net";
import { EventEmitter } from "node:events";
import { formatClientVersion, parseSshVersionLine, type ParsedSshVersion } from "./version.js";
import {
  SshEncryptedPacketStreamReader,
  SshEncryptedPacketStreamWriter,
  SshPlainPacketStreamReader,
  SshPlainPacketStreamWriter
} from "./packet-stream.js";
import type { PacketProtectionConfig } from "./packet-codec.js";

export interface SshTcpConnectOptions {
  host: string;
  port: number;
  timeoutMs?: number;
  clientSoftwareVersion?: string;
}

export interface SshIdentificationExchange {
  clientLine: string;
  serverLine: string;
  serverVersion: ParsedSshVersion;
}

export type SshPacketTransportEvent =
  | { type: "payload"; payload: Buffer }
  | { type: "error"; error: Error }
  | { type: "close" };

export class SshSocketTransport {
  private readonly events = new EventEmitter();
  private reader: SshPlainPacketStreamReader | SshEncryptedPacketStreamReader = new SshPlainPacketStreamReader();
  private writer: SshPlainPacketStreamWriter | SshEncryptedPacketStreamWriter = new SshPlainPacketStreamWriter();
  private packetReaderStarted = false;

  private constructor(private readonly socket: net.Socket) {
    socket.on("error", (error) => this.events.emit("event", { type: "error", error } satisfies SshPacketTransportEvent));
    socket.on("close", () => this.events.emit("event", { type: "close" } satisfies SshPacketTransportEvent));
  }

  static async connect(options: SshTcpConnectOptions): Promise<SshSocketTransport> {
    const socket = net.createConnection({ host: options.host, port: options.port });
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        socket.destroy(new Error("SSH TCP connect timeout."));
      }, options.timeoutMs ?? 10000);
      socket.once("connect", () => {
        clearTimeout(timeout);
        resolve();
      });
      socket.once("error", (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
    return new SshSocketTransport(socket);
  }

  static fromSocket(socket: net.Socket): SshSocketTransport {
    return new SshSocketTransport(socket);
  }

  onEvent(listener: (event: SshPacketTransportEvent) => void): () => void {
    this.events.on("event", listener);
    return () => this.events.off("event", listener);
  }

  async exchangeIdentification(clientSoftwareVersion?: string): Promise<SshIdentificationExchange> {
    const clientLine = formatClientVersion(clientSoftwareVersion).trimEnd();
    const serverLine = await readServerIdentificationLine(this.socket);
    this.socket.write(`${clientLine}\r\n`, "ascii");
    return {
      clientLine,
      serverLine,
      serverVersion: parseSshVersionLine(serverLine)
    };
  }

  send(payload: Buffer): void {
    this.startPacketReader();
    this.socket.write(this.writer.write(payload));
  }

  enableEncryption(inbound: PacketProtectionConfig, outbound: PacketProtectionConfig): void {
    this.reader = new SshEncryptedPacketStreamReader(inbound, this.reader.getSequenceNumber());
    this.writer = new SshEncryptedPacketStreamWriter(outbound, this.writer.getSequenceNumber());
  }

  close(): void {
    this.socket.end();
  }

  destroy(error?: Error): void {
    this.socket.destroy(error);
  }

  private handleData(chunk: Buffer): void {
    try {
      for (const payload of this.reader.push(chunk)) {
        this.events.emit("event", { type: "payload", payload } satisfies SshPacketTransportEvent);
      }
    } catch (error) {
      this.events.emit("event", { type: "error", error: error instanceof Error ? error : new Error(String(error)) } satisfies SshPacketTransportEvent);
      this.socket.destroy(error instanceof Error ? error : undefined);
    }
  }

  private startPacketReader(): void {
    if (this.packetReaderStarted) {
      return;
    }
    this.packetReaderStarted = true;
    this.socket.on("data", (chunk) => this.handleData(chunk));
    const buffered = this.socket.read();
    if (Buffer.isBuffer(buffered) && buffered.length > 0) {
      this.handleData(buffered);
    }
  }
}

export async function readServerIdentificationLine(socket: net.Socket, maxBytes = 8192): Promise<string> {
  let buffer = Buffer.alloc(0);

  return new Promise((resolve, reject) => {
    const cleanup = (): void => {
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
    };
    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };
    const onClose = (): void => {
      cleanup();
      reject(new Error("Socket closed before SSH identification."));
    };
    const onData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > maxBytes) {
        cleanup();
        reject(new Error("SSH identification exceeded maximum size."));
        return;
      }

      let newlineIndex = buffer.indexOf(0x0a);
      while (newlineIndex >= 0) {
        const line = buffer.subarray(0, newlineIndex + 1).toString("ascii").replace(/\r?\n$/u, "");
        buffer = buffer.subarray(newlineIndex + 1);
        if (line.startsWith("SSH-")) {
          cleanup();
          if (buffer.length > 0) {
            socket.unshift(buffer);
          }
          resolve(line);
          return;
        }
        newlineIndex = buffer.indexOf(0x0a);
      }
    };

    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
  });
}
