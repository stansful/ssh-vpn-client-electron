import net from "node:net";
import { EventEmitter } from "node:events";
import { configureLowLatencySocket } from "../network/socket-io.js";
import { formatClientVersion, parseSshVersionLine, type ParsedSshVersion } from "./version.js";
import {
  SshEncryptedPacketStreamReader,
  SshEncryptedPacketStreamWriter,
  SshPlainPacketStreamReader,
  SshPlainPacketStreamWriter
} from "./packet-stream.js";
import type { PacketProtectionConfig } from "./packet-codec.js";

const EMPTY_BUFFER = Buffer.alloc(0);
// This is a bounded write pipeline, not an eager allocation. It lets the
// single SSH TCP connection retain enough admitted upload data for high-BDP
// links even when Node's much smaller stream HWM reports backpressure.
export const DEFAULT_SSH_SOCKET_PIPELINE_BYTES = 4 * 1024 * 1024;

export interface SshTcpConnectOptions {
  host: string;
  port: number;
  timeoutMs?: number;
  clientSoftwareVersion?: string;
  keepAliveInitialDelayMs?: number;
}

export interface SshTransportLimits {
  maximumOutboundQueueBytes?: number;
  maximumControlQueueBytes?: number;
  maximumSocketPipelineBytes?: number;
  writeTimeoutMs?: number;
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

type OutboundQueueEntry = {
  payload: Buffer;
  bulk: boolean;
  resolve: () => void;
  reject: (error: Error) => void;
};

export class SshSocketTransport {
  private readonly events = new EventEmitter();
  private reader: SshPlainPacketStreamReader | SshEncryptedPacketStreamReader = new SshPlainPacketStreamReader();
  private writer: SshPlainPacketStreamWriter | SshEncryptedPacketStreamWriter = new SshPlainPacketStreamWriter();
  private packetReaderStarted = false;
  private pauseAfterMessageNumber: number | undefined;
  private packetParsingPaused = false;
  private pendingInboundProtection: PacketProtectionConfig | undefined;
  private readonly outboundQueue: OutboundQueueEntry[] = [];
  private readonly outboundPriorityQueue: OutboundQueueEntry[] = [];
  private readonly outboundKexQueue: OutboundQueueEntry[] = [];
  private outboundQueueBytes = 0;
  private outboundBulkQueueBytes = 0;
  private outboundPumpRunning = false;
  private outboundFrameInProgress = false;
  private runtimeKeyExchangeActive = false;
  private unusable = false;
  private bytesSent = 0;
  private bytesReceived = 0;
  private readonly maximumOutboundQueueBytes: number;
  private readonly maximumControlQueueBytes: number;
  private readonly maximumSocketPipelineBytes: number;
  private readonly writeTimeoutMs: number;

  private constructor(private readonly socket: net.Socket, limits: SshTransportLimits = {}) {
    this.maximumOutboundQueueBytes = limits.maximumOutboundQueueBytes ?? 8 * 1024 * 1024;
    this.maximumControlQueueBytes = limits.maximumControlQueueBytes ?? 512 * 1024;
    this.maximumSocketPipelineBytes = limits.maximumSocketPipelineBytes ?? DEFAULT_SSH_SOCKET_PIPELINE_BYTES;
    this.writeTimeoutMs = limits.writeTimeoutMs ?? 120_000;
    socket.on("error", (error) => this.events.emit("event", { type: "error", error } satisfies SshPacketTransportEvent));
    socket.on("close", () => {
      this.unusable = true;
      this.rejectOutboundQueue(new Error("SSH transport closed."));
      this.events.emit("event", { type: "close" } satisfies SshPacketTransportEvent);
    });
  }

  static async connect(options: SshTcpConnectOptions): Promise<SshSocketTransport> {
    const socket = net.createConnection({ host: options.host, port: options.port });
    configureLowLatencySocket(socket, { keepAliveInitialDelayMs: options.keepAliveInitialDelayMs });
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        socket.destroy(new Error(`SSH TCP connect timeout for ${options.host}:${options.port}.`));
      }, options.timeoutMs ?? 10000);
      timeout.unref();
      const onConnect = (): void => {
        clearTimeout(timeout);
        socket.off("error", onError);
        resolve();
      };
      const onError = (error: Error): void => {
        clearTimeout(timeout);
        socket.off("connect", onConnect);
        reject(error);
      };
      socket.once("connect", onConnect);
      socket.once("error", onError);
    });
    return new SshSocketTransport(socket);
  }

  static fromSocket(socket: net.Socket, limits?: SshTransportLimits): SshSocketTransport {
    return new SshSocketTransport(socket, limits);
  }

  onEvent(listener: (event: SshPacketTransportEvent) => void): () => void {
    this.events.on("event", listener);
    return () => this.events.off("event", listener);
  }

  async exchangeIdentification(clientSoftwareVersion?: string, timeoutMs = 10000): Promise<SshIdentificationExchange> {
    const clientLine = formatClientVersion(clientSoftwareVersion).trimEnd();
    // Install the reader before writing to avoid missing an immediate server
    // response, but never wait for the server banner before sending ours.
    const serverLinePromise = readServerIdentificationLine(this.socket, 8192, timeoutMs);
    const [serverLine] = await Promise.all([
      serverLinePromise,
      writeSocketFrame(this.socket, Buffer.from(`${clientLine}\r\n`, "ascii"), timeoutMs)
    ]);
    return {
      clientLine,
      serverLine,
      serverVersion: parseSshVersionLine(serverLine)
    };
  }

  send(payload: Buffer): Promise<void> {
    return this.enqueueOutboundPayload(payload, true);
  }

  /**
   * Queues an exclusively owned protocol buffer without cloning it. The caller
   * must not mutate the buffer until the returned promise settles. Settlement
   * means the ordered socket buffer accepted the frame (and waits for `drain`
   * only under real backpressure), not that the peer acknowledged it.
   */
  sendOwned(payload: Buffer): Promise<void> {
    return this.enqueueOutboundPayload(payload, false);
  }

  private enqueueOutboundPayload(payload: Buffer, copyPayload: boolean): Promise<void> {
    this.startPacketReader();
    if (this.unusable || this.socket.destroyed) {
      return Promise.reject(new Error("SSH transport is not writable."));
    }
    const bulk = payload[0] === 94; // SSH_MSG_CHANNEL_DATA
    const exceedsBulkLimit = bulk && this.outboundBulkQueueBytes + payload.length > this.maximumOutboundQueueBytes;
    const controlQueueBytes = this.outboundQueueBytes - this.outboundBulkQueueBytes;
    const exceedsControlLimit = !bulk && controlQueueBytes + payload.length > this.maximumControlQueueBytes;
    const exceedsTotalLimit = this.outboundQueueBytes + payload.length > this.maximumOutboundQueueBytes + this.maximumControlQueueBytes;
    if (exceedsBulkLimit || exceedsControlLimit || exceedsTotalLimit) {
      return Promise.reject(new Error(`SSH outbound queue exceeded ${this.maximumOutboundQueueBytes} bytes.`));
    }
    return new Promise<void>((resolve, reject) => {
      const queuedPayload = copyPayload ? Buffer.from(payload) : payload;
      // Preserve protocol order by default. Flow-control and global-request
      // liveness packets are independent of channel DATA and safe to prioritize
      // over an upload backlog. During runtime KEX they remain held until
      // NEWKEYS, as required for the transport protection transition.
      const keyExchangePayload = isKeyExchangePayload(payload);
      const priority = !this.runtimeKeyExchangeActive && isPriorityControlPayload(payload);
      const queue = this.runtimeKeyExchangeActive && keyExchangePayload
        ? this.outboundKexQueue
        : priority
          ? this.outboundPriorityQueue
          : this.outboundQueue;
      queue.push({ payload: queuedPayload, bulk, resolve, reject });
      this.outboundQueueBytes += payload.length;
      if (bulk) {
        this.outboundBulkQueueBytes += payload.length;
      }
      void this.pumpOutboundQueue();
    });
  }

  enableEncryption(inbound: PacketProtectionConfig, outbound: PacketProtectionConfig): void {
    this.switchInboundProtection(inbound);
    this.enableOutboundEncryption(outbound);
  }

  prepareInboundEncryption(inbound: PacketProtectionConfig): void {
    if (this.pendingInboundProtection) {
      throw new Error("SSH inbound packet protection transition is already pending.");
    }
    this.pendingInboundProtection = inbound;
  }

  pausePacketParsingAfter(messageNumber: number): void {
    if (!Number.isInteger(messageNumber) || messageNumber < 0 || messageNumber > 255) {
      throw new Error("SSH pause message number is invalid.");
    }
    if (this.pauseAfterMessageNumber !== undefined || this.packetParsingPaused) {
      throw new Error("SSH packet parsing pause is already armed.");
    }
    this.pauseAfterMessageNumber = messageNumber;
  }

  resumePacketParsing(): void {
    if (!this.packetParsingPaused) {
      return;
    }
    this.packetParsingPaused = false;
    this.handleData(EMPTY_BUFFER);
  }

  enableOutboundEncryption(outbound: PacketProtectionConfig): void {
    const pendingKeyExchangeWrite = this.outboundFrameInProgress || this.outboundKexQueue.length > 0;
    const pendingOrdinaryWrite = !this.runtimeKeyExchangeActive && (
      this.outboundQueue.length > 0 || this.outboundPriorityQueue.length > 0
    );
    if (pendingKeyExchangeWrite || pendingOrdinaryWrite) {
      throw new Error("Cannot switch SSH outbound packet protection while writes are pending.");
    }
    this.writer = new SshEncryptedPacketStreamWriter(outbound, this.writer.getSequenceNumber());
  }

  beginRuntimeKeyExchange(): void {
    if (this.runtimeKeyExchangeActive) {
      throw new Error("SSH runtime key exchange transport barrier is already active.");
    }
    this.runtimeKeyExchangeActive = true;
  }

  finishRuntimeKeyExchange(): void {
    if (!this.runtimeKeyExchangeActive) {
      throw new Error("SSH runtime key exchange transport barrier is not active.");
    }
    this.runtimeKeyExchangeActive = false;
    void this.pumpOutboundQueue();
  }

  getTransferredBytes(): { sent: number; received: number } {
    return { sent: this.bytesSent, received: this.bytesReceived };
  }

  close(): void {
    this.socket.end();
  }

  destroy(error?: Error): void {
    this.unusable = true;
    this.rejectOutboundQueue(error ?? new Error("SSH transport destroyed."));
    this.socket.destroy(error);
  }

  private handleData(chunk: Buffer): void {
    try {
      this.bytesReceived += chunk.length;
      if (this.packetParsingPaused) {
        this.reader.push(chunk, 0);
        return;
      }
      let input = chunk;
      while (true) {
        const [payload] = this.reader.push(input, 1);
        input = EMPTY_BUFFER;
        if (!payload) {
          break;
        }
        const shouldSwitchInbound = payload[0] === 21 && this.pendingInboundProtection !== undefined;
        this.events.emit("event", { type: "payload", payload } satisfies SshPacketTransportEvent);
        if (shouldSwitchInbound) {
          const buffered = this.reader.takeBufferedData();
          const protection = this.pendingInboundProtection!;
          this.pendingInboundProtection = undefined;
          this.reader = new SshEncryptedPacketStreamReader(protection, this.reader.getSequenceNumber());
          input = buffered;
        }
        if (payload[0] === this.pauseAfterMessageNumber) {
          this.pauseAfterMessageNumber = undefined;
          this.packetParsingPaused = true;
          break;
        }
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
    this.socket.resume();
  }

  private switchInboundProtection(inbound: PacketProtectionConfig): void {
    const buffered = this.reader.takeBufferedData();
    this.reader = new SshEncryptedPacketStreamReader(inbound, this.reader.getSequenceNumber());
    if (buffered.length > 0) {
      this.handleData(buffered);
    }
  }

  private async pumpOutboundQueue(): Promise<void> {
    if (this.outboundPumpRunning) {
      return;
    }
    this.outboundPumpRunning = true;
    try {
      while (true) {
        const queue = this.nextOutboundQueue();
        if (!queue) {
          break;
        }
        const entry = queue[0];
        try {
          this.outboundFrameInProgress = true;
          let frameBytes: number;
          if (this.writer instanceof SshEncryptedPacketStreamWriter) {
            const protectedPacket = this.writer.writeProtected(entry.payload);
            await writeSocketFrames(
              this.socket,
              [protectedPacket.encryptedPacket, protectedPacket.mac],
              this.writeTimeoutMs,
              this.maximumSocketPipelineBytes
            );
            frameBytes = protectedPacket.encryptedPacket.length + protectedPacket.mac.length;
          } else {
            const frame = this.writer.write(entry.payload);
            await writeSocketFrame(this.socket, frame, this.writeTimeoutMs, this.maximumSocketPipelineBytes);
            frameBytes = frame.length;
          }
          this.outboundFrameInProgress = false;
          this.bytesSent += frameBytes;
          queue.shift();
          this.outboundQueueBytes -= entry.payload.length;
          if (entry.bulk) {
            this.outboundBulkQueueBytes -= entry.payload.length;
          }
          entry.resolve();
        } catch (error) {
          this.outboundFrameInProgress = false;
          const normalized = error instanceof Error ? error : new Error(String(error));
          this.unusable = true;
          this.rejectOutboundQueue(normalized);
          this.socket.destroy(normalized);
          break;
        }
      }
    } finally {
      this.outboundPumpRunning = false;
    }
  }

  private nextOutboundQueue(): OutboundQueueEntry[] | undefined {
    if (this.runtimeKeyExchangeActive) {
      return this.outboundKexQueue.length > 0 ? this.outboundKexQueue : undefined;
    }
    if (this.outboundPriorityQueue.length > 0) {
      return this.outboundPriorityQueue;
    }
    if (this.outboundQueue.length > 0) {
      return this.outboundQueue;
    }
    return this.outboundKexQueue.length > 0 ? this.outboundKexQueue : undefined;
  }

  private rejectOutboundQueue(error: Error): void {
    for (const entry of [
      ...this.outboundKexQueue.splice(0),
      ...this.outboundPriorityQueue.splice(0),
      ...this.outboundQueue.splice(0)
    ]) {
      entry.reject(error);
    }
    this.outboundQueueBytes = 0;
    this.outboundBulkQueueBytes = 0;
  }
}

function isKeyExchangePayload(payload: Buffer): boolean {
  const number = payload[0];
  return number === 20 || number === 21 || (number >= 30 && number <= 49);
}

function isPriorityControlPayload(payload: Buffer): boolean {
  const number = payload[0];
  return number === 80 || number === 81 || number === 82 || number === 93;
}

export async function readServerIdentificationLine(socket: net.Socket, maxBytes = 8192, timeoutMs = 10000): Promise<string> {
  let buffer = Buffer.alloc(0);
  let identificationBytes = 0;

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      socket.pause();
      reject(new Error("Timed out waiting for SSH identification."));
    }, timeoutMs);
    timeout.unref();
    const cleanup = (): void => {
      clearTimeout(timeout);
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

      let newlineIndex = buffer.indexOf(0x0a);
      while (newlineIndex >= 0) {
        const lineBytes = newlineIndex + 1;
        if (identificationBytes + lineBytes > maxBytes) {
          socket.pause();
          cleanup();
          reject(new Error("SSH identification exceeded maximum size."));
          return;
        }
        const line = buffer.subarray(0, newlineIndex + 1).toString("ascii").replace(/\r?\n$/u, "");
        buffer = buffer.subarray(lineBytes);
        identificationBytes += lineBytes;
        if (line.startsWith("SSH-")) {
          socket.pause();
          cleanup();
          if (buffer.length > 0) {
            socket.unshift(buffer);
          }
          resolve(line);
          return;
        }
        newlineIndex = buffer.indexOf(0x0a);
      }
      // Bytes after a complete SSH identification line belong to the binary
      // packet stream and must not count against the banner limit. Until that
      // line is found, bound the incomplete pre-banner data as well.
      if (identificationBytes + buffer.length > maxBytes) {
        socket.pause();
        cleanup();
        reject(new Error("SSH identification exceeded maximum size."));
      }
    };

    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
  });
}

function writeSocketFrame(socket: net.Socket, frame: Buffer, timeoutMs: number, maximumPipelineBytes = 0): Promise<void> {
  try {
    // Resolve as soon as Node accepts the frame into its ordered socket
    // pipeline. Waiting for every write callback creates a one-packet
    // stop-and-wait upload path on Windows. Only a full bounded pipeline waits
    // for drain; the common fast path allocates no timer or event listeners.
    const accepted = socket.write(frame, (error?: Error | null) => {
      if (error && !socket.destroyed) {
        socket.destroy(error);
      }
    });
    if (accepted || canContinueSocketPipeline(socket, maximumPipelineBytes)) {
      return Promise.resolve();
    }
    return waitForSocketDrain(socket, timeoutMs);
  } catch (error) {
    return Promise.reject(error instanceof Error ? error : new Error(String(error)));
  }
}

function writeSocketFrames(
  socket: net.Socket,
  frames: readonly Buffer[],
  timeoutMs: number,
  maximumPipelineBytes = 0
): Promise<void> {
  if (frames.length === 1) {
    return writeSocketFrame(socket, frames[0], timeoutMs, maximumPipelineBytes);
  }
  let corked = false;
  try {
    let accepted = true;
    socket.cork();
    corked = true;
    for (const frame of frames) {
      if (!socket.write(frame, (error?: Error | null) => {
        if (error && !socket.destroyed) {
          socket.destroy(error);
        }
      })) {
        accepted = false;
      }
    }
    socket.uncork();
    corked = false;
    if (accepted || canContinueSocketPipeline(socket, maximumPipelineBytes)) {
      return Promise.resolve();
    }
    return waitForSocketDrain(socket, timeoutMs);
  } catch (error) {
    if (corked) {
      try {
        socket.uncork();
      } catch {
        // The original write failure is more useful.
      }
    }
    return Promise.reject(error instanceof Error ? error : new Error(String(error)));
  }
}

function canContinueSocketPipeline(socket: net.Socket, maximumPipelineBytes: number): boolean {
  return maximumPipelineBytes > 0 && socket.writableLength > 0 && socket.writableLength < maximumPipelineBytes;
}

function waitForSocketDrain(socket: net.Socket, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timeout = timeoutMs > 0
      ? setTimeout(() => finish(new Error("SSH socket write timed out.")), timeoutMs)
      : undefined;
    timeout?.unref();
    const cleanup = (): void => {
      if (timeout) {
        clearTimeout(timeout);
      }
      socket.off("drain", onDrain);
      socket.off("error", onError);
      socket.off("close", onClose);
    };
    const finish = (error?: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    };
    const onDrain = (): void => finish();
    const onError = (error: Error): void => finish(error);
    const onClose = (): void => finish(new Error("SSH socket closed before queued data was written."));
    socket.once("drain", onDrain);
    socket.once("error", onError);
    socket.once("close", onClose);
  });
}
