import { createCipheriv } from "node:crypto";
import { EventEmitter } from "node:events";
import { Duplex, PassThrough, type TransformCallback } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import { deriveTransportKeys, transportKeyLengthsFor } from "../src/core/ssh/key-derivation.js";
import {
  SshEncryptedPacketStreamReader,
  SshEncryptedPacketStreamWriter,
  SshPlainPacketStreamReader,
  SshPlainPacketStreamWriter
} from "../src/core/ssh/packet-stream.js";
import {
  DEFAULT_SSH_SOCKET_PIPELINE_BYTES,
  SshSocketTransport,
  readServerIdentificationLine
} from "../src/core/ssh/socket-transport.js";
import { MAX_SSH_PACKET_LENGTH } from "../src/core/ssh/packet.js";

describe("SSH packet stream reader/writer", () => {
  it("keeps enough bounded socket admission capacity for a 250 Mbps / 72 ms upload path", () => {
    const requiredBandwidthDelayProduct = Math.ceil((250e6 / 8) * (72 / 1000));
    expect(DEFAULT_SSH_SOCKET_PIPELINE_BYTES).toBeGreaterThanOrEqual(requiredBandwidthDelayProduct);
  });

  it("handles partial plaintext packet reads", () => {
    const writer = new SshPlainPacketStreamWriter();
    const reader = new SshPlainPacketStreamReader();
    const frame = writer.write(Buffer.from("hello"));

    expect(reader.push(frame.subarray(0, 3))).toEqual([]);
    expect(reader.push(frame.subarray(3))).toEqual([Buffer.from("hello")]);
  });

  it("rejects oversized and misaligned plaintext lengths from the first four bytes", () => {
    const oversized = Buffer.alloc(4);
    oversized.writeUInt32BE(MAX_SSH_PACKET_LENGTH + 1);
    expect(() => new SshPlainPacketStreamReader().push(oversized)).toThrow("exceeds the maximum");

    const misaligned = Buffer.alloc(4);
    misaligned.writeUInt32BE(13);
    expect(() => new SshPlainPacketStreamReader().push(misaligned)).toThrow("not aligned");
  });

  it("handles partial encrypted packet reads with MAC verification", () => {
    const keys = deriveTransportKeys(123n, Buffer.alloc(32, 1), Buffer.alloc(32, 2), transportKeyLengthsFor("aes256-ctr", "hmac-sha2-256"));
    const config = {
      cipherName: "aes256-ctr" as const,
      encryptionKey: keys.encryptionKeyClientToServer,
      initialIv: keys.initialIvClientToServer,
      macName: "hmac-sha2-256" as const,
      macKey: keys.integrityKeyClientToServer
    };
    const writer = new SshEncryptedPacketStreamWriter(config);
    const reader = new SshEncryptedPacketStreamReader(config);
    const frame = writer.write(Buffer.from("encrypted"));

    expect(reader.push(frame.subarray(0, 2))).toEqual([]);
    expect(reader.push(frame.subarray(2, 19))).toEqual([]);
    expect(reader.push(frame.subarray(19))).toEqual([Buffer.from("encrypted")]);
  });

  it("exposes ciphertext and MAC separately without changing the wire frame", () => {
    const config = packetConfig(31);
    const payload = Buffer.from("vectored-write");
    const protectedPacket = new SshEncryptedPacketStreamWriter(config).writeProtected(payload);
    const frame = Buffer.concat([protectedPacket.encryptedPacket, protectedPacket.mac]);

    expect(new SshEncryptedPacketStreamReader(config).push(frame)).toEqual([payload]);
  });

  it("rejects an encrypted oversized length before buffering the packet body", () => {
    const config = packetConfig(30);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(MAX_SSH_PACKET_LENGTH + 1);
    const encryptedLength = createCipheriv("aes-256-ctr", config.encryptionKey, config.initialIv).update(length);

    expect(() => new SshEncryptedPacketStreamReader(config).push(encryptedLength)).toThrow("exceeds the maximum");
  });

  it("continues MAC sequence numbers after plaintext packets", () => {
    const plainWriter = new SshPlainPacketStreamWriter();
    const plainReader = new SshPlainPacketStreamReader();
    plainReader.push(plainWriter.write(Buffer.from("kexinit")));
    plainReader.push(plainWriter.write(Buffer.from("newkeys")));

    const keys = deriveTransportKeys(456n, Buffer.alloc(32, 1), Buffer.alloc(32, 2), transportKeyLengthsFor("aes256-ctr", "hmac-sha2-256"));
    const config = {
      cipherName: "aes256-ctr" as const,
      encryptionKey: keys.encryptionKeyClientToServer,
      initialIv: keys.initialIvClientToServer,
      macName: "hmac-sha2-256" as const,
      macKey: keys.integrityKeyClientToServer
    };
    const encryptedWriter = new SshEncryptedPacketStreamWriter(config, plainWriter.getSequenceNumber());
    const encryptedReader = new SshEncryptedPacketStreamReader(config, plainReader.getSequenceNumber());

    expect(encryptedReader.push(encryptedWriter.write(Buffer.from("service-request")))).toEqual([Buffer.from("service-request")]);
    expect(encryptedWriter.getSequenceNumber()).toBe(3);
    expect(encryptedReader.getSequenceNumber()).toBe(3);
  });

  it("reads SSH identification while ignoring pre-banner lines", async () => {
    const stream = new PassThrough() as unknown as NodeJS.ReadWriteStream;
    const promise = readServerIdentificationLine(stream as never);
    stream.write("notice\r\nSSH-2.0-TestServer_1.0\r\n");

    await expect(promise).resolves.toBe("SSH-2.0-TestServer_1.0");
  });

  it("does not count coalesced binary packets against the identification limit", async () => {
    const stream = new PassThrough() as unknown as NodeJS.ReadWriteStream;
    const promise = readServerIdentificationLine(stream as never, 64);
    const binaryRemainder = Buffer.alloc(16 * 1024, 0x5a);
    stream.write(Buffer.concat([Buffer.from("SSH-2.0-TestServer_1.0\r\n"), binaryRemainder]));

    await expect(promise).resolves.toBe("SSH-2.0-TestServer_1.0");
    expect((stream as PassThrough).read(binaryRemainder.length)).toEqual(binaryRemainder);
  });

  it("rejects an oversized identification prefix without a newline", async () => {
    const stream = new PassThrough() as unknown as NodeJS.ReadWriteStream;
    const promise = readServerIdentificationLine(stream as never, 64);
    stream.write(Buffer.alloc(65, 0x41));

    await expect(promise).rejects.toThrow("identification exceeded maximum size");
  });

  it("times out a server that never sends identification", async () => {
    const stream = new PassThrough() as unknown as NodeJS.ReadWriteStream;
    await expect(readServerIdentificationLine(stream as never, 8192, 5)).rejects.toThrow("Timed out waiting");
  });

  it("sends client identification immediately instead of waiting for the server", async () => {
    const socket = new ControlledDuplex();
    const transport = SshSocketTransport.fromSocket(socket as never);
    const exchange = transport.exchangeIdentification("test-client", 1000);
    await nextTurn();

    expect(Buffer.concat(socket.writes).toString("ascii")).toBe("SSH-2.0-test-client\r\n");
    socket.push(Buffer.from("SSH-2.0-test-server\r\n"));
    await expect(exchange).resolves.toMatchObject({ serverLine: "SSH-2.0-test-server" });
    transport.destroy();
  });

  it("keeps send pending until socket backpressure drains and bounds queued payloads", async () => {
    const socket = new ControlledDuplex(true);
    const transport = SshSocketTransport.fromSocket(socket as never, {
      maximumOutboundQueueBytes: 8,
      maximumSocketPipelineBytes: 0
    });
    let completed = false;
    const first = transport.send(Buffer.from([94, 1, 2, 3, 4, 5])).then(() => {
      completed = true;
    });
    await nextTurn();

    expect(completed).toBe(false);
    await expect(transport.send(Buffer.from([94, 7, 8]))).rejects.toThrow("outbound queue exceeded");
    const control = transport.send(Buffer.from([20]));
    socket.releaseWrite();
    await Promise.all([first, control]);
    expect(completed).toBe(true);
    expect(socket.writes).toHaveLength(2);
    transport.destroy();
  });

  it("keeps public send copy-safe while allowing owned hot-path payloads to skip a clone", async () => {
    const socket = new ControlledDuplex(true);
    const transport = SshSocketTransport.fromSocket(socket as never, { maximumSocketPipelineBytes: 0 });
    const first = transport.sendOwned(Buffer.from([94, 0]));
    await nextTurn();
    const owned = Buffer.from([94, 1]);
    const copied = Buffer.from([94, 2]);
    const second = transport.sendOwned(owned);
    const third = transport.send(copied);
    const queued = (transport as unknown as { outboundQueue: Array<{ payload: Buffer }> }).outboundQueue;

    expect(queued[1]?.payload).toBe(owned);
    expect(queued[2]?.payload).not.toBe(copied);
    expect(queued[2]?.payload).toEqual(copied);

    socket.releaseWrite();
    await Promise.all([first, second, third]);
    transport.destroy();
  });

  it("pipelines accepted upload frames without waiting for per-write callbacks", async () => {
    const socket = new DelayedCallbackSocket();
    const transport = SshSocketTransport.fromSocket(socket as never);
    const payload = Buffer.alloc(8 * 1024, 0x5a);
    payload[0] = 94;

    const sends = Array.from({ length: 512 }, () => transport.send(payload));
    await Promise.all(sends);

    const acceptedBytes = socket.writes.reduce((total, frame) => total + frame.length, 0);
    expect(acceptedBytes).toBeGreaterThanOrEqual(2_250_000);
    expect(socket.writes).toHaveLength(512);
    expect(socket.callbacks).toHaveLength(512);
    socket.releaseCallbacks();
    transport.destroy();
  });

  it("fills the bounded upload pipeline beyond Node's stream HWM before waiting for drain", async () => {
    const socket = new ControlledDuplex(true);
    const transport = SshSocketTransport.fromSocket(socket as never);
    const payload = Buffer.alloc(8 * 1024, 0x5a);
    payload[0] = 94;
    let admittedPayloadBytes = 0;

    const sends = Array.from({ length: 512 }, () =>
      transport.send(payload).then(() => {
        admittedPayloadBytes += payload.length;
      })
    );
    await nextTurn();

    expect(admittedPayloadBytes).toBeGreaterThanOrEqual(2_250_000);
    expect(socket.writableLength).toBeLessThanOrEqual(DEFAULT_SSH_SOCKET_PIPELINE_BYTES + payload.length * 2);
    socket.releaseWrite();
    await Promise.all(sends);
    transport.destroy();
  });

  it("prioritizes SSH control packets after the currently-writing bulk packet", async () => {
    const socket = new ControlledDuplex(true);
    const transport = SshSocketTransport.fromSocket(socket as never, { maximumSocketPipelineBytes: 0 });
    const firstBulk = transport.send(Buffer.from([94, 1]));
    await nextTurn();
    const secondBulk = transport.send(Buffer.from([94, 2]));
    const windowAdjust = transport.send(Buffer.from([93, 3]));
    const globalFailure = transport.send(Buffer.from([82]));
    const channelOpen = transport.send(Buffer.from([90, 4]));

    socket.releaseWrite();
    await Promise.all([firstBulk, secondBulk, windowAdjust, globalFailure, channelOpen]);

    const payloads = new SshPlainPacketStreamReader().push(Buffer.concat(socket.writes));
    expect(payloads).toEqual([
      Buffer.from([94, 1]),
      Buffer.from([93, 3]),
      Buffer.from([82]),
      Buffer.from([90, 4]),
      Buffer.from([94, 2])
    ]);
    transport.destroy();
  });

  it("removes an aborted queued channel open and releases its queue accounting", async () => {
    const socket = new ControlledDuplex(true);
    const transport = SshSocketTransport.fromSocket(socket as never, { maximumSocketPipelineBytes: 0 });
    const currentBulk = transport.send(Buffer.from([94, 1]));
    await nextTurn();
    const controller = new AbortController();
    const removeListener = vi.spyOn(controller.signal, "removeEventListener");
    const queuedOpen = transport.sendOwned(Buffer.from([90, 2]), controller.signal);
    const queuedOpenRejection = expect(queuedOpen).rejects.toMatchObject({ name: "AbortError" });
    const internals = transport as unknown as {
      outboundChannelOpenQueue: unknown[];
      outboundQueueBytes: number;
      outboundBulkQueueBytes: number;
    };

    expect(internals.outboundChannelOpenQueue).toHaveLength(1);
    expect(internals.outboundQueueBytes).toBe(4);
    expect(internals.outboundBulkQueueBytes).toBe(2);
    controller.abort();
    await queuedOpenRejection;

    expect(removeListener).toHaveBeenCalled();
    expect(internals.outboundChannelOpenQueue).toHaveLength(0);
    expect(internals.outboundQueueBytes).toBe(2);
    expect(internals.outboundBulkQueueBytes).toBe(2);
    socket.releaseWrite();
    await currentBulk;
    expect(internals.outboundQueueBytes).toBe(0);
    expect(internals.outboundBulkQueueBytes).toBe(0);
    expect(new SshPlainPacketStreamReader().push(Buffer.concat(socket.writes))).toEqual([
      Buffer.from([94, 1])
    ]);
    transport.destroy();
  });

  it("rejects a pre-aborted channel open without queueing or writing it", async () => {
    const socket = new ControlledDuplex();
    const transport = SshSocketTransport.fromSocket(socket as never);
    const controller = new AbortController();
    controller.abort();

    await expect(transport.sendOwned(Buffer.from([90, 1]), controller.signal)).rejects.toMatchObject({
      name: "AbortError"
    });

    const internals = transport as unknown as {
      outboundChannelOpenQueue: unknown[];
      outboundQueueBytes: number;
    };
    expect(internals.outboundChannelOpenQueue).toHaveLength(0);
    expect(internals.outboundQueueBytes).toBe(0);
    expect(socket.writes).toEqual([]);
    transport.destroy();
  });

  it("does not reject cancellation after a channel-open frame has started", async () => {
    const socket = new ControlledDuplex(true);
    const transport = SshSocketTransport.fromSocket(socket as never, { maximumSocketPipelineBytes: 0 });
    const controller = new AbortController();
    let settled = false;
    const startedOpen = transport.sendOwned(Buffer.from([90, 1]), controller.signal).finally(() => {
      settled = true;
    });
    await nextTurn();

    controller.abort();
    await nextTurn();
    expect(settled).toBe(false);

    socket.releaseWrite();
    await expect(startedOpen).resolves.toBeUndefined();
    expect(new SshPlainPacketStreamReader().push(Buffer.concat(socket.writes))).toEqual([
      Buffer.from([90, 1])
    ]);
    transport.destroy();
  });

  it("bounds channel-open priority bursts so an established upload keeps moving", async () => {
    const socket = new ControlledDuplex(true);
    const transport = SshSocketTransport.fromSocket(socket as never, { maximumSocketPipelineBytes: 0 });
    const currentBulk = transport.send(Buffer.from([94, 1]));
    await nextTurn();
    const queuedBulk = transport.send(Buffer.from([94, 2]));
    const opens = Array.from({ length: 24 }, (_, index) => transport.send(Buffer.from([90, index])));
    const windowAdjust = transport.send(Buffer.from([93, 7]));

    socket.releaseWrite();
    await Promise.all([currentBulk, queuedBulk, windowAdjust, ...opens]);

    const payloads = new SshPlainPacketStreamReader().push(Buffer.concat(socket.writes));
    const queuedBulkIndex = payloads.findIndex((payload) => payload.equals(Buffer.from([94, 2])));
    const lastOpenIndex = payloads.map((payload) => payload[0]).lastIndexOf(90);
    expect(payloads[1]).toEqual(Buffer.from([93, 7]));
    expect(queuedBulkIndex).toBeGreaterThan(1);
    expect(queuedBulkIndex).toBeLessThan(lastOpenIndex);
    expect(payloads.slice(2, queuedBulkIndex).filter((payload) => payload[0] === 90)).toHaveLength(8);
    transport.destroy();
  });

  it("holds ordinary packets behind a server-initiated runtime KEX barrier", async () => {
    const socket = new ControlledDuplex(true);
    const transport = SshSocketTransport.fromSocket(socket as never, { maximumSocketPipelineBytes: 0 });
    const currentBulk = transport.send(Buffer.from([94, 1]));
    await nextTurn();
    let heldBulkCompleted = false;
    const heldBulk = transport.send(Buffer.from([94, 2])).then(() => {
      heldBulkCompleted = true;
    });

    transport.beginRuntimeKeyExchange();
    const kexInit = transport.send(Buffer.from([20, 3]));
    socket.releaseWrite();
    await Promise.all([currentBulk, kexInit]);
    expect(heldBulkCompleted).toBe(false);

    await transport.send(Buffer.from([21, 4]));
    transport.finishRuntimeKeyExchange();
    await heldBulk;

    const payloads = new SshPlainPacketStreamReader().push(Buffer.concat(socket.writes));
    expect(payloads).toEqual([
      Buffer.from([94, 1]),
      Buffer.from([20, 3]),
      Buffer.from([21, 4]),
      Buffer.from([94, 2])
    ]);
    transport.destroy();
  });

  it("drains prior FIFO data before a client-initiated KEX and holds later data", async () => {
    const socket = new ControlledDuplex(true);
    const transport = SshSocketTransport.fromSocket(socket as never, { maximumSocketPipelineBytes: 0 });
    const currentBulk = transport.send(Buffer.from([94, 1]));
    await nextTurn();
    const priorBulk = transport.send(Buffer.from([94, 2]));
    const kexInit = transport.send(Buffer.from([20, 3]));

    socket.releaseWrite();
    await Promise.all([currentBulk, priorBulk, kexInit]);
    transport.beginRuntimeKeyExchange();

    let heldBulkCompleted = false;
    const heldBulk = transport.send(Buffer.from([94, 4])).then(() => {
      heldBulkCompleted = true;
    });
    await transport.send(Buffer.from([30, 5]));
    await transport.send(Buffer.from([21, 6]));
    expect(heldBulkCompleted).toBe(false);
    transport.finishRuntimeKeyExchange();
    await heldBulk;

    const payloads = new SshPlainPacketStreamReader().push(Buffer.concat(socket.writes));
    expect(payloads).toEqual([
      Buffer.from([94, 1]),
      Buffer.from([94, 2]),
      Buffer.from([20, 3]),
      Buffer.from([30, 5]),
      Buffer.from([21, 6]),
      Buffer.from([94, 4])
    ]);
    transport.destroy();
  });

  it("keeps disconnect ordered behind already-queued channel data", async () => {
    const socket = new ControlledDuplex(true);
    const transport = SshSocketTransport.fromSocket(socket as never, { maximumSocketPipelineBytes: 0 });
    const currentBulk = transport.send(Buffer.from([94, 1]));
    await nextTurn();
    const queuedBulk = transport.send(Buffer.from([94, 2]));
    const disconnect = transport.send(Buffer.from([1, 3]));

    socket.releaseWrite();
    await Promise.all([currentBulk, queuedBulk, disconnect]);

    const payloads = new SshPlainPacketStreamReader().push(Buffer.concat(socket.writes));
    expect(payloads).toEqual([
      Buffer.from([94, 1]),
      Buffer.from([94, 2]),
      Buffer.from([1, 3])
    ]);
    transport.destroy();
  });

  it("pauses after KEX reply and switches keys when reply, NEWKEYS, and data share one TCP chunk", async () => {
    const oldConfig = packetConfig(10);
    const newConfig = packetConfig(20);
    const socket = new ControlledDuplex();
    const transport = SshSocketTransport.fromSocket(socket as never);
    transport.enableEncryption(oldConfig, oldConfig);
    await transport.send(Buffer.from("start-reader"));
    const payloads: Buffer[] = [];
    transport.onEvent((event) => {
      if (event.type === "payload") {
        payloads.push(event.payload);
      }
    });
    transport.pausePacketParsingAfter(31);

    const oldWriter = new SshEncryptedPacketStreamWriter(oldConfig);
    const newWriter = new SshEncryptedPacketStreamWriter(newConfig, 2);
    socket.push(Buffer.concat([
      oldWriter.write(Buffer.from([31])),
      oldWriter.write(Buffer.from([21])),
      newWriter.write(Buffer.from("after-rekey"))
    ]));
    await nextTurn();
    expect(payloads).toEqual([Buffer.from([31])]);

    transport.prepareInboundEncryption(newConfig);
    transport.resumePacketParsing();
    await nextTurn();

    expect(payloads).toEqual([Buffer.from([31]), Buffer.from([21]), Buffer.from("after-rekey")]);
    transport.destroy();
  });
});

function packetConfig(seed: number) {
  const keys = deriveTransportKeys(
    BigInt(seed),
    Buffer.alloc(32, seed),
    Buffer.alloc(32, seed + 1),
    transportKeyLengthsFor("aes256-ctr", "hmac-sha2-256")
  );
  return {
    cipherName: "aes256-ctr" as const,
    encryptionKey: keys.encryptionKeyClientToServer,
    initialIv: keys.initialIvClientToServer,
    macName: "hmac-sha2-256" as const,
    macKey: keys.integrityKeyClientToServer
  };
}

class ControlledDuplex extends Duplex {
  readonly writes: Buffer[] = [];
  private pendingWrite: TransformCallback | undefined;

  constructor(private blockWrites = false) {
    super({ writableHighWaterMark: blockWrites ? 1 : 16 * 1024 });
  }

  override _read(): void {}

  override _write(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    this.writes.push(Buffer.from(chunk));
    if (this.blockWrites) {
      this.pendingWrite = callback;
    } else {
      callback();
    }
  }

  releaseWrite(): void {
    this.blockWrites = false;
    const callback = this.pendingWrite;
    this.pendingWrite = undefined;
    callback?.();
  }
}

class DelayedCallbackSocket extends EventEmitter {
  readonly writes: Buffer[] = [];
  readonly callbacks: Array<(error?: Error | null) => void> = [];
  destroyed = false;

  write(data: Buffer, callback?: (error?: Error | null) => void): boolean {
    this.writes.push(Buffer.from(data));
    if (callback) {
      this.callbacks.push(callback);
    }
    return true;
  }

  read(): null {
    return null;
  }

  resume(): void {}

  destroy(): void {
    this.destroyed = true;
  }

  releaseCallbacks(): void {
    for (const callback of this.callbacks.splice(0)) {
      callback();
    }
  }
}

function nextTurn(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}
