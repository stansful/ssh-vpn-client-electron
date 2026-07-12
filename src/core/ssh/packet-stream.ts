import { createCipheriv, createDecipheriv, timingSafeEqual, type Cipher, type Decipher } from "node:crypto";
import { assertSshPacketLength, decodeSshPacket, encodeSshPacket, MAX_SSH_PACKET_LENGTH } from "./packet.js";
import {
  computeSshMac,
  macLength,
  toNodeCipherName,
  type PacketProtectionConfig,
  type ProtectedPacket
} from "./packet-codec.js";

const EMPTY_BUFFER = Buffer.alloc(0);

export class SshPlainPacketStreamReader {
  private buffer: Buffer = EMPTY_BUFFER;
  private sequenceNumber = 0;

  push(chunk: Buffer, maximumPayloads = Number.POSITIVE_INFINITY): Buffer[] {
    this.buffer = appendBounded(this.buffer, chunk, "plaintext");
    const payloads: Buffer[] = [];

    while (this.buffer.length >= 4 && payloads.length < maximumPayloads) {
      const packetLength = this.buffer.readUInt32BE(0);
      assertSshPacketLength(packetLength, 8);
      const totalLength = 4 + packetLength;
      if (this.buffer.length < totalLength) {
        break;
      }
      const packet = this.buffer.subarray(0, totalLength);
      this.buffer = this.buffer.subarray(totalLength);
      payloads.push(decodeSshPacket(packet, 8).payload);
      this.sequenceNumber = (this.sequenceNumber + 1) >>> 0;
    }

    return payloads;
  }

  getSequenceNumber(): number {
    return this.sequenceNumber;
  }

  bufferedBytes(): number {
    return this.buffer.length;
  }

  takeBufferedData(): Buffer {
    const buffered = this.buffer;
    this.buffer = EMPTY_BUFFER;
    return buffered;
  }
}

export class SshPlainPacketStreamWriter {
  private sequenceNumber = 0;

  write(payload: Buffer): Buffer {
    const packet = encodeSshPacket(payload, 8);
    this.sequenceNumber = (this.sequenceNumber + 1) >>> 0;
    return packet;
  }

  getSequenceNumber(): number {
    return this.sequenceNumber;
  }
}

export class SshEncryptedPacketStreamReader {
  private encryptedBuffer: Buffer = EMPTY_BUFFER;
  private plainPacket: Buffer = EMPTY_BUFFER;
  private plainPacketBytes = 0;
  private expectedPlainPacketLength: number | undefined;
  private sequenceNumber: number;
  private readonly decipher: Decipher;

  constructor(private readonly config: PacketProtectionConfig, initialSequenceNumber = 0) {
    this.sequenceNumber = initialSequenceNumber >>> 0;
    this.decipher = createDecipheriv(toNodeCipherName(config.cipherName), config.encryptionKey, config.initialIv);
  }

  push(chunk: Buffer, maximumPayloads = Number.POSITIVE_INFINITY): Buffer[] {
    this.encryptedBuffer = appendBounded(this.encryptedBuffer, chunk, "encrypted");
    const payloads: Buffer[] = [];
    const expectedMacLength = macLength(this.config.macName);

    while (payloads.length < maximumPayloads) {
      if (this.expectedPlainPacketLength === undefined) {
        if (this.encryptedBuffer.length < 4) {
          break;
        }
        const encryptedLength = this.consumeEncrypted(4);
        const plainLength = this.decipher.update(encryptedLength);
        const packetLength = plainLength.readUInt32BE(0);
        assertSshPacketLength(packetLength, 16);
        this.expectedPlainPacketLength = 4 + packetLength;
        this.plainPacket = Buffer.allocUnsafe(this.expectedPlainPacketLength);
        plainLength.copy(this.plainPacket, 0);
        this.plainPacketBytes = plainLength.length;
      }

      const remainingPacketBytes = this.expectedPlainPacketLength - this.plainPacketBytes;
      if (remainingPacketBytes > 0) {
        if (this.encryptedBuffer.length === 0) {
          break;
        }
        const encryptedBody = this.consumeEncrypted(Math.min(remainingPacketBytes, this.encryptedBuffer.length));
        const plainBody = this.decipher.update(encryptedBody);
        plainBody.copy(this.plainPacket, this.plainPacketBytes);
        this.plainPacketBytes += plainBody.length;
        if (this.plainPacketBytes < this.expectedPlainPacketLength) {
          break;
        }
      }

      if (this.encryptedBuffer.length < expectedMacLength) {
        break;
      }

      const mac = this.consumeEncrypted(expectedMacLength);
      const expectedMac = computeSshMac(this.config.macName, this.config.macKey, this.sequenceNumber, this.plainPacket);
      if (mac.length !== expectedMac.length || !timingSafeEqual(mac, expectedMac)) {
        throw new Error("SSH packet MAC verification failed.");
      }

      payloads.push(decodeSshPacket(this.plainPacket, 16).payload);
      this.sequenceNumber = (this.sequenceNumber + 1) >>> 0;
      this.plainPacket = EMPTY_BUFFER;
      this.plainPacketBytes = 0;
      this.expectedPlainPacketLength = undefined;
    }

    return payloads;
  }

  getSequenceNumber(): number {
    return this.sequenceNumber;
  }

  bufferedBytes(): number {
    return this.encryptedBuffer.length + this.plainPacketBytes;
  }

  takeBufferedData(): Buffer {
    if (this.expectedPlainPacketLength !== undefined || this.plainPacketBytes > 0) {
      throw new Error("Cannot switch SSH packet protection in the middle of a packet.");
    }
    const buffered = this.encryptedBuffer;
    this.encryptedBuffer = EMPTY_BUFFER;
    return buffered;
  }

  private consumeEncrypted(length: number): Buffer {
    const chunk = this.encryptedBuffer.subarray(0, length);
    this.encryptedBuffer = this.encryptedBuffer.subarray(length);
    return chunk;
  }
}


// A reader normally retains at most one partial packet. The extra packet of
// headroom permits common TCP coalescing without allowing an attacker to grow
// memory indefinitely before authentication or MAC verification.
const MAX_BUFFERED_STREAM_BYTES = MAX_SSH_PACKET_LENGTH * 2 + 1024;

function appendBounded(buffer: Buffer, chunk: Buffer, label: string): Buffer {
  if (buffer.length + chunk.length > MAX_BUFFERED_STREAM_BYTES) {
    throw new Error(`SSH ${label} packet buffer exceeded ${MAX_BUFFERED_STREAM_BYTES} bytes.`);
  }
  if (buffer.length === 0) {
    return chunk;
  }
  if (chunk.length === 0) {
    return buffer;
  }
  return Buffer.concat([buffer, chunk]);
}

export class SshEncryptedPacketStreamWriter {
  private sequenceNumber: number;
  private readonly cipher: Cipher;

  constructor(private readonly config: PacketProtectionConfig, initialSequenceNumber = 0) {
    this.sequenceNumber = initialSequenceNumber >>> 0;
    this.cipher = createCipheriv(toNodeCipherName(config.cipherName), config.encryptionKey, config.initialIv);
  }

  write(payload: Buffer): Buffer {
    const { encryptedPacket, mac } = this.protect(payload);
    return Buffer.concat([encryptedPacket, mac]);
  }

  writeProtected(payload: Buffer): ProtectedPacket {
    return this.protect(payload);
  }

  private protect(payload: Buffer): ProtectedPacket {
    const plainPacket = encodeSshPacket(payload, 16);
    const mac = computeSshMac(this.config.macName, this.config.macKey, this.sequenceNumber, plainPacket);
    const encryptedPacket = this.cipher.update(plainPacket);
    this.sequenceNumber = (this.sequenceNumber + 1) >>> 0;
    return { encryptedPacket, mac };
  }

  getSequenceNumber(): number {
    return this.sequenceNumber;
  }
}
