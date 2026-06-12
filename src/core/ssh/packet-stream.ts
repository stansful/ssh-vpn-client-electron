import { createCipheriv, createDecipheriv, timingSafeEqual, type Cipher, type Decipher } from "node:crypto";
import { decodeSshPacket, encodeSshPacket } from "./packet.js";
import {
  computeSshMac,
  macLength,
  toNodeCipherName,
  type PacketProtectionConfig,
  type ProtectedPacket
} from "./packet-codec.js";

export class SshPlainPacketStreamReader {
  private buffer = Buffer.alloc(0);
  private sequenceNumber = 0;

  push(chunk: Buffer): Buffer[] {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const payloads: Buffer[] = [];

    while (this.buffer.length >= 4) {
      const packetLength = this.buffer.readUInt32BE(0);
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
  private encryptedBuffer = Buffer.alloc(0);
  private plainPacket = Buffer.alloc(0);
  private expectedPlainPacketLength: number | undefined;
  private sequenceNumber: number;
  private readonly decipher: Decipher;

  constructor(private readonly config: PacketProtectionConfig, initialSequenceNumber = 0) {
    this.sequenceNumber = initialSequenceNumber >>> 0;
    this.decipher = createDecipheriv(toNodeCipherName(config.cipherName), config.encryptionKey, config.initialIv);
  }

  push(chunk: Buffer): Buffer[] {
    this.encryptedBuffer = Buffer.concat([this.encryptedBuffer, chunk]);
    const payloads: Buffer[] = [];
    const expectedMacLength = macLength(this.config.macName);

    while (true) {
      if (this.expectedPlainPacketLength === undefined) {
        if (this.encryptedBuffer.length < 4) {
          break;
        }
        const encryptedLength = this.consumeEncrypted(4);
        this.plainPacket = Buffer.concat([this.plainPacket, this.decipher.update(encryptedLength)]);
        this.expectedPlainPacketLength = 4 + this.plainPacket.readUInt32BE(0);
      }

      const remainingPacketBytes = this.expectedPlainPacketLength - this.plainPacket.length;
      if (remainingPacketBytes > 0) {
        if (this.encryptedBuffer.length < remainingPacketBytes) {
          break;
        }
        const encryptedBody = this.consumeEncrypted(remainingPacketBytes);
        this.plainPacket = Buffer.concat([this.plainPacket, this.decipher.update(encryptedBody)]);
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
      this.plainPacket = Buffer.alloc(0);
      this.expectedPlainPacketLength = undefined;
    }

    return payloads;
  }

  getSequenceNumber(): number {
    return this.sequenceNumber;
  }

  bufferedBytes(): number {
    return this.encryptedBuffer.length + this.plainPacket.length;
  }

  private consumeEncrypted(length: number): Buffer {
    const chunk = this.encryptedBuffer.subarray(0, length);
    this.encryptedBuffer = this.encryptedBuffer.subarray(length);
    return chunk;
  }
}

export class SshEncryptedPacketStreamWriter {
  private sequenceNumber: number;
  private readonly cipher: Cipher;

  constructor(private readonly config: PacketProtectionConfig, initialSequenceNumber = 0) {
    this.sequenceNumber = initialSequenceNumber >>> 0;
    this.cipher = createCipheriv(toNodeCipherName(config.cipherName), config.encryptionKey, config.initialIv);
  }

  write(payload: Buffer): Buffer {
    const plainPacket = encodeSshPacket(payload, 16);
    const mac = computeSshMac(this.config.macName, this.config.macKey, this.sequenceNumber, plainPacket);
    const encryptedPacket = this.cipher.update(plainPacket);
    this.sequenceNumber = (this.sequenceNumber + 1) >>> 0;
    return Buffer.concat([encryptedPacket, mac]);
  }

  writeProtected(payload: Buffer): ProtectedPacket {
    const frame = this.write(payload);
    const macBytes = macLength(this.config.macName);
    return {
      encryptedPacket: frame.subarray(0, frame.length - macBytes),
      mac: frame.subarray(frame.length - macBytes)
    };
  }

  getSequenceNumber(): number {
    return this.sequenceNumber;
  }
}
