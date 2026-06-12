import { createCipheriv, createDecipheriv, createHmac, type Cipher, type Decipher, timingSafeEqual } from "node:crypto";
import { decodeSshPacket, encodeSshPacket } from "./packet.js";

export interface PacketProtectionConfig {
  cipherName: "aes128-ctr" | "aes192-ctr" | "aes256-ctr";
  encryptionKey: Buffer;
  initialIv: Buffer;
  macName: "hmac-sha2-256" | "hmac-sha2-512";
  macKey: Buffer;
}

export interface ProtectedPacket {
  encryptedPacket: Buffer;
  mac: Buffer;
}

export class SshPacketProtector {
  private sequenceNumber = 0;
  private readonly cipher: Cipher;
  private readonly decipher: Decipher;

  constructor(private readonly config: PacketProtectionConfig) {
    this.cipher = createCipheriv(toNodeCipherName(this.config.cipherName), this.config.encryptionKey, this.config.initialIv);
    this.decipher = createDecipheriv(toNodeCipherName(this.config.cipherName), this.config.encryptionKey, this.config.initialIv);
  }

  protect(payload: Buffer): ProtectedPacket {
    const plainPacket = encodeSshPacket(payload, 16);
    const mac = computeMac(this.config.macName, this.config.macKey, this.sequenceNumber, plainPacket);
    const encryptedPacket = this.cipher.update(plainPacket);
    this.bumpSequenceNumber();
    return { encryptedPacket, mac };
  }

  unprotect(packet: ProtectedPacket): Buffer {
    const plainPacket = this.decipher.update(packet.encryptedPacket);
    const expectedMac = computeMac(this.config.macName, this.config.macKey, this.sequenceNumber, plainPacket);
    if (packet.mac.length !== expectedMac.length || !timingSafeEqual(packet.mac, expectedMac)) {
      throw new Error("SSH packet MAC verification failed.");
    }
    this.bumpSequenceNumber();
    return decodeSshPacket(plainPacket, 16).payload;
  }

  getSequenceNumber(): number {
    return this.sequenceNumber;
  }

  private bumpSequenceNumber(): void {
    this.sequenceNumber = (this.sequenceNumber + 1) >>> 0;
  }
}

export function computeSshMac(macName: PacketProtectionConfig["macName"], macKey: Buffer, sequenceNumber: number, plainPacket: Buffer): Buffer {
  const sequence = Buffer.allocUnsafe(4);
  sequence.writeUInt32BE(sequenceNumber >>> 0, 0);
  return createHmac(toNodeMacName(macName), macKey).update(sequence).update(plainPacket).digest();
}

export function macLength(macName: PacketProtectionConfig["macName"]): number {
  return macName === "hmac-sha2-256" ? 32 : 64;
}

export function computeMac(macName: PacketProtectionConfig["macName"], macKey: Buffer, sequenceNumber: number, plainPacket: Buffer): Buffer {
  return computeSshMac(macName, macKey, sequenceNumber, plainPacket);
}

export function toNodeCipherName(cipherName: PacketProtectionConfig["cipherName"]): string {
  return cipherName.replace(/^aes(\d+)-ctr$/u, "aes-$1-ctr");
}

export function toNodeMacName(macName: PacketProtectionConfig["macName"]): string {
  if (macName === "hmac-sha2-256") {
    return "sha256";
  }
  return "sha512";
}
