import { createHmac } from "node:crypto";

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

export function computeSshMac(macName: PacketProtectionConfig["macName"], macKey: Buffer, sequenceNumber: number, plainPacket: Buffer): Buffer {
  const sequence = Buffer.allocUnsafe(4);
  sequence.writeUInt32BE(sequenceNumber >>> 0, 0);
  return createHmac(toNodeMacName(macName), macKey).update(sequence).update(plainPacket).digest();
}

export function macLength(macName: PacketProtectionConfig["macName"]): number {
  return macName === "hmac-sha2-256" ? 32 : 64;
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
