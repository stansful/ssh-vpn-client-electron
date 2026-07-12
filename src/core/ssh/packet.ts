import { randomFillSync } from "node:crypto";

// RFC 4253 requires implementations to accept at least 32 KiB packets, but it
// does not require accepting an unbounded uint32 packet_length. 256 KiB leaves
// ample room for our 64 KiB channel frames and KEX messages while putting a
// hard ceiling on allocations controlled by an unauthenticated peer.
export const MIN_SSH_PACKET_LENGTH = 12;
export const MAX_SSH_PACKET_LENGTH = 256 * 1024;

export interface DecodedSshPacket {
  payload: Buffer;
  padding: Buffer;
}

export function encodeSshPacket(payload: Buffer, blockSize = 8): Buffer {
  if (blockSize < 8) {
    throw new Error("SSH block size must be at least 8 bytes.");
  }

  let paddingLength = blockSize - ((payload.length + 5) % blockSize);
  if (paddingLength < 4) {
    paddingLength += blockSize;
  }

  const packetLength = payload.length + paddingLength + 1;
  assertSshPacketLength(packetLength, blockSize);
  const packet = Buffer.allocUnsafe(4 + packetLength);
  packet.writeUInt32BE(packetLength, 0);
  packet.writeUInt8(paddingLength, 4);
  payload.copy(packet, 5);
  randomFillSync(packet, 5 + payload.length, paddingLength);
  return packet;
}

export function decodeSshPacket(packet: Buffer, blockSize = 8): DecodedSshPacket {
  if (packet.length < 5) {
    throw new Error("SSH packet is too short.");
  }
  if (packet.length % blockSize !== 0) {
    throw new Error("SSH packet is not aligned to the cipher block size.");
  }

  const packetLength = packet.readUInt32BE(0);
  assertSshPacketLength(packetLength, blockSize);
  if (packetLength !== packet.length - 4) {
    throw new Error("SSH packet length mismatch.");
  }

  const paddingLength = packet.readUInt8(4);
  if (paddingLength < 4) {
    throw new Error("SSH packet padding is too short.");
  }

  const payloadLength = packetLength - paddingLength - 1;
  if (payloadLength < 0) {
    throw new Error("SSH packet payload length is invalid.");
  }

  return {
    payload: packet.subarray(5, 5 + payloadLength),
    padding: packet.subarray(5 + payloadLength)
  };
}

export function assertSshPacketLength(packetLength: number, blockSize = 8): void {
  if (!Number.isInteger(packetLength) || packetLength < MIN_SSH_PACKET_LENGTH) {
    throw new Error(`SSH packet length ${packetLength} is below the minimum ${MIN_SSH_PACKET_LENGTH}.`);
  }
  if (packetLength > MAX_SSH_PACKET_LENGTH) {
    throw new Error(`SSH packet length ${packetLength} exceeds the maximum ${MAX_SSH_PACKET_LENGTH}.`);
  }
  if ((packetLength + 4) % blockSize !== 0) {
    throw new Error("SSH packet length is not aligned to the cipher block size.");
  }
}
