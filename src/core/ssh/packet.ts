import { randomBytes } from "node:crypto";

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
  const packet = Buffer.allocUnsafe(4 + packetLength);
  packet.writeUInt32BE(packetLength, 0);
  packet.writeUInt8(paddingLength, 4);
  payload.copy(packet, 5);
  randomBytes(paddingLength).copy(packet, 5 + payload.length);
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
