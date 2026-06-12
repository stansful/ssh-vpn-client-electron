import { createHash, getDiffieHellman } from "node:crypto";
import { SshBinaryReader, SshBinaryWriter } from "./binary.js";

export const SSH_MSG_KEXDH_INIT = 30;
export const SSH_MSG_KEXDH_REPLY = 31;

export interface Group14Sha256ClientExchange {
  exchangeValue: bigint;
  publicKey: Buffer;
  computeSharedSecret(serverExchangeValue: bigint): bigint;
}

export interface KexDhReply {
  hostKey: Buffer;
  serverExchangeValue: bigint;
  signature: Buffer;
}

export interface ExchangeHashInput {
  clientVersion: string;
  serverVersion: string;
  clientKexInitPayload: Buffer;
  serverKexInitPayload: Buffer;
  serverHostKey: Buffer;
  clientExchangeValue: bigint;
  serverExchangeValue: bigint;
  sharedSecret: bigint;
}

export function createGroup14Sha256ClientExchange(): Group14Sha256ClientExchange {
  const dh = getDiffieHellman("modp14");
  dh.generateKeys();
  const publicKey = dh.getPublicKey();

  return {
    exchangeValue: bufferToBigInt(publicKey),
    publicKey,
    computeSharedSecret(serverExchangeValue: bigint): bigint {
      return bufferToBigInt(dh.computeSecret(bigIntToBuffer(serverExchangeValue)));
    }
  };
}

export function encodeKexDhInit(exchangeValue: bigint): Buffer {
  return new SshBinaryWriter().byte(SSH_MSG_KEXDH_INIT).mpint(exchangeValue).toBuffer();
}

export function decodeKexDhReply(payload: Buffer): KexDhReply {
  const reader = new SshBinaryReader(payload);
  const messageNumber = reader.byte();
  if (messageNumber !== SSH_MSG_KEXDH_REPLY) {
    throw new Error(`Unexpected SSH message ${messageNumber}; expected KEXDH_REPLY.`);
  }

  const reply: KexDhReply = {
    hostKey: reader.string(),
    serverExchangeValue: reader.mpint(),
    signature: reader.string()
  };
  if (!reader.eof()) {
    throw new Error("SSH KEXDH_REPLY payload has trailing bytes.");
  }
  return reply;
}

export function computeGroup14Sha256ExchangeHash(input: ExchangeHashInput): Buffer {
  const material = new SshBinaryWriter()
    .string(stripVersionLineEnding(input.clientVersion))
    .string(stripVersionLineEnding(input.serverVersion))
    .string(input.clientKexInitPayload)
    .string(input.serverKexInitPayload)
    .string(input.serverHostKey)
    .mpint(input.clientExchangeValue)
    .mpint(input.serverExchangeValue)
    .mpint(input.sharedSecret)
    .toBuffer();

  return createHash("sha256").update(material).digest();
}

export function bufferToBigInt(buffer: Buffer): bigint {
  const trimmed = trimLeadingZeroes(buffer);
  if (trimmed.length === 0) {
    return 0n;
  }
  return BigInt(`0x${trimmed.toString("hex")}`);
}

export function bigIntToBuffer(value: bigint): Buffer {
  if (value < 0n) {
    throw new Error("Negative integers are not supported.");
  }
  if (value === 0n) {
    return Buffer.from([0]);
  }
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) {
    hex = `0${hex}`;
  }
  return Buffer.from(hex, "hex");
}

function trimLeadingZeroes(buffer: Buffer): Buffer {
  let offset = 0;
  while (offset < buffer.length && buffer[offset] === 0) {
    offset += 1;
  }
  return buffer.subarray(offset);
}

function stripVersionLineEnding(version: string): string {
  return version.replace(/\r?\n$/u, "");
}
