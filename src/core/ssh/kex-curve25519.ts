import { createHash, createPublicKey, diffieHellman, generateKeyPairSync, type KeyObject } from "node:crypto";
import { SshBinaryReader, SshBinaryWriter } from "./binary.js";
import { bufferToBigInt } from "./kex-group14.js";

export const SSH_MSG_KEX_ECDH_INIT = 30;
export const SSH_MSG_KEX_ECDH_REPLY = 31;

const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

export interface Curve25519ClientExchange {
  publicKey: Buffer;
  computeSharedSecret(serverPublicKey: Buffer): bigint;
}

export interface Curve25519Reply {
  hostKey: Buffer;
  serverPublicKey: Buffer;
  signature: Buffer;
}

export interface Curve25519ExchangeHashInput {
  clientVersion: string;
  serverVersion: string;
  clientKexInitPayload: Buffer;
  serverKexInitPayload: Buffer;
  serverHostKey: Buffer;
  clientPublicKey: Buffer;
  serverPublicKey: Buffer;
  sharedSecret: bigint;
}

export function createCurve25519ClientExchange(): Curve25519ClientExchange {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  const rawPublicKey = exportRawX25519PublicKey(publicKey);

  return {
    publicKey: rawPublicKey,
    computeSharedSecret(serverPublicKey: Buffer): bigint {
      return bufferToBigInt(
        diffieHellman({
          privateKey,
          publicKey: importRawX25519PublicKey(serverPublicKey)
        })
      );
    }
  };
}

export function encodeCurve25519KexInit(publicKey: Buffer): Buffer {
  ensureX25519PublicKey(publicKey);
  return new SshBinaryWriter().byte(SSH_MSG_KEX_ECDH_INIT).string(publicKey).toBuffer();
}

export function decodeCurve25519KexReply(payload: Buffer): Curve25519Reply {
  const reader = new SshBinaryReader(payload);
  const messageNumber = reader.byte();
  if (messageNumber !== SSH_MSG_KEX_ECDH_REPLY) {
    throw new Error(`Unexpected SSH message ${messageNumber}; expected KEX_ECDH_REPLY.`);
  }
  const reply = {
    hostKey: reader.string(),
    serverPublicKey: reader.string(),
    signature: reader.string()
  };
  ensureX25519PublicKey(reply.serverPublicKey);
  if (!reader.eof()) {
    throw new Error("SSH KEX_ECDH_REPLY payload has trailing bytes.");
  }
  return reply;
}

export function computeCurve25519Sha256ExchangeHash(input: Curve25519ExchangeHashInput): Buffer {
  const material = new SshBinaryWriter()
    .string(stripVersionLineEnding(input.clientVersion))
    .string(stripVersionLineEnding(input.serverVersion))
    .string(input.clientKexInitPayload)
    .string(input.serverKexInitPayload)
    .string(input.serverHostKey)
    .string(input.clientPublicKey)
    .string(input.serverPublicKey)
    .mpint(input.sharedSecret)
    .toBuffer();

  return createHash("sha256").update(material).digest();
}

export function exportRawX25519PublicKey(publicKey: KeyObject): Buffer {
  const spki = publicKey.export({ format: "der", type: "spki" });
  const raw = spki.subarray(-32);
  ensureX25519PublicKey(raw);
  return raw;
}

export function importRawX25519PublicKey(publicKey: Buffer): KeyObject {
  ensureX25519PublicKey(publicKey);
  return createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, publicKey]),
    format: "der",
    type: "spki"
  });
}

function ensureX25519PublicKey(publicKey: Buffer): void {
  if (publicKey.length !== 32) {
    throw new Error("X25519 public key must be 32 bytes.");
  }
}

function stripVersionLineEnding(version: string): string {
  return version.replace(/\r?\n$/u, "");
}
