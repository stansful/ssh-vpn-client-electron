import { createHash } from "node:crypto";
import { SshBinaryWriter } from "./binary.js";

export interface DerivedTransportKeys {
  initialIvClientToServer: Buffer;
  initialIvServerToClient: Buffer;
  encryptionKeyClientToServer: Buffer;
  encryptionKeyServerToClient: Buffer;
  integrityKeyClientToServer: Buffer;
  integrityKeyServerToClient: Buffer;
}

export interface TransportKeyLengths {
  ivLength: number;
  cipherKeyLength: number;
  macKeyLength: number;
  hashAlgorithm?: string;
}

export function deriveTransportKeys(
  sharedSecret: bigint,
  exchangeHash: Buffer,
  sessionId: Buffer,
  lengths: TransportKeyLengths
): DerivedTransportKeys {
  const hashAlgorithm = lengths.hashAlgorithm ?? "sha256";
  return {
    initialIvClientToServer: deriveKey(sharedSecret, exchangeHash, sessionId, "A", lengths.ivLength, hashAlgorithm),
    initialIvServerToClient: deriveKey(sharedSecret, exchangeHash, sessionId, "B", lengths.ivLength, hashAlgorithm),
    encryptionKeyClientToServer: deriveKey(sharedSecret, exchangeHash, sessionId, "C", lengths.cipherKeyLength, hashAlgorithm),
    encryptionKeyServerToClient: deriveKey(sharedSecret, exchangeHash, sessionId, "D", lengths.cipherKeyLength, hashAlgorithm),
    integrityKeyClientToServer: deriveKey(sharedSecret, exchangeHash, sessionId, "E", lengths.macKeyLength, hashAlgorithm),
    integrityKeyServerToClient: deriveKey(sharedSecret, exchangeHash, sessionId, "F", lengths.macKeyLength, hashAlgorithm)
  };
}

export function deriveDirectionalTransportKeys(
  sharedSecret: bigint,
  exchangeHash: Buffer,
  sessionId: Buffer,
  clientToServer: TransportKeyLengths,
  serverToClient: TransportKeyLengths
): DerivedTransportKeys {
  const hashAlgorithm = clientToServer.hashAlgorithm ?? serverToClient.hashAlgorithm ?? "sha256";
  return {
    initialIvClientToServer: deriveKey(sharedSecret, exchangeHash, sessionId, "A", clientToServer.ivLength, hashAlgorithm),
    initialIvServerToClient: deriveKey(sharedSecret, exchangeHash, sessionId, "B", serverToClient.ivLength, hashAlgorithm),
    encryptionKeyClientToServer: deriveKey(sharedSecret, exchangeHash, sessionId, "C", clientToServer.cipherKeyLength, hashAlgorithm),
    encryptionKeyServerToClient: deriveKey(sharedSecret, exchangeHash, sessionId, "D", serverToClient.cipherKeyLength, hashAlgorithm),
    integrityKeyClientToServer: deriveKey(sharedSecret, exchangeHash, sessionId, "E", clientToServer.macKeyLength, hashAlgorithm),
    integrityKeyServerToClient: deriveKey(sharedSecret, exchangeHash, sessionId, "F", serverToClient.macKeyLength, hashAlgorithm)
  };
}

export function deriveKey(
  sharedSecret: bigint,
  exchangeHash: Buffer,
  sessionId: Buffer,
  letter: "A" | "B" | "C" | "D" | "E" | "F",
  requiredLength: number,
  hashAlgorithm = "sha256"
): Buffer {
  if (requiredLength <= 0) {
    return Buffer.alloc(0);
  }

  const sharedSecretBlob = new SshBinaryWriter().mpint(sharedSecret).toBuffer();
  let output = createHash(hashAlgorithm)
    .update(sharedSecretBlob)
    .update(exchangeHash)
    .update(letter, "ascii")
    .update(sessionId)
    .digest();

  while (output.length < requiredLength) {
    const next = createHash(hashAlgorithm).update(sharedSecretBlob).update(exchangeHash).update(output).digest();
    output = Buffer.concat([output, next]);
  }

  return output.subarray(0, requiredLength);
}

export function transportKeyLengthsFor(cipherName: string, macName: string): TransportKeyLengths {
  return {
    ivLength: 16,
    cipherKeyLength: cipherKeyLength(cipherName),
    macKeyLength: macKeyLength(macName),
    hashAlgorithm: "sha256"
  };
}

function cipherKeyLength(cipherName: string): number {
  if (cipherName === "aes128-ctr") {
    return 16;
  }
  if (cipherName === "aes192-ctr") {
    return 24;
  }
  if (cipherName === "aes256-ctr") {
    return 32;
  }
  throw new Error(`Unsupported SSH cipher ${cipherName}.`);
}

function macKeyLength(macName: string): number {
  if (macName === "hmac-sha2-256") {
    return 32;
  }
  if (macName === "hmac-sha2-512") {
    return 64;
  }
  throw new Error(`Unsupported SSH MAC ${macName}.`);
}
