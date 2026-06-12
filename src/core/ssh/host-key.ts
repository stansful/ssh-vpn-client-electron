import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { SshBinaryReader, SshBinaryWriter } from "./binary.js";
import { bigIntToBuffer } from "./kex-group14.js";

export type SshHostKeyAlgorithm = "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" | "ssh-ed25519";

export interface ParsedSshHostKey {
  algorithm: SshHostKeyAlgorithm;
  blob: Buffer;
  keyObject: KeyObject;
}

export interface ParsedSshSignature {
  algorithm: string;
  signature: Buffer;
}

export function parseSshHostKeyBlob(blob: Buffer): ParsedSshHostKey {
  const reader = new SshBinaryReader(blob);
  const algorithm = reader.utf8String() as SshHostKeyAlgorithm;

  if (algorithm === "ssh-rsa" || algorithm === "rsa-sha2-256" || algorithm === "rsa-sha2-512") {
    const exponent = reader.mpint();
    const modulus = reader.mpint();
    ensureEof(reader, "host key");
    return {
      algorithm,
      blob,
      keyObject: createPublicKey({
        key: {
          kty: "RSA",
          e: bigIntToBase64Url(exponent),
          n: bigIntToBase64Url(modulus)
        },
        format: "jwk"
      })
    };
  }

  if (algorithm === "ssh-ed25519") {
    const publicKey = reader.string();
    ensureEof(reader, "host key");
    if (publicKey.length !== 32) {
      throw new Error("Invalid ssh-ed25519 public key length.");
    }
    return {
      algorithm,
      blob,
      keyObject: createPublicKey({
        key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicKey]),
        format: "der",
        type: "spki"
      })
    };
  }

  throw new Error(`Unsupported SSH host key algorithm ${algorithm}.`);
}

export function parseSshSignatureBlob(signatureBlob: Buffer): ParsedSshSignature {
  const reader = new SshBinaryReader(signatureBlob);
  const algorithm = reader.utf8String();
  const signature = reader.string();
  ensureEof(reader, "signature");
  return { algorithm, signature };
}

export function verifySshSignature(hostKeyBlob: Buffer, data: Buffer, signatureBlob: Buffer): boolean {
  const hostKey = parseSshHostKeyBlob(hostKeyBlob);
  const signature = parseSshSignatureBlob(signatureBlob);
  if (!isCompatibleSignatureAlgorithm(hostKey.algorithm, signature.algorithm)) {
    return false;
  }

  if (signature.algorithm === "ssh-ed25519") {
    return verify(null, data, hostKey.keyObject, signature.signature);
  }
  return verify(rsaHashForSignature(signature.algorithm), data, hostKey.keyObject, signature.signature);
}

export function encodeRsaPublicKeyBlob(modulus: bigint, exponent: bigint, algorithm: "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" = "ssh-rsa"): Buffer {
  return new SshBinaryWriter().string(algorithm).mpint(exponent).mpint(modulus).toBuffer();
}

export function encodeEd25519PublicKeyBlob(publicKey: Buffer): Buffer {
  if (publicKey.length !== 32) {
    throw new Error("Invalid ssh-ed25519 public key length.");
  }
  return new SshBinaryWriter().string("ssh-ed25519").string(publicKey).toBuffer();
}

export function exportSshPublicKeyBlob(publicKey: KeyObject, algorithm?: "rsa-sha2-256" | "rsa-sha2-512" | "ssh-rsa" | "ssh-ed25519"): { algorithm: string; blob: Buffer } {
  if (publicKey.asymmetricKeyType === "rsa") {
    const selected = algorithm && algorithm !== "ssh-ed25519" ? algorithm : "rsa-sha2-256";
    const jwk = publicKey.export({ format: "jwk" });
    if (!jwk.n || !jwk.e) {
      throw new Error("RSA public key JWK is missing modulus or exponent.");
    }
    const modulus = BigInt(`0x${Buffer.from(jwk.n, "base64url").toString("hex")}`);
    const exponent = BigInt(`0x${Buffer.from(jwk.e, "base64url").toString("hex")}`);
    return {
      algorithm: selected,
      blob: encodeRsaPublicKeyBlob(modulus, exponent, "ssh-rsa")
    };
  }

  if (publicKey.asymmetricKeyType === "ed25519") {
    if (algorithm && algorithm !== "ssh-ed25519") {
      throw new Error(`Algorithm ${algorithm} is incompatible with Ed25519 keys.`);
    }
    const spki = publicKey.export({ format: "der", type: "spki" });
    return {
      algorithm: "ssh-ed25519",
      blob: encodeEd25519PublicKeyBlob(spki.subarray(-32))
    };
  }

  throw new Error(`Unsupported public key type ${publicKey.asymmetricKeyType ?? "unknown"}.`);
}

export function encodeSshSignatureBlob(algorithm: string, signature: Buffer): Buffer {
  return new SshBinaryWriter().string(algorithm).string(signature).toBuffer();
}

function isCompatibleSignatureAlgorithm(hostKeyAlgorithm: SshHostKeyAlgorithm, signatureAlgorithm: string): boolean {
  if (hostKeyAlgorithm === "ssh-ed25519") {
    return signatureAlgorithm === "ssh-ed25519";
  }
  return signatureAlgorithm === "ssh-rsa" || signatureAlgorithm === "rsa-sha2-256" || signatureAlgorithm === "rsa-sha2-512";
}

function rsaHashForSignature(algorithm: string): "sha1" | "sha256" | "sha512" {
  if (algorithm === "ssh-rsa") {
    return "sha1";
  }
  if (algorithm === "rsa-sha2-256") {
    return "sha256";
  }
  if (algorithm === "rsa-sha2-512") {
    return "sha512";
  }
  throw new Error(`Unsupported RSA signature algorithm ${algorithm}.`);
}

function bigIntToBase64Url(value: bigint): string {
  return bigIntToBuffer(value).toString("base64url");
}

function ensureEof(reader: SshBinaryReader, label: string): void {
  if (!reader.eof()) {
    throw new Error(`SSH ${label} blob has trailing bytes.`);
  }
}
