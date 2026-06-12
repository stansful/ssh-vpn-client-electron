import { createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";
import { SshBinaryWriter } from "./binary.js";
import { encodeSshSignatureBlob, exportSshPublicKeyBlob } from "./host-key.js";
import { encodePublicKeyAuthSignedRequest } from "./auth-messages.js";

export interface LoadedPrivateKey {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export function loadPrivateKey(privateKeyPem: string, passphrase?: string): LoadedPrivateKey {
  const privateKey = createPrivateKey({
    key: privateKeyPem,
    passphrase
  });
  return {
    privateKey,
    publicKey: createPublicKey(privateKey)
  };
}

export function signSshData(privateKey: KeyObject, algorithm: "rsa-sha2-256" | "rsa-sha2-512" | "ssh-rsa" | "ssh-ed25519", data: Buffer): Buffer {
  if (algorithm === "ssh-ed25519") {
    return encodeSshSignatureBlob(algorithm, sign(null, data, privateKey));
  }
  return encodeSshSignatureBlob(algorithm, sign(rsaHashForSignature(algorithm), data, privateKey));
}

export function buildSignedPublicKeyAuthRequest(request: {
  sessionId: Buffer;
  username: string;
  service: string;
  privateKey: KeyObject;
  publicKey?: KeyObject;
  algorithm?: "rsa-sha2-256" | "rsa-sha2-512" | "ssh-rsa" | "ssh-ed25519";
}): Buffer {
  const publicKey = request.publicKey ?? createPublicKey(request.privateKey);
  const exported = exportSshPublicKeyBlob(publicKey, request.algorithm);
  const signingPayload = buildPublicKeyAuthSigningPayload({
    sessionId: request.sessionId,
    username: request.username,
    service: request.service,
    publicKeyAlgorithm: exported.algorithm,
    publicKeyBlob: exported.blob
  });

  return encodePublicKeyAuthSignedRequest({
    username: request.username,
    service: request.service,
    publicKeyAlgorithm: exported.algorithm,
    publicKeyBlob: exported.blob,
    signatureBlob: signSshData(request.privateKey, exported.algorithm as "rsa-sha2-256" | "rsa-sha2-512" | "ssh-rsa" | "ssh-ed25519", signingPayload)
  });
}

export function buildPublicKeyAuthSigningPayload(request: {
  sessionId: Buffer;
  username: string;
  service: string;
  publicKeyAlgorithm: string;
  publicKeyBlob: Buffer;
}): Buffer {
  return Buffer.concat([
    new SshBinaryWriter().string(request.sessionId).toBuffer(),
    new SshBinaryWriter()
      .byte(50)
      .string(request.username)
      .string(request.service)
      .string("publickey")
      .boolean(true)
      .string(request.publicKeyAlgorithm)
      .string(request.publicKeyBlob)
      .toBuffer()
  ]);
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
