import { createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";
import { SshBinaryReader, SshBinaryWriter } from "./binary.js";
import { encodeSshSignatureBlob, exportSshPublicKeyBlob } from "./host-key.js";
import { encodePublicKeyAuthSignedRequest } from "./auth-messages.js";

export interface LoadedPrivateKey {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export class SshPrivateKeyLoadError extends Error {
  readonly diagnostics: string[];

  constructor(message: string, diagnostics: string[]) {
    super(message);
    this.name = "SshPrivateKeyLoadError";
    this.diagnostics = diagnostics;
  }
}

export function loadPrivateKey(privateKeyPem: string, passphrase?: string): LoadedPrivateKey {
  const normalized = normalizeSshPrivateKeyText(privateKeyPem);
  assertSshPrivateKeyText(normalized);
  let privateKey: KeyObject;
  try {
    privateKey = isOpenSshPrivateKey(normalized)
      ? loadOpenSshPrivateKey(normalized)
      : createPrivateKey({
          key: normalized,
          passphrase
        });
  } catch (error) {
    const parserError = formatCryptoError(error);
    throw new SshPrivateKeyLoadError(formatPrivateKeyLoadMessage(parserError), [
      ...describePrivateKeyInput(privateKeyPem, normalized, passphrase),
      `parserError=${parserError}`
    ]);
  }
  return {
    privateKey,
    publicKey: createPublicKey(privateKey)
  };
}

export function normalizeSshPrivateKeyText(privateKeyText: string): string {
  let normalized = privateKeyText.replace(/^\uFEFF/u, "").trim();
  if (!normalized.includes("\n") && /\\[rn]/u.test(normalized)) {
    normalized = normalized.replace(/\\r\\n/gu, "\n").replace(/\\n/gu, "\n").replace(/\\r/gu, "\n");
  }
  return normalized.replace(/\r\n/gu, "\n").replace(/\r/gu, "\n");
}

export function assertSshPrivateKeyText(privateKeyText: string): void {
  const trimmed = normalizeSshPrivateKeyText(privateKeyText);
  if (!trimmed) {
    throw new Error("SSH private key is empty.");
  }
  if (/^(ssh-(rsa|ed25519)|ecdsa-sha2-)/iu.test(trimmed)) {
    throw new Error("SSH private key field contains a public key. Paste the private key contents instead.");
  }
  if (!/^-----BEGIN (?:OPENSSH |RSA |DSA |EC |ENCRYPTED )?PRIVATE KEY-----/mu.test(trimmed)) {
    throw new Error("SSH private key must start with a PRIVATE KEY PEM/OpenSSH header. Paste the key contents, not a file path.");
  }
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

function describePrivateKeyInput(original: string, normalized: string, passphrase?: string): string[] {
  const lines = normalized.split("\n");
  const firstLine = lines[0] ?? "";
  const lastLine = lines[lines.length - 1] ?? "";
  const header = firstLine.match(/^-----BEGIN ([^-]+)-----$/u)?.[1] ?? "unknown";
  const footer = lastLine.match(/^-----END ([^-]+)-----$/u)?.[1] ?? "unknown";

  return [
    `format=${formatHeader(header)}`,
    `header=${quoteDiagnostic(firstLine)}`,
    `footer=${quoteDiagnostic(lastLine)}`,
    `originalChars=${original.length}`,
    `normalizedChars=${normalized.length}`,
    `originalLineCount=${countLines(original)}`,
    `normalizedLineCount=${lines.length}`,
    `lineEndings=${describeLineEndings(original)}`,
    `containsEscapedNewlines=${/\\[rn]/u.test(original)}`,
    `hasBom=${original.charCodeAt(0) === 0xfeff}`,
    `passphraseProvided=${Boolean(passphrase)}`,
    `legacyPemEncrypted=${/Proc-Type:\s*4,ENCRYPTED/iu.test(normalized) || header === "ENCRYPTED PRIVATE KEY"}`,
    `headerFooterMatch=${header !== "unknown" && header === footer}`,
    ...describeOpenSshEnvelope(header, normalized)
  ];
}

function formatHeader(header: string): string {
  if (header === "OPENSSH PRIVATE KEY") {
    return "openssh";
  }
  if (header === "RSA PRIVATE KEY") {
    return "pkcs1-rsa";
  }
  if (header === "DSA PRIVATE KEY") {
    return "pkcs1-dsa";
  }
  if (header === "EC PRIVATE KEY") {
    return "sec1-ec";
  }
  if (header === "ENCRYPTED PRIVATE KEY") {
    return "pkcs8-encrypted";
  }
  if (header === "PRIVATE KEY") {
    return "pkcs8";
  }
  return "unknown";
}

function countLines(value: string): number {
  if (value.length === 0) {
    return 0;
  }
  return value.split(/\r\n|\n|\r/u).length;
}

function describeLineEndings(value: string): string {
  const crlf = /\r\n/u.test(value);
  const withoutCrlf = value.replace(/\r\n/gu, "");
  const lf = /\n/u.test(withoutCrlf);
  const cr = /\r/u.test(withoutCrlf);
  if (crlf && !lf && !cr) {
    return "crlf";
  }
  if (!crlf && lf && !cr) {
    return "lf";
  }
  if (!crlf && !lf && cr) {
    return "cr";
  }
  if (!crlf && !lf && !cr) {
    return "none";
  }
  return "mixed";
}

function quoteDiagnostic(value: string): string {
  return JSON.stringify(value.length > 96 ? `${value.slice(0, 96)}...` : value);
}

function formatCryptoError(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).replace(/\s+/gu, " ").trim();
}

function formatPrivateKeyLoadMessage(parserError: string): string {
  if (parserError.startsWith("Encrypted OpenSSH private keys are not supported yet.")) {
    return "Encrypted OpenSSH private keys are not supported yet. Use an unencrypted OpenSSH key or convert the key to encrypted PKCS8/PEM.";
  }
  return "Unable to load SSH private key. Check the key format and passphrase.";
}

function isOpenSshPrivateKey(value: string): boolean {
  return value.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----");
}

function loadOpenSshPrivateKey(privateKeyPem: string): KeyObject {
  const envelope = readOpenSshEnvelope(privateKeyPem);
  if (envelope.cipherName !== "none" || envelope.kdfName !== "none") {
    throw new Error(`Encrypted OpenSSH private keys are not supported yet. cipher=${envelope.cipherName}, kdf=${envelope.kdfName}`);
  }
  if (envelope.publicKeys.length !== 1) {
    throw new Error(`OpenSSH private key contains ${envelope.publicKeys.length} public keys; expected 1.`);
  }

  const reader = new SshBinaryReader(envelope.privateBlock);
  const check1 = reader.uint32();
  const check2 = reader.uint32();
  if (check1 !== check2) {
    throw new Error("OpenSSH private key checkints do not match.");
  }

  const keyType = reader.utf8String();
  const privateKey = readOpenSshKeyObject(keyType, reader);
  reader.utf8String();
  validateOpenSshPadding(reader.remaining());
  return privateKey;
}

function readOpenSshEnvelope(privateKeyPem: string): {
  cipherName: string;
  kdfName: string;
  kdfOptions: Buffer;
  publicKeys: Buffer[];
  privateBlock: Buffer;
} {
  const payload = decodePemBody(privateKeyPem);
  const magic = Buffer.from("openssh-key-v1\0", "utf8");
  if (!payload.subarray(0, magic.length).equals(magic)) {
    throw new Error("OpenSSH private key magic is missing.");
  }

  const reader = new SshBinaryReader(payload.subarray(magic.length));
  const cipherName = reader.utf8String();
  const kdfName = reader.utf8String();
  const kdfOptions = reader.string();
  const keyCount = reader.uint32();
  const publicKeys: Buffer[] = [];
  for (let index = 0; index < keyCount; index += 1) {
    publicKeys.push(reader.string());
  }
  const privateBlock = reader.string();
  if (!reader.eof()) {
    throw new Error("OpenSSH private key envelope has trailing bytes.");
  }
  return { cipherName, kdfName, kdfOptions, publicKeys, privateBlock };
}

function readOpenSshKeyObject(keyType: string, reader: SshBinaryReader): KeyObject {
  if (keyType === "ssh-ed25519") {
    const publicKey = reader.string();
    const privateKey = reader.string();
    if (publicKey.length !== 32) {
      throw new Error(`OpenSSH Ed25519 public key has ${publicKey.length} bytes; expected 32.`);
    }
    if (privateKey.length !== 64 && privateKey.length !== 32) {
      throw new Error(`OpenSSH Ed25519 private key has ${privateKey.length} bytes; expected 32 or 64.`);
    }
    const seed = privateKey.subarray(0, 32);
    const jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: publicKey.toString("base64url"),
      d: seed.toString("base64url")
    };
    return createPrivateKey({ key: jwk, format: "jwk" });
  }

  if (keyType === "ssh-rsa") {
    const modulus = reader.mpint();
    const publicExponent = reader.mpint();
    const privateExponent = reader.mpint();
    const coefficient = reader.mpint();
    const prime1 = reader.mpint();
    const prime2 = reader.mpint();
    const jwk = {
      kty: "RSA",
      n: bigIntToBase64Url(modulus),
      e: bigIntToBase64Url(publicExponent),
      d: bigIntToBase64Url(privateExponent),
      p: bigIntToBase64Url(prime1),
      q: bigIntToBase64Url(prime2),
      dp: bigIntToBase64Url(privateExponent % (prime1 - 1n)),
      dq: bigIntToBase64Url(privateExponent % (prime2 - 1n)),
      qi: bigIntToBase64Url(coefficient)
    };
    return createPrivateKey({ key: jwk, format: "jwk" });
  }

  if (keyType.startsWith("ecdsa-sha2-")) {
    const curveName = reader.utf8String();
    const publicPoint = reader.string();
    const privateScalar = reader.mpint();
    const curve = openSshCurveToJwkCurve(curveName);
    const coordinateLength = curveCoordinateLength(curveName);
    if (publicPoint.length !== 1 + coordinateLength * 2 || publicPoint[0] !== 4) {
      throw new Error(`OpenSSH ECDSA public point is invalid for ${curveName}.`);
    }
    const jwk = {
      kty: "EC",
      crv: curve,
      x: publicPoint.subarray(1, 1 + coordinateLength).toString("base64url"),
      y: publicPoint.subarray(1 + coordinateLength).toString("base64url"),
      d: bigIntToFixedLengthBase64Url(privateScalar, coordinateLength)
    };
    return createPrivateKey({ key: jwk, format: "jwk" });
  }

  throw new Error(`Unsupported OpenSSH private key type ${keyType}.`);
}

function decodePemBody(privateKeyPem: string): Buffer {
  const base64 = privateKeyPem
    .split("\n")
    .filter((line) => line && !line.startsWith("-----BEGIN ") && !line.startsWith("-----END "))
    .join("");
  if (!base64) {
    throw new Error("Private key PEM body is empty.");
  }
  return Buffer.from(base64, "base64");
}

function validateOpenSshPadding(padding: Buffer): void {
  for (let index = 0; index < padding.length; index += 1) {
    if (padding[index] !== ((index + 1) & 0xff)) {
      throw new Error("OpenSSH private key padding is invalid.");
    }
  }
}

function openSshCurveToJwkCurve(curveName: string): "P-256" | "P-384" | "P-521" {
  if (curveName === "nistp256") {
    return "P-256";
  }
  if (curveName === "nistp384") {
    return "P-384";
  }
  if (curveName === "nistp521") {
    return "P-521";
  }
  throw new Error(`Unsupported OpenSSH ECDSA curve ${curveName}.`);
}

function curveCoordinateLength(curveName: string): number {
  if (curveName === "nistp256") {
    return 32;
  }
  if (curveName === "nistp384") {
    return 48;
  }
  if (curveName === "nistp521") {
    return 66;
  }
  throw new Error(`Unsupported OpenSSH ECDSA curve ${curveName}.`);
}

function bigIntToBase64Url(value: bigint): string {
  return bigIntToUnsignedBuffer(value).toString("base64url");
}

function bigIntToFixedLengthBase64Url(value: bigint, length: number): string {
  const raw = bigIntToUnsignedBuffer(value);
  if (raw.length > length) {
    throw new Error("Integer is larger than expected fixed-length field.");
  }
  return Buffer.concat([Buffer.alloc(length - raw.length), raw]).toString("base64url");
}

function bigIntToUnsignedBuffer(value: bigint): Buffer {
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

function describeOpenSshEnvelope(header: string, normalized: string): string[] {
  if (header !== "OPENSSH PRIVATE KEY") {
    return [];
  }
  try {
    const envelope = readOpenSshEnvelope(normalized);
    return [
      `openSshCipher=${envelope.cipherName}`,
      `openSshKdf=${envelope.kdfName}`,
      `openSshKdfOptionsBytes=${envelope.kdfOptions.length}`,
      `openSshPublicKeys=${envelope.publicKeys.length}`,
      `openSshPrivateBlockBytes=${envelope.privateBlock.length}`
    ];
  } catch (error) {
    return [`openSshEnvelopeError=${formatCryptoError(error)}`];
  }
}
