import { createDecipheriv, createHash, createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";
import { SshBinaryReader, SshBinaryWriter } from "./binary.js";
import { bcryptPbkdf } from "./bcrypt-pbkdf.js";
import { ecdsaHashForAlgorithm, encodeSshSignatureBlob, exportSshPublicKeyBlob, type SshPublicKeyAlgorithm } from "./host-key.js";
import { encodePublicKeyAuthSignedRequest } from "./auth-messages.js";
import { bufferToBigInt } from "./kex-group14.js";
import type { SshKeyFormat, SshKeyType } from "../../shared/types.js";

export interface LoadedPrivateKey {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export interface SshKeyTextMetadata {
  keyType: SshKeyType;
  keyFormat: SshKeyFormat;
  /** Passphrase-protected OpenSSH key: {@link loadPrivateKey} needs its passphrase. */
  encryptedOpenSsh: boolean;
  /**
   * A security-key (FIDO) key, `sk-ecdsa-…` or `sk-ssh-ed25519@openssh.com`:
   * its file only names the hardware key that signs, so it cannot sign in.
   * Present only when true.
   */
  securityKey?: boolean;
  /**
   * For a passphrase-protected OpenSSH key {@link loadPrivateKey} refuses
   * whatever the passphrase: the cipher (or KDF) it is encrypted with, when
   * that is not one of the AES ones, or its bcrypt rounds, when more than
   * MAXIMUM_BCRYPT_ROUNDS. Each is present only when it is the reason.
   */
  unsupportedOpenSshCipher?: string;
  excessiveBcryptRounds?: number;
}

type OpenSshCipher = {
  nodeName: string;
  keyLength: number;
  ivLength: number;
  blockSize: number;
  /** Bytes of authentication tag stored after the encrypted section (AES-GCM). */
  tagLength: number;
};

/** Ciphers `ssh-keygen -Z` can protect a private key with that this loader reads. */
const OPENSSH_KEY_CIPHERS: Readonly<Record<string, OpenSshCipher>> = {
  "aes128-ctr": { nodeName: "aes-128-ctr", keyLength: 16, ivLength: 16, blockSize: 16, tagLength: 0 },
  "aes192-ctr": { nodeName: "aes-192-ctr", keyLength: 24, ivLength: 16, blockSize: 16, tagLength: 0 },
  "aes256-ctr": { nodeName: "aes-256-ctr", keyLength: 32, ivLength: 16, blockSize: 16, tagLength: 0 },
  "aes128-cbc": { nodeName: "aes-128-cbc", keyLength: 16, ivLength: 16, blockSize: 16, tagLength: 0 },
  "aes192-cbc": { nodeName: "aes-192-cbc", keyLength: 24, ivLength: 16, blockSize: 16, tagLength: 0 },
  "aes256-cbc": { nodeName: "aes-256-cbc", keyLength: 32, ivLength: 16, blockSize: 16, tagLength: 0 },
  "aes128-gcm@openssh.com": { nodeName: "aes-128-gcm", keyLength: 16, ivLength: 12, blockSize: 16, tagLength: 16 },
  "aes256-gcm@openssh.com": { nodeName: "aes-256-gcm", keyLength: 32, ivLength: 12, blockSize: 16, tagLength: 16 }
};

/**
 * Each bcrypt round costs about 9 ms here, on the main thread: ssh-keygen's
 * default of 16 or 24 rounds is a fifth of a second, `-a 100` nearly one.
 * This bound leaves room for the `-a 100` hardening guides recommend, and
 * refuses a count that would freeze the app for seconds (500 rounds is about
 * 4.5 s). The key text analyser in the key form says so before saving.
 */
const MAXIMUM_BCRYPT_ROUNDS = 128;

/**
 * Keys already opened with bcrypt, by a digest of their text and passphrase,
 * so an automatic reconnect does not pay for the KDF again on the main
 * thread. Held in this process only, and dropped by
 * {@link forgetOpenedPrivateKeys} when a session ends.
 */
const openedEncryptedKeys = new Map<string, KeyObject>();
const MAXIMUM_OPENED_ENCRYPTED_KEYS = 4;

/** Drops the keys kept open for reconnects; the next connect derives them again. */
export function forgetOpenedPrivateKeys(): void {
  openedEncryptedKeys.clear();
}

/** Why an OpenSSH key could not be opened, as far as the user can act on it. */
type OpenSshKeyProblem = "unsupported-encryption" | "passphrase-required" | "wrong-passphrase" | "security-key";

class OpenSshKeyError extends Error {
  constructor(
    readonly problem: OpenSshKeyProblem,
    message: string
  ) {
    super(message);
    this.name = "OpenSshKeyError";
  }
}

/**
 * Describes a private key from its text alone, for the key list and the key
 * picker. Nothing here proves the key loads: an OpenSSH key names its type in
 * the public part of the envelope, which stays readable even when the private
 * part is encrypted, and a PEM key names it in its header. Only unencrypted
 * PKCS#8 (or encrypted PKCS#8 with its passphrase) has to be parsed.
 *
 * Never throws; anything unrecognised is reported as unknown.
 */
export function detectSshKeyMetadata(privateKeyText: string, passphrase?: string): SshKeyTextMetadata {
  const unknown: SshKeyTextMetadata = { keyType: "unknown", keyFormat: "unknown", encryptedOpenSsh: false };
  let normalized: string;
  try {
    normalized = normalizeSshPrivateKeyText(privateKeyText);
  } catch {
    return unknown;
  }
  const header = normalized.match(/^-----BEGIN ([A-Z0-9 ]+)-----$/mu)?.[1];
  switch (header) {
    case "OPENSSH PRIVATE KEY":
      return detectOpenSshKeyMetadata(normalized);
    case "RSA PRIVATE KEY":
      return { keyType: "rsa", keyFormat: "pem", encryptedOpenSsh: false };
    case "DSA PRIVATE KEY":
      return { keyType: "dsa", keyFormat: "pem", encryptedOpenSsh: false };
    case "EC PRIVATE KEY":
      return { keyType: "ecdsa", keyFormat: "pem", encryptedOpenSsh: false };
    case "PRIVATE KEY":
      return { keyType: detectPkcs8KeyType(normalized), keyFormat: "pkcs8", encryptedOpenSsh: false };
    case "ENCRYPTED PRIVATE KEY":
      // The algorithm sits inside the encrypted part, so the type is only
      // known when the passphrase is at hand.
      return {
        keyType: passphrase ? detectPkcs8KeyType(normalized, passphrase) : "unknown",
        keyFormat: "pkcs8",
        encryptedOpenSsh: false
      };
    default:
      return unknown;
  }
}

function detectOpenSshKeyMetadata(normalized: string): SshKeyTextMetadata {
  try {
    const envelope = readOpenSshEnvelope(normalized);
    const encrypted = envelope.cipherName !== "none" || envelope.kdfName !== "none";
    let algorithm = envelope.publicKeys[0] ? readSshString(envelope.publicKeys[0]) : undefined;
    if (!algorithm && !encrypted) {
      // The public section is optional in practice; an unencrypted private
      // block names the type right after its two check integers.
      const reader = new SshBinaryReader(envelope.privateBlock);
      reader.uint32();
      reader.uint32();
      algorithm = reader.utf8String();
    }
    return {
      keyType: sshAlgorithmToKeyType(algorithm),
      keyFormat: "openssh",
      encryptedOpenSsh: encrypted,
      ...(isSecurityKeyAlgorithm(algorithm) ? { securityKey: true } : {}),
      ...(encrypted ? openSshEncryptionProblem(envelope) : {})
    };
  } catch {
    return { keyType: "unknown", keyFormat: "openssh", encryptedOpenSsh: false };
  }
}

/**
 * Why decryptOpenSshPrivateBlock will refuse an encrypted key, read from the
 * envelope without the passphrase - so the key list can say so, not only the
 * key form while the text is still in it (key-text.ts reads it the same way).
 * The cipher name is shown to the user, so only a plain one is passed on.
 */
function openSshEncryptionProblem(
  envelope: OpenSshEnvelope
): Pick<SshKeyTextMetadata, "unsupportedOpenSshCipher" | "excessiveBcryptRounds"> {
  if (!OPENSSH_KEY_CIPHERS[envelope.cipherName] || envelope.kdfName !== "bcrypt") {
    const cipher = envelope.cipherName;
    return { unsupportedOpenSshCipher: /^[\w@.+-]{1,64}$/u.test(cipher) ? cipher : "an unknown cipher" };
  }
  try {
    const kdfOptions = new SshBinaryReader(envelope.kdfOptions);
    kdfOptions.string();
    const rounds = kdfOptions.uint32();
    return rounds > MAXIMUM_BCRYPT_ROUNDS ? { excessiveBcryptRounds: rounds } : {};
  } catch {
    return {};
  }
}

function readSshString(blob: Buffer): string | undefined {
  try {
    return new SshBinaryReader(blob).utf8String();
  } catch {
    return undefined;
  }
}

function isSecurityKeyAlgorithm(algorithm: string | undefined): boolean {
  return algorithm?.startsWith("sk-") === true;
}

function sshAlgorithmToKeyType(algorithm: string | undefined): SshKeyType {
  if (algorithm === "ssh-ed25519" || algorithm === "sk-ssh-ed25519@openssh.com") {
    return "ed25519";
  }
  if (algorithm === "ssh-rsa") {
    return "rsa";
  }
  if (algorithm?.startsWith("ecdsa-sha2-") || algorithm?.startsWith("sk-ecdsa-sha2-")) {
    return "ecdsa";
  }
  if (algorithm === "ssh-dss") {
    return "dsa";
  }
  return "unknown";
}

function detectPkcs8KeyType(normalized: string, passphrase?: string): SshKeyType {
  try {
    const keyType = createPrivateKey({ key: normalized, format: "pem", passphrase }).asymmetricKeyType;
    if (keyType === "ed25519") {
      return "ed25519";
    }
    if (keyType === "rsa" || keyType === "rsa-pss") {
      return "rsa";
    }
    if (keyType === "ec") {
      return "ecdsa";
    }
    if (keyType === "dsa") {
      return "dsa";
    }
    return "unknown";
  } catch {
    return "unknown";
  }
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
      ? loadOpenSshPrivateKey(normalized, passphrase)
      : createPrivateKey({
          key: normalized,
          passphrase
        });
  } catch (error) {
    const parserError = formatCryptoError(error);
    throw new SshPrivateKeyLoadError(formatPrivateKeyLoadMessage(error), [
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

export function signSshData(privateKey: KeyObject, algorithm: SshPublicKeyAlgorithm, data: Buffer): Buffer {
  if (algorithm === "ssh-ed25519") {
    return encodeSshSignatureBlob(algorithm, sign(null, data, privateKey));
  }
  if (algorithm.startsWith("ecdsa-sha2-")) {
    // RFC 5656 §3.1.2: the signature is string(mpint r || mpint s), not the
    // DER sequence node produces by default.
    const signature = sign(ecdsaHashForAlgorithm(algorithm), data, { key: privateKey, dsaEncoding: "ieee-p1363" });
    const half = signature.length / 2;
    const rs = new SshBinaryWriter()
      .mpint(bufferToBigInt(signature.subarray(0, half)))
      .mpint(bufferToBigInt(signature.subarray(half)))
      .toBuffer();
    return encodeSshSignatureBlob(algorithm, rs);
  }
  return encodeSshSignatureBlob(algorithm, sign(rsaHashForSignature(algorithm), data, privateKey));
}

export function buildSignedPublicKeyAuthRequest(request: {
  sessionId: Buffer;
  username: string;
  service: string;
  privateKey: KeyObject;
  publicKey?: KeyObject;
  algorithm?: SshPublicKeyAlgorithm;
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
    signatureBlob: signSshData(request.privateKey, exported.algorithm, signingPayload)
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

/**
 * What the log may say about key text that would not load. Nothing here is
 * copied from the text itself: a key pasted with its newlines collapsed puts
 * the base64 body on the first and last line, so even a short quote of them
 * can carry a whole Ed25519 seed. Only shapes, counts and a label from a fixed
 * list are reported.
 */
function describePrivateKeyInput(original: string, normalized: string, passphrase?: string): string[] {
  const lines = normalized.split("\n");
  const firstLine = lines[0] ?? "";
  const lastLine = lines[lines.length - 1] ?? "";
  const header = firstLine.match(/^-----BEGIN ([^-]+)-----$/u)?.[1] ?? "unknown";
  const footer = lastLine.match(/^-----END ([^-]+)-----$/u)?.[1] ?? "unknown";
  // The format guess also looks past a header that shares its line with the body.
  const armorLabel = normalized.match(/-----BEGIN ([A-Z0-9 ]+)-----/u)?.[1] ?? header;

  return [
    `format=${formatHeader(armorLabel)}`,
    `header=${describeArmorLine(firstLine, "BEGIN")}`,
    `footer=${describeArmorLine(lastLine, "END")}`,
    `firstLineChars=${firstLine.length}`,
    `lastLineChars=${lastLine.length}`,
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

const KNOWN_ARMOR_LABELS = new Set([
  "OPENSSH PRIVATE KEY",
  "RSA PRIVATE KEY",
  "DSA PRIVATE KEY",
  "EC PRIVATE KEY",
  "ENCRYPTED PRIVATE KEY",
  "PRIVATE KEY"
]);

/**
 * "BEGIN OPENSSH PRIVATE KEY" for a line that is exactly a known armor line,
 * otherwise only how the line is shaped.
 */
function describeArmorLine(line: string, kind: "BEGIN" | "END"): string {
  const label = line.match(new RegExp(`^-----${kind} ([A-Z0-9 ]+)-----$`, "u"))?.[1];
  if (label !== undefined) {
    return KNOWN_ARMOR_LABELS.has(label) ? `${kind} ${label}` : `${kind} (unrecognized label)`;
  }
  if (line.startsWith(`-----${kind} `)) {
    return `${kind} followed by more text on the same line`;
  }
  if (line.includes(`-----${kind} `)) {
    return `${kind} after other text on the same line`;
  }
  return line.length === 0 ? "empty" : `no ${kind} line`;
}

/** An algorithm or cipher name read from key text, or a placeholder if it does not look like one. */
function safeName(value: string): string {
  return /^[A-Za-z0-9@._+-]{1,64}$/u.test(value) ? value : "(unrecognized)";
}

function formatCryptoError(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).replace(/\s+/gu, " ").trim();
}

// No ":" or "=" follows "private key" or "passphrase" in these: the services'
// log redaction reads whatever comes after one as a secret and masks it, which
// would turn the sentence in Activity and main.log into a masked "secret".
function formatPrivateKeyLoadMessage(error: unknown): string {
  if (error instanceof OpenSshKeyError) {
    if (error.problem === "unsupported-encryption") {
      // Keeps the wording the connect screen recognises.
      return "Encrypted OpenSSH private keys are not supported with this cipher or bcrypt round count. Re-encrypt the key with ssh-keygen -p -Z aes256-ctr, or convert it to encrypted PKCS8/PEM.";
    }
    if (error.problem === "passphrase-required") {
      return "Unable to load SSH private key because it is protected with a passphrase, and none was provided.";
    }
    if (error.problem === "security-key") {
      return "Unable to load SSH private key because it is a security-key (FIDO) key, which signs only with its hardware key. Use an Ed25519, ECDSA or RSA key.";
    }
    return "Unable to load SSH private key because the passphrase is wrong.";
  }
  return "Unable to load SSH private key. Check the key format and passphrase.";
}

function isOpenSshPrivateKey(value: string): boolean {
  return value.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----");
}

function loadOpenSshPrivateKey(privateKeyPem: string, passphrase?: string): KeyObject {
  const envelope = readOpenSshEnvelope(privateKeyPem);
  const encryptedWithKdf = envelope.kdfName !== "none" && Boolean(passphrase);
  const cacheKey = encryptedWithKdf
    ? createHash("sha256").update(privateKeyPem).update("\0").update(passphrase ?? "").digest("hex")
    : undefined;
  const opened = cacheKey === undefined ? undefined : openedEncryptedKeys.get(cacheKey);
  if (opened) {
    return opened;
  }
  const privateKey = openOpenSshPrivateKey(envelope, passphrase);
  if (cacheKey !== undefined) {
    if (openedEncryptedKeys.size >= MAXIMUM_OPENED_ENCRYPTED_KEYS) {
      const oldest = openedEncryptedKeys.keys().next().value;
      if (oldest !== undefined) {
        openedEncryptedKeys.delete(oldest);
      }
    }
    openedEncryptedKeys.set(cacheKey, privateKey);
  }
  return privateKey;
}

function openOpenSshPrivateKey(envelope: OpenSshEnvelope, passphrase?: string): KeyObject {
  if (envelope.publicKeys.length !== 1) {
    throw new Error(`OpenSSH private key contains ${envelope.publicKeys.length} public keys; expected 1.`);
  }
  // Said before asking for a passphrase that would not help.
  if (isSecurityKeyAlgorithm(readSshString(envelope.publicKeys[0]))) {
    throw new OpenSshKeyError("security-key", "OpenSSH private key is a security-key (FIDO) key.");
  }
  const encrypted = envelope.cipherName !== "none" || envelope.kdfName !== "none";

  const reader = new SshBinaryReader(decryptOpenSshPrivateBlock(envelope, passphrase));
  const check1 = reader.uint32();
  const check2 = reader.uint32();
  if (check1 !== check2) {
    // Two copies of one random number: with the wrong key they decrypt to
    // two different ones. (AES-GCM keys fail their tag before this.)
    if (encrypted) {
      throw new OpenSshKeyError("wrong-passphrase", "OpenSSH private key checkints do not match after decryption; the passphrase is wrong.");
    }
    throw new Error("OpenSSH private key checkints do not match.");
  }

  const keyType = reader.utf8String();
  const privateKey = readOpenSshKeyObject(keyType, reader);
  reader.utf8String();
  validateOpenSshPadding(reader.remaining());
  return privateKey;
}

type OpenSshEnvelope = {
  cipherName: string;
  kdfName: string;
  kdfOptions: Buffer;
  publicKeys: Buffer[];
  privateBlock: Buffer;
  /** Bytes after the private section: the AES-GCM tag, empty otherwise. */
  trailer: Buffer;
};

function readOpenSshEnvelope(privateKeyPem: string): OpenSshEnvelope {
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
  return { cipherName, kdfName, kdfOptions, publicKeys, privateBlock, trailer: reader.remaining() };
}

/** The plaintext private section: as stored for an unencrypted key, decrypted otherwise. */
function decryptOpenSshPrivateBlock(envelope: OpenSshEnvelope, passphrase: string | undefined): Buffer {
  if (envelope.cipherName === "none" && envelope.kdfName === "none") {
    if (envelope.trailer.length > 0) {
      throw new Error("OpenSSH private key envelope has trailing bytes.");
    }
    return envelope.privateBlock;
  }
  const cipher = OPENSSH_KEY_CIPHERS[envelope.cipherName];
  if (!cipher || envelope.kdfName !== "bcrypt") {
    throw new OpenSshKeyError(
      "unsupported-encryption",
      `Encrypted OpenSSH private key uses an unsupported cipher=${safeName(envelope.cipherName)}, kdf=${safeName(envelope.kdfName)}.`
    );
  }
  const kdfOptions = new SshBinaryReader(envelope.kdfOptions);
  const salt = kdfOptions.string();
  const rounds = kdfOptions.uint32();
  if (!kdfOptions.eof()) {
    throw new Error("OpenSSH private key bcrypt options have trailing bytes.");
  }
  if (rounds < 1 || rounds > MAXIMUM_BCRYPT_ROUNDS) {
    throw new OpenSshKeyError(
      "unsupported-encryption",
      `OpenSSH private key asks for ${rounds} bcrypt rounds; at most ${MAXIMUM_BCRYPT_ROUNDS} are accepted.`
    );
  }
  if (envelope.privateBlock.length === 0 || envelope.privateBlock.length % cipher.blockSize !== 0) {
    throw new Error("Encrypted OpenSSH private key section is not a whole number of cipher blocks.");
  }
  if (envelope.trailer.length !== cipher.tagLength) {
    throw new Error("Encrypted OpenSSH private key has trailing bytes that do not fit its cipher.");
  }
  if (!passphrase) {
    throw new OpenSshKeyError("passphrase-required", "Encrypted OpenSSH private key needs its passphrase.");
  }

  const derived = bcryptPbkdf(Buffer.from(passphrase, "utf8"), salt, cipher.keyLength + cipher.ivLength, rounds);
  const key = derived.subarray(0, cipher.keyLength);
  const iv = derived.subarray(cipher.keyLength);
  if (cipher.tagLength > 0) {
    const decipher = createDecipheriv(cipher.nodeName as "aes-256-gcm", key, iv, { authTagLength: cipher.tagLength });
    decipher.setAuthTag(envelope.trailer);
    const plaintext = decipher.update(envelope.privateBlock);
    try {
      decipher.final();
    } catch {
      throw new OpenSshKeyError("wrong-passphrase", "Encrypted OpenSSH private key failed authentication; the passphrase is wrong.");
    }
    return plaintext;
  }
  // The section carries its own 1, 2, 3… padding, checked after parsing.
  const decipher = createDecipheriv(cipher.nodeName, key, iv);
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(envelope.privateBlock), decipher.final()]);
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
      throw new Error(`OpenSSH ECDSA public point is invalid for ${safeName(curveName)}.`);
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

  throw new Error(`Unsupported OpenSSH private key type ${safeName(keyType)}.`);
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
  throw new Error(`Unsupported OpenSSH ECDSA curve ${safeName(curveName)}.`);
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
  throw new Error(`Unsupported OpenSSH ECDSA curve ${safeName(curveName)}.`);
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
      `openSshCipher=${safeName(envelope.cipherName)}`,
      `openSshKdf=${safeName(envelope.kdfName)}`,
      `openSshKdfOptionsBytes=${envelope.kdfOptions.length}`,
      `openSshPublicKeys=${envelope.publicKeys.length}`,
      `openSshPrivateBlockBytes=${envelope.privateBlock.length}`,
      `openSshTrailerBytes=${envelope.trailer.length}`
    ];
  } catch (error) {
    return [`openSshEnvelopeError=${formatCryptoError(error)}`];
  }
}
