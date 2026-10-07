import type { SshKeyFormat, SshKeyType } from "../../../../shared/types.js";

/**
 * What the key form can tell about pasted key text before saving. The core
 * only checks the header when it saves and parses the key at connect time, so
 * this mirrors its normalisation and catches the usual mix-ups early: a public
 * key, a PuTTY file, a file path, a key cut off at the end.
 */
export type KeyTextKind = "empty" | "private" | "public" | "putty" | "path" | "unknown";

export interface KeyTextAnalysis {
  kind: KeyTextKind;
  keyType?: SshKeyType;
  keyFormat?: SshKeyFormat;
  /** Passphrase-protected OpenSSH key, which the SSH core cannot load yet. */
  encryptedOpenSsh?: boolean;
  /** Encrypted PEM or PKCS#8: it needs the passphrase to sign in. */
  needsPassphrase?: boolean;
  /** The BEGIN line has no matching END line. */
  truncated?: boolean;
}

export interface KeyTextProblem {
  message: string;
  /** Second line with an example of where the right text lives. */
  hint?: string;
  /** For the hint: the private key file name that pairs with a public key. */
  file?: string;
}

const PRIVATE_HEADER = /^-----BEGIN ((?:OPENSSH |RSA |DSA |EC |ENCRYPTED )?PRIVATE KEY)-----$/mu;
const PUBLIC_KEY_LINE = /^(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-[a-z0-9-]+|sk-(?:ssh-ed25519|ecdsa-sha2-[a-z0-9-]+)@openssh\.com)\b/iu;
const PUBLIC_PEM_HEADER = /^-----BEGIN (?:SSH2 |RSA )?PUBLIC KEY-----/mu;
const PUTTY_HEADER = /^PuTTY-User-Key-File-\d+:/mu;

/** Same normalisation the core applies before it saves a key. */
export function normalizeKeyText(text: string): string {
  let normalized = text.replace(/^\uFEFF/u, "").trim();
  if (!normalized.includes("\n") && /\\[rn]/u.test(normalized)) {
    normalized = normalized.replace(/\\r\\n/gu, "\n").replace(/\\n/gu, "\n").replace(/\\r/gu, "\n");
  }
  return normalized.replace(/\r\n/gu, "\n").replace(/\r/gu, "\n");
}

export function analyzeKeyText(text: string): KeyTextAnalysis {
  const normalized = normalizeKeyText(text);
  if (!normalized) {
    return { kind: "empty" };
  }
  const header = normalized.match(PRIVATE_HEADER);
  if (header) {
    return analyzePrivateKey(normalized, header[1], header.index ?? 0);
  }
  if (PUBLIC_KEY_LINE.test(normalized)) {
    return { kind: "public", keyType: publicKeyType(normalized) };
  }
  if (PUBLIC_PEM_HEADER.test(normalized)) {
    return { kind: "public" };
  }
  if (PUTTY_HEADER.test(normalized)) {
    return { kind: "putty" };
  }
  if (looksLikePath(normalized)) {
    return { kind: "path" };
  }
  return { kind: "unknown" };
}

/** Problems that make the text useless as a private key; saving waits until they are fixed. */
export function keyTextProblem(analysis: KeyTextAnalysis): KeyTextProblem | undefined {
  switch (analysis.kind) {
    case "public": {
      const file = analysis.keyType === "ed25519" ? "~/.ssh/id_ed25519" : analysis.keyType === "ecdsa" ? "~/.ssh/id_ecdsa" : "~/.ssh/id_rsa";
      return {
        message: "That's a public key. Paste the private key — it starts with -----BEGIN … PRIVATE KEY-----.",
        hint: "It's the same file without .pub, for example",
        file
      };
    }
    case "putty":
      return { message: "That’s a PuTTY .ppk key. In PuTTYgen choose Conversions → Export OpenSSH key, then paste that text." };
    case "path":
      return { message: "That’s a file path. Open the file in a text editor and paste what’s inside." };
    case "unknown":
      return { message: "This doesn’t look like a private key. Paste the whole key, starting with -----BEGIN … PRIVATE KEY-----." };
    case "private":
      return analysis.truncated
        ? { message: "The key looks cut off — its -----END … PRIVATE KEY----- line is missing. Copy the whole file again." }
        : undefined;
    default:
      return undefined;
  }
}

/** Keys that save fine but cannot sign in yet (the SSH core supports RSA and Ed25519, PEM passphrases only). */
export function keyTextWarning(analysis: KeyTextAnalysis): string | undefined {
  if (analysis.kind !== "private" || analysis.truncated) {
    return undefined;
  }
  if (analysis.encryptedOpenSsh) {
    return "Passphrase-protected OpenSSH keys can’t sign in yet. Convert the key to PEM with ssh-keygen -p -m PEM, then paste it again.";
  }
  if (analysis.keyType === "ecdsa") {
    return "ECDSA keys can be saved but can’t sign in yet. Use an RSA or Ed25519 key to connect.";
  }
  if (analysis.keyType === "dsa") {
    return "DSA keys can be saved but can’t sign in yet. Use an RSA or Ed25519 key to connect.";
  }
  return undefined;
}

function analyzePrivateKey(normalized: string, label: string, headerIndex: number): KeyTextAnalysis {
  const footer = `-----END ${label}-----`;
  const footerIndex = normalized.indexOf(footer, headerIndex);
  const truncated = footerIndex < 0;
  const body = normalized.slice(headerIndex, truncated ? undefined : footerIndex);
  switch (label) {
    case "OPENSSH PRIVATE KEY":
      return { kind: "private", keyFormat: "openssh", truncated, ...readOpenSshEnvelope(body) };
    case "RSA PRIVATE KEY":
      return { kind: "private", keyFormat: "pem", keyType: "rsa", truncated, needsPassphrase: isLegacyEncryptedPem(body) };
    case "DSA PRIVATE KEY":
      return { kind: "private", keyFormat: "pem", keyType: "dsa", truncated, needsPassphrase: isLegacyEncryptedPem(body) };
    case "EC PRIVATE KEY":
      return { kind: "private", keyFormat: "pem", keyType: "ecdsa", truncated, needsPassphrase: isLegacyEncryptedPem(body) };
    case "ENCRYPTED PRIVATE KEY":
      // The algorithm sits inside the encrypted part.
      return { kind: "private", keyFormat: "pkcs8", keyType: "unknown", truncated, needsPassphrase: true };
    default:
      return { kind: "private", keyFormat: "pkcs8", keyType: pkcs8KeyType(body), truncated };
  }
}

function isLegacyEncryptedPem(body: string): boolean {
  return /^Proc-Type:\s*4,ENCRYPTED/imu.test(body);
}

function base64Body(block: string): Uint8Array | undefined {
  const base64 = block
    .split("\n")
    .filter((line) => line && !line.startsWith("-----") && !line.includes(":"))
    .join("")
    .replace(/\s+/gu, "");
  if (!base64 || !/^[A-Za-z0-9+/]+=*$/u.test(base64)) {
    return undefined;
  }
  try {
    const binary = atob(base64.length % 4 === 0 ? base64 : base64.slice(0, base64.length - (base64.length % 4)));
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return undefined;
  }
}

class ByteReader {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  uint32(): number {
    if (this.offset + 4 > this.bytes.length) {
      throw new Error("Unexpected end of key data.");
    }
    const value = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 4).getUint32(0);
    this.offset += 4;
    return value;
  }

  bytesField(): Uint8Array {
    const length = this.uint32();
    if (this.offset + length > this.bytes.length) {
      throw new Error("Unexpected end of key data.");
    }
    const value = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  text(): string {
    return String.fromCharCode(...this.bytesField());
  }

  skip(length: number): void {
    this.offset += length;
  }
}

const OPENSSH_MAGIC = "openssh-key-v1\0";

/** Reads the cipher and the key type from the readable part of an OpenSSH envelope. */
function readOpenSshEnvelope(block: string): Pick<KeyTextAnalysis, "keyType" | "encryptedOpenSsh"> {
  const bytes = base64Body(block);
  if (!bytes || String.fromCharCode(...bytes.subarray(0, OPENSSH_MAGIC.length)) !== OPENSSH_MAGIC) {
    return { keyType: "unknown", encryptedOpenSsh: false };
  }
  try {
    const reader = new ByteReader(bytes);
    reader.skip(OPENSSH_MAGIC.length);
    const cipher = reader.text();
    const kdf = reader.text();
    reader.bytesField();
    const count = reader.uint32();
    const encrypted = cipher !== "none" || kdf !== "none";
    let algorithm: string | undefined;
    if (count > 0) {
      algorithm = new ByteReader(reader.bytesField()).text();
    } else if (!encrypted) {
      const privateBlock = new ByteReader(reader.bytesField());
      privateBlock.uint32();
      privateBlock.uint32();
      algorithm = privateBlock.text();
    }
    return { keyType: sshAlgorithmType(algorithm), encryptedOpenSsh: encrypted };
  } catch {
    return { keyType: "unknown", encryptedOpenSsh: false };
  }
}

function sshAlgorithmType(algorithm: string | undefined): SshKeyType {
  if (!algorithm) {
    return "unknown";
  }
  if (algorithm === "ssh-ed25519" || algorithm === "sk-ssh-ed25519@openssh.com") {
    return "ed25519";
  }
  if (algorithm === "ssh-rsa") {
    return "rsa";
  }
  if (algorithm.startsWith("ecdsa-sha2-") || algorithm.startsWith("sk-ecdsa-sha2-")) {
    return "ecdsa";
  }
  if (algorithm === "ssh-dss") {
    return "dsa";
  }
  return "unknown";
}

function publicKeyType(line: string): SshKeyType {
  return sshAlgorithmType(line.split(/\s+/u)[0]?.toLowerCase());
}

// DER-encoded algorithm OIDs in a PKCS#8 AlgorithmIdentifier.
const PKCS8_OIDS: Array<{ type: SshKeyType; oid: number[] }> = [
  { type: "rsa", oid: [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] },
  { type: "rsa", oid: [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a] },
  { type: "ed25519", oid: [0x06, 0x03, 0x2b, 0x65, 0x70] },
  { type: "ecdsa", oid: [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01] },
  { type: "dsa", oid: [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01] }
];

function pkcs8KeyType(block: string): SshKeyType {
  const bytes = base64Body(block);
  if (!bytes) {
    return "unknown";
  }
  // The algorithm identifier sits in the first few dozen bytes.
  const head = bytes.subarray(0, 64);
  for (const candidate of PKCS8_OIDS) {
    if (indexOfSequence(head, candidate.oid) >= 0) {
      return candidate.type;
    }
  }
  return "unknown";
}

function indexOfSequence(haystack: Uint8Array, needle: number[]): number {
  outer: for (let start = 0; start + needle.length <= haystack.length; start += 1) {
    for (let index = 0; index < needle.length; index += 1) {
      if (haystack[start + index] !== needle[index]) {
        continue outer;
      }
    }
    return start;
  }
  return -1;
}

function looksLikePath(text: string): boolean {
  if (text.includes("\n") || text.length > 400) {
    return false;
  }
  return (
    /^~[\\/]/u.test(text) ||
    /^[A-Za-z]:[\\/]/u.test(text) ||
    /^\\\\/u.test(text) ||
    /^\.{0,2}\/[^\s]*$/u.test(text) ||
    /^file:\/\//iu.test(text) ||
    /\.(?:pem|ppk|key|pub)$/iu.test(text) ||
    /(?:^|[\\/])id_(?:rsa|ed25519|ecdsa|dsa)$/u.test(text)
  );
}

/** Whether the key box shows its text, and whether only because the text is a public key. */
export interface KeyReveal {
  shown: boolean;
  auto: boolean;
}

/**
 * A public key isn't secret, so the box shows it while the text is one. When
 * the text stops being a public key - the private key is pasted over it - an
 * automatic reveal ends; a Show the user pressed stays their choice.
 */
export function revealAfterKeyEdit(current: KeyReveal, text: string): KeyReveal {
  if (analyzeKeyText(text).kind === "public") {
    return current.shown ? current : { shown: true, auto: true };
  }
  return current.auto ? { shown: false, auto: false } : current;
}
