import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  analyzeKeyText,
  keyTextProblem,
  keyTextWarning,
  normalizeKeyText,
  revealAfterKeyEdit
} from "../src/renderer/components/pages/keys/key-text.js";

function sshString(value: string | Buffer): Buffer {
  const body = typeof value === "string" ? Buffer.from(value, "utf8") : value;
  const length = Buffer.alloc(4);
  length.writeUInt32BE(body.length);
  return Buffer.concat([length, body]);
}

function uint32(value: number): Buffer {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value);
  return buffer;
}

function pem(label: string, body: Buffer): string {
  const base64 = body.toString("base64").replace(/(.{70})/gu, "$1\n");
  return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----\n`;
}

/** Minimal OpenSSH envelope: enough for the analyzer, not a loadable key. */
function openSshKey(options: { algorithm: string; cipher?: string; kdf?: string; withPublicKey?: boolean }): string {
  const cipher = options.cipher ?? "none";
  const kdf = options.kdf ?? "none";
  const publicBlob = Buffer.concat([sshString(options.algorithm), sshString(Buffer.alloc(32, 7))]);
  const privateBlock = Buffer.concat([uint32(0x01020304), uint32(0x01020304), sshString(options.algorithm), sshString(Buffer.alloc(32, 1))]);
  const withPublic = options.withPublicKey ?? true;
  const body = Buffer.concat([
    Buffer.from("openssh-key-v1\0", "binary"),
    sshString(cipher),
    sshString(kdf),
    sshString(kdf === "none" ? Buffer.alloc(0) : Buffer.alloc(24, 9)),
    uint32(withPublic ? 1 : 0),
    ...(withPublic ? [sshString(publicBlob)] : []),
    sshString(cipher === "none" ? privateBlock : Buffer.alloc(64, 3))
  ]);
  return pem("OPENSSH PRIVATE KEY", body);
}

describe("analyzeKeyText", () => {
  it("treats blank text as empty", () => {
    expect(analyzeKeyText("  \n ").kind).toBe("empty");
    expect(keyTextProblem(analyzeKeyText(""))).toBeUndefined();
  });

  it("reads the type of unencrypted OpenSSH keys from the public section", () => {
    const ed25519 = analyzeKeyText(openSshKey({ algorithm: "ssh-ed25519" }));
    expect(ed25519).toMatchObject({ kind: "private", keyFormat: "openssh", keyType: "ed25519", encryptedOpenSsh: false, truncated: false });
    expect(keyTextProblem(ed25519)).toBeUndefined();
    expect(keyTextWarning(ed25519)).toBeUndefined();

    expect(analyzeKeyText(openSshKey({ algorithm: "ssh-rsa" })).keyType).toBe("rsa");
    expect(analyzeKeyText(openSshKey({ algorithm: "ecdsa-sha2-nistp256" })).keyType).toBe("ecdsa");
  });

  it("falls back to the private block when the public section is empty", () => {
    expect(analyzeKeyText(openSshKey({ algorithm: "ssh-ed25519", withPublicKey: false })).keyType).toBe("ed25519");
  });

  it("flags passphrase-protected OpenSSH keys as saveable but not able to sign in", () => {
    const analysis = analyzeKeyText(openSshKey({ algorithm: "ssh-ed25519", cipher: "aes256-ctr", kdf: "bcrypt" }));
    expect(analysis).toMatchObject({ kind: "private", keyType: "ed25519", encryptedOpenSsh: true });
    expect(keyTextProblem(analysis)).toBeUndefined();
    expect(keyTextWarning(analysis)).toMatch(/Passphrase-protected OpenSSH keys can’t sign in yet/u);
  });

  it("detects PEM and PKCS#8 keys made by node", () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 1024 });
    const ed = generateKeyPairSync("ed25519");
    const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });

    expect(analyzeKeyText(rsa.privateKey.export({ type: "pkcs1", format: "pem" }).toString())).toMatchObject({ keyType: "rsa", keyFormat: "pem" });
    expect(analyzeKeyText(rsa.privateKey.export({ type: "pkcs8", format: "pem" }).toString())).toMatchObject({ keyType: "rsa", keyFormat: "pkcs8" });
    expect(analyzeKeyText(ed.privateKey.export({ type: "pkcs8", format: "pem" }).toString())).toMatchObject({ keyType: "ed25519", keyFormat: "pkcs8" });

    const ecPem = analyzeKeyText(ec.privateKey.export({ type: "sec1", format: "pem" }).toString());
    expect(ecPem).toMatchObject({ keyType: "ecdsa", keyFormat: "pem" });
    expect(keyTextWarning(ecPem)).toMatch(/ECDSA keys can be saved but can’t sign in yet/u);
  });

  it("knows encrypted PEM and PKCS#8 keys need a passphrase", () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 1024 });
    const legacy = rsa.privateKey.export({ type: "pkcs1", format: "pem", cipher: "aes-128-cbc", passphrase: "secret" }).toString();
    const pkcs8 = rsa.privateKey.export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: "secret" }).toString();
    expect(analyzeKeyText(legacy)).toMatchObject({ keyType: "rsa", needsPassphrase: true });
    expect(analyzeKeyText(pkcs8)).toMatchObject({ keyFormat: "pkcs8", needsPassphrase: true });
  });

  it("explains a pasted public key and names the matching private key file", () => {
    const analysis = analyzeKeyText("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl home@laptop");
    expect(analysis).toMatchObject({ kind: "public", keyType: "ed25519" });
    expect(keyTextProblem(analysis)).toEqual({
      message: "That's a public key. Paste the private key — it starts with -----BEGIN … PRIVATE KEY-----.",
      hint: "It's the same file without .pub, for example",
      file: "~/.ssh/id_ed25519"
    });
    expect(keyTextProblem(analyzeKeyText("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7xP4mWq2Lr9Tz home@laptop"))?.file).toBe("~/.ssh/id_rsa");
    expect(analyzeKeyText("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----").kind).toBe("public");
  });

  it("recognises PuTTY keys and file paths", () => {
    expect(analyzeKeyText("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n").kind).toBe("putty");
    expect(analyzeKeyText("C:\\Users\\me\\.ssh\\id_rsa").kind).toBe("path");
    expect(analyzeKeyText("~/.ssh/id_ed25519").kind).toBe("path");
    expect(analyzeKeyText("/home/me/keys/server.pem").kind).toBe("path");
    expect(keyTextProblem(analyzeKeyText("~/.ssh/id_ed25519"))?.message).toMatch(/file path/u);
  });

  it("reports text that is not a key at all", () => {
    const analysis = analyzeKeyText("hello there");
    expect(analysis.kind).toBe("unknown");
    expect(keyTextProblem(analysis)?.message).toMatch(/doesn’t look like a private key/u);
  });

  it("catches a key cut off before its END line", () => {
    const full = openSshKey({ algorithm: "ssh-ed25519" });
    const cut = full.slice(0, full.indexOf("-----END"));
    const analysis = analyzeKeyText(cut);
    expect(analysis).toMatchObject({ kind: "private", truncated: true });
    expect(keyTextProblem(analysis)?.message).toMatch(/cut off/u);
    expect(keyTextWarning(analysis)).toBeUndefined();
  });

  it("accepts a key pasted as one JSON line with literal \\n and text before the header", () => {
    const key = openSshKey({ algorithm: "ssh-rsa" }).trim().replace(/\n/gu, "\\n");
    expect(analyzeKeyText(key)).toMatchObject({ kind: "private", keyType: "rsa", truncated: false });
    expect(analyzeKeyText(`Bag Attributes\n${openSshKey({ algorithm: "ssh-ed25519" })}`).keyType).toBe("ed25519");
  });

  it("normalises like the core does", () => {
    expect(normalizeKeyText("\uFEFF  a\r\nb\rc  ")).toBe("a\nb\nc");
  });
});

describe("key box reveal", () => {
  const publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl home@laptop";
  const privateKey = generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }).toString();

  it("masks the private key typed or pasted over a public key that was shown automatically", () => {
    const afterPublic = revealAfterKeyEdit({ shown: false, auto: false }, publicKey);
    expect(afterPublic).toEqual({ shown: true, auto: true });

    expect(revealAfterKeyEdit(afterPublic, privateKey)).toEqual({ shown: false, auto: false });
    expect(revealAfterKeyEdit(afterPublic, "")).toEqual({ shown: false, auto: false });
  });

  it("keeps a Show the user pressed", () => {
    const pressedShow = { shown: true, auto: false };
    expect(revealAfterKeyEdit(pressedShow, publicKey)).toBe(pressedShow);
    expect(revealAfterKeyEdit(pressedShow, privateKey)).toBe(pressedShow);
    expect(revealAfterKeyEdit({ shown: false, auto: false }, privateKey)).toEqual({ shown: false, auto: false });
  });
});
