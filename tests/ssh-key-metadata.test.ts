import { generateKeyPairSync, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { SshBinaryWriter } from "../src/core/ssh/binary.js";
import { detectSshKeyMetadata } from "../src/core/ssh/private-key.js";

describe("SSH key metadata detection", () => {
  it("reads the type of OpenSSH keys from the public part of the envelope", () => {
    expect(detectSshKeyMetadata(openSshKey(publicBlob("ssh-ed25519", randomBytes(32))))).toEqual({
      keyType: "ed25519",
      keyFormat: "openssh",
      encryptedOpenSsh: false
    });
    expect(detectSshKeyMetadata(openSshKey(rsaPublicBlob())).keyType).toBe("rsa");
    expect(detectSshKeyMetadata(openSshKey(ecdsaPublicBlob())).keyType).toBe("ecdsa");
    expect(detectSshKeyMetadata(openSshKey(publicBlob("ssh-dss", randomBytes(64))))).toEqual({
      keyType: "dsa",
      keyFormat: "openssh",
      encryptedOpenSsh: false
    });
  });

  // The public part stays readable when the private part is encrypted, so
  // the key list can still say what an unsupported key is.
  it("flags passphrase-protected OpenSSH keys and still names their type", () => {
    const encrypted = openSshKey(publicBlob("ssh-ed25519", randomBytes(32)), { cipher: "aes256-ctr", kdf: "bcrypt" });

    expect(detectSshKeyMetadata(encrypted)).toEqual({ keyType: "ed25519", keyFormat: "openssh", encryptedOpenSsh: true });
    expect(detectSshKeyMetadata(encrypted, "the passphrase does not help").encryptedOpenSsh).toBe(true);
  });

  it("falls back to the private block when the public section is empty", () => {
    const privateBlock = new SshBinaryWriter().uint32(7).uint32(7).string("ssh-rsa").toBuffer();

    expect(detectSshKeyMetadata(openSshKey(Buffer.alloc(0), { privateBlock })).keyType).toBe("rsa");
  });

  it("reads PEM key types from the header, encrypted or not", () => {
    const rsaPem = generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey.export({ format: "pem", type: "pkcs1" }).toString();
    const encryptedRsaPem = generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey.export({
      format: "pem",
      type: "pkcs1",
      cipher: "aes-128-cbc",
      passphrase: "secret"
    }).toString();
    const ecPem = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "pem", type: "sec1" }).toString();

    expect(detectSshKeyMetadata(rsaPem)).toEqual({ keyType: "rsa", keyFormat: "pem", encryptedOpenSsh: false });
    expect(encryptedRsaPem).toContain("Proc-Type: 4,ENCRYPTED");
    expect(detectSshKeyMetadata(encryptedRsaPem)).toEqual({ keyType: "rsa", keyFormat: "pem", encryptedOpenSsh: false });
    expect(detectSshKeyMetadata(ecPem)).toEqual({ keyType: "ecdsa", keyFormat: "pem", encryptedOpenSsh: false });
    expect(detectSshKeyMetadata("-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----")).toEqual({
      keyType: "dsa",
      keyFormat: "pem",
      encryptedOpenSsh: false
    });
  });

  it("parses PKCS#8 keys to learn their algorithm", () => {
    const pkcs8 = (key: ReturnType<typeof generateKeyPairSync>["privateKey"]): string =>
      key.export({ format: "pem", type: "pkcs8" }).toString();

    expect(detectSshKeyMetadata(pkcs8(generateKeyPairSync("ed25519").privateKey))).toEqual({
      keyType: "ed25519",
      keyFormat: "pkcs8",
      encryptedOpenSsh: false
    });
    expect(detectSshKeyMetadata(pkcs8(generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey)).keyType).toBe("rsa");
    expect(detectSshKeyMetadata(pkcs8(generateKeyPairSync("ec", { namedCurve: "P-384" }).privateKey)).keyType).toBe("ecdsa");
    expect(detectSshKeyMetadata(pkcs8(generateKeyPairSync("dsa", { modulusLength: 1024, divisorLength: 160 }).privateKey)).keyType).toBe("dsa");
  });

  it("needs the passphrase to name the algorithm of an encrypted PKCS#8 key", () => {
    const encrypted = generateKeyPairSync("ed25519").privateKey.export({
      format: "pem",
      type: "pkcs8",
      cipher: "aes-256-cbc",
      passphrase: "correct horse"
    }).toString();

    expect(detectSshKeyMetadata(encrypted)).toEqual({ keyType: "unknown", keyFormat: "pkcs8", encryptedOpenSsh: false });
    expect(detectSshKeyMetadata(encrypted, "wrong")).toEqual({ keyType: "unknown", keyFormat: "pkcs8", encryptedOpenSsh: false });
    expect(detectSshKeyMetadata(encrypted, "correct horse").keyType).toBe("ed25519");
  });

  it("accepts keys pasted with escaped newlines", () => {
    const pem = generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }).toString();

    expect(detectSshKeyMetadata(pem.trim().replace(/\n/gu, "\\n")).keyType).toBe("ed25519");
  });

  it("reports anything else as unknown without throwing", () => {
    const unknown = { keyType: "unknown", keyFormat: "unknown", encryptedOpenSsh: false };

    expect(detectSshKeyMetadata("")).toEqual(unknown);
    expect(detectSshKeyMetadata("garbage")).toEqual(unknown);
    expect(detectSshKeyMetadata("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample user@host")).toEqual(unknown);
    expect(detectSshKeyMetadata("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----")).toEqual(unknown);
    expect(detectSshKeyMetadata("-----BEGIN PRIVATE KEY-----\nnot base64 at all\n-----END PRIVATE KEY-----")).toEqual({
      ...unknown,
      keyFormat: "pkcs8"
    });
    expect(detectSshKeyMetadata("-----BEGIN OPENSSH PRIVATE KEY-----\nbm90LWEta2V5\n-----END OPENSSH PRIVATE KEY-----")).toEqual({
      ...unknown,
      keyFormat: "openssh"
    });
    expect(detectSshKeyMetadata(openSshKey(publicBlob("ssh-unheard-of", randomBytes(8)))).keyType).toBe("unknown");
  });
});

function publicBlob(algorithm: string, body: Buffer): Buffer {
  return new SshBinaryWriter().string(algorithm).string(body).toBuffer();
}

function rsaPublicBlob(): Buffer {
  return new SshBinaryWriter().string("ssh-rsa").mpint(65537n).mpint(BigInt(`0x${randomBytes(128).toString("hex")}`)).toBuffer();
}

function ecdsaPublicBlob(): Buffer {
  return new SshBinaryWriter()
    .string("ecdsa-sha2-nistp256")
    .string("nistp256")
    .string(Buffer.concat([Buffer.from([4]), randomBytes(64)]))
    .toBuffer();
}

function openSshKey(
  publicKey: Buffer,
  options: { cipher?: string; kdf?: string; privateBlock?: Buffer } = {}
): string {
  const kdfOptions = options.kdf && options.kdf !== "none"
    ? new SshBinaryWriter().string(randomBytes(16)).uint32(16).toBuffer()
    : Buffer.alloc(0);
  const envelope = Buffer.concat([
    Buffer.from("openssh-key-v1\0", "utf8"),
    new SshBinaryWriter()
      .string(options.cipher ?? "none")
      .string(options.kdf ?? "none")
      .string(kdfOptions)
      .uint32(1)
      .string(publicKey)
      .string(options.privateBlock ?? randomBytes(48))
      .toBuffer()
  ]);
  const base64 = envelope.toString("base64").match(/.{1,70}/gu)?.join("\n") ?? "";
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${base64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}
