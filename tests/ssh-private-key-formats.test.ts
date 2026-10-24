import { createPublicKey, generateKeyPairSync, verify, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import { SshBinaryReader, SshBinaryWriter } from "../src/core/ssh/binary.js";
import { exportSshPublicKeyBlob } from "../src/core/ssh/host-key.js";
import {
  SshPrivateKeyLoadError,
  buildSignedPublicKeyAuthRequest,
  buildPublicKeyAuthSigningPayload,
  detectSshKeyMetadata,
  loadPrivateKey,
  signSshData
} from "../src/core/ssh/private-key.js";
import { FIXTURE_PASSPHRASE, SSH_KEY_FIXTURES } from "./ssh-key-fixtures.js";

describe("passphrase-protected OpenSSH private keys", () => {
  it.each(Object.entries(SSH_KEY_FIXTURES))("opens the ssh-keygen %s key to the public key in its .pub file", (_name, fixture) => {
    const passphrase = fixture.made.includes("-N ''") ? undefined : FIXTURE_PASSPHRASE;
    if (fixture === SSH_KEY_FIXTURES.ed25519ChaCha20Poly1305) {
      expect(() => loadPrivateKey(fixture.privateKey, passphrase)).toThrow(/Encrypted OpenSSH private keys are not supported/u);
      return;
    }

    const loaded = loadPrivateKey(fixture.privateKey, passphrase);

    expect(publicKeyLine(loaded.publicKey)).toBe(fixture.publicKey);
    expect(publicKeyLine(createPublicKey(loaded.privateKey))).toBe(fixture.publicKey);
  });

  it("tells a wrong passphrase apart from a broken key, for every cipher family", () => {
    // CTR and CBC fail the check integers; GCM fails its tag first.
    for (const fixture of [SSH_KEY_FIXTURES.rsa, SSH_KEY_FIXTURES.ed25519Aes256Cbc, SSH_KEY_FIXTURES.ed25519Aes256Gcm]) {
      const error = loadError(fixture.privateKey, "wrong horse");
      expect(error.message).toBe("Unable to load SSH private key because the passphrase is wrong.");
      expect(error.diagnostics.join("; ")).toContain("passphraseProvided=true");
    }
  });

  it("asks for the passphrase when none was given", () => {
    for (const passphrase of [undefined, ""]) {
      expect(loadError(SSH_KEY_FIXTURES.ecdsaP256.privateKey, passphrase).message).toBe(
        "Unable to load SSH private key because it is protected with a passphrase, and none was provided."
      );
    }
  });

  it("refuses a bcrypt round count that would freeze the app", () => {
    // 129 rounds is over a second on the main thread, at every connect.
    const tooSlow = openSshEnvelope({ cipher: "aes256-ctr", rounds: 129 });
    const startedAt = Date.now();
    expect(loadError(tooSlow, "secret").message).toMatch(/^Encrypted OpenSSH private keys are not supported with this cipher or bcrypt round count/u);
    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });

  it("names a security-key (FIDO) key instead of calling it unreadable", () => {
    const envelope = Buffer.concat([
      Buffer.from("openssh-key-v1\0", "utf8"),
      new SshBinaryWriter()
        .string("none")
        .string("none")
        .string(Buffer.alloc(0))
        .uint32(1)
        .string(new SshBinaryWriter().string("sk-ecdsa-sha2-nistp256@openssh.com").string("nistp256").string(Buffer.alloc(65, 4)).string("ssh:").toBuffer())
        .string(Buffer.alloc(64, 2))
        .toBuffer()
    ]);
    const text = `-----BEGIN OPENSSH PRIVATE KEY-----\n${envelope.toString("base64").match(/.{1,70}/gu)?.join("\n") ?? ""}\n-----END OPENSSH PRIVATE KEY-----`;
    expect(detectSshKeyMetadata(text)).toEqual({ keyType: "ecdsa", keyFormat: "openssh", encryptedOpenSsh: false, securityKey: true });
    expect(loadError(text).message).toMatch(/security-key \(FIDO\) key/u);
  });

  it("still describes encrypted keys by type, an AES-GCM key's trailing tag included", () => {
    expect(detectSshKeyMetadata(SSH_KEY_FIXTURES.ed25519Aes256Gcm.privateKey)).toEqual({
      keyType: "ed25519",
      keyFormat: "openssh",
      encryptedOpenSsh: true
    });
    expect(detectSshKeyMetadata(SSH_KEY_FIXTURES.ecdsaP521.privateKey)).toEqual({
      keyType: "ecdsa",
      keyFormat: "openssh",
      encryptedOpenSsh: true
    });
  });
});

describe("ECDSA user keys", () => {
  it.each([
    ["ecdsaP256", "ecdsa-sha2-nistp256", "sha256", 32],
    ["ecdsaP384", "ecdsa-sha2-nistp384", "sha384", 48],
    ["ecdsaP521", "ecdsa-sha2-nistp521", "sha512", 66]
  ] as const)("signs public-key auth with the %s key in the RFC 5656 format", (name, algorithm, hash, coordinateLength) => {
    const fixture = SSH_KEY_FIXTURES[name];
    const loaded = loadPrivateKey(fixture.privateKey, FIXTURE_PASSPHRASE);
    const request = new SshBinaryReader(
      buildSignedPublicKeyAuthRequest({
        sessionId: Buffer.alloc(32, 5),
        username: "alice",
        service: "ssh-connection",
        privateKey: loaded.privateKey,
        publicKey: loaded.publicKey
      })
    );
    expect(request.byte()).toBe(50);
    expect(request.utf8String()).toBe("alice");
    expect(request.utf8String()).toBe("ssh-connection");
    expect(request.utf8String()).toBe("publickey");
    expect(request.boolean()).toBe(true);
    expect(request.utf8String()).toBe(algorithm);
    const publicKeyBlob = request.string();
    expect(`${algorithm} ${publicKeyBlob.toString("base64")}`).toBe(fixture.publicKey);
    const signatureBlob = request.string();
    expect(request.eof()).toBe(true);

    const signedData = buildPublicKeyAuthSigningPayload({
      sessionId: Buffer.alloc(32, 5),
      username: "alice",
      service: "ssh-connection",
      publicKeyAlgorithm: algorithm,
      publicKeyBlob
    });
    const signature = new SshBinaryReader(signatureBlob);
    expect(signature.utf8String()).toBe(algorithm);
    const rs = new SshBinaryReader(signature.string());
    expect(signature.eof()).toBe(true);
    const r = minimalMpint(rs.string());
    const s = minimalMpint(rs.string());
    expect(rs.eof()).toBe(true);

    const p1363 = Buffer.concat([fixedLength(r, coordinateLength), fixedLength(s, coordinateLength)]);
    expect(verify(hash, signedData, { key: loaded.publicKey, dsaEncoding: "ieee-p1363" }, p1363)).toBe(true);
    expect(verify(hash, Buffer.from("other data"), { key: loaded.publicKey, dsaEncoding: "ieee-p1363" }, p1363)).toBe(false);
  });

  it("signs with ECDSA keys from PEM too and refuses a mismatched algorithm", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const loaded = loadPrivateKey(privateKey.export({ format: "pem", type: "sec1" }).toString());
    const blob = signSshData(loaded.privateKey, "ecdsa-sha2-nistp256", Buffer.from("payload"));
    expect(new SshBinaryReader(blob).utf8String()).toBe("ecdsa-sha2-nistp256");

    expect(() => exportSshPublicKeyBlob(publicKey, "ecdsa-sha2-nistp384")).toThrow(/incompatible/u);
    expect(() => exportSshPublicKeyBlob(publicKey, "ssh-ed25519")).toThrow(/incompatible/u);
    expect(() => exportSshPublicKeyBlob(generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey, "ecdsa-sha2-nistp256")).toThrow(
      /incompatible with RSA/u
    );
    expect(() => exportSshPublicKeyBlob(generateKeyPairSync("ec", { namedCurve: "secp256k1" }).publicKey)).toThrow(/Unsupported ECDSA curve/u);
  });

  it("keeps r and s as minimal mpints whatever their leading bits", () => {
    const loaded = loadPrivateKey(SSH_KEY_FIXTURES.ecdsaP256Unencrypted.privateKey);
    // Half of all values have their top bit set and need a zero byte in front.
    let paddedValues = 0;
    for (let index = 0; index < 64; index += 1) {
      const signature = new SshBinaryReader(signSshData(loaded.privateKey, "ecdsa-sha2-nistp256", Buffer.from(`data-${index}`)));
      signature.utf8String();
      const rs = new SshBinaryReader(signature.string());
      for (const value of [rs.string(), rs.string()]) {
        minimalMpint(value);
        paddedValues += value[0] === 0 ? 1 : 0;
      }
    }
    expect(paddedValues).toBeGreaterThan(0);
  });
});

describe("private key load diagnostics", () => {
  it("never quotes key material, even from a key pasted on one line", () => {
    const pem = generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }).toString().trim();
    const oneLine = pem.replace(/\n/gu, " ");
    const body = pem.split("\n").filter((line) => !line.startsWith("-----")).join("");

    const diagnostics = loadError(oneLine).diagnostics.join("; ");

    expect(diagnostics).toContain("format=pkcs8");
    expect(diagnostics).toContain("header=BEGIN followed by more text on the same line");
    expect(diagnostics).toContain("footer=END after other text on the same line");
    expect(diagnostics).toContain(`firstLineChars=${oneLine.length}`);
    for (let offset = 0; offset + 8 <= body.length; offset += 1) {
      expect(diagnostics).not.toContain(body.slice(offset, offset + 8));
    }
  });

  it("names a well-formed armor line only from the known labels", () => {
    const diagnostics = loadError("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----").diagnostics.join("; ");
    expect(diagnostics).toContain("header=BEGIN PRIVATE KEY");
    expect(diagnostics).toContain("footer=END PRIVATE KEY");

    const odd = loadError("-----BEGIN SECRET STUFF-----\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----").diagnostics.join("; ");
    expect(odd).toContain("header=BEGIN (unrecognized label)");
    expect(odd).toContain("format=unknown");
    expect(odd).not.toContain("SECRET");
  });

  it("does not echo names read from inside a broken OpenSSH key", () => {
    const secretLooking = "zZ9+/secret material=";
    const diagnostics = loadError(openSshEnvelope({ cipher: secretLooking, rounds: 16 }), "secret").diagnostics.join("; ");
    expect(diagnostics).toContain("openSshCipher=(unrecognized)");
    expect(diagnostics).not.toContain("secret material");
  });
});

function publicKeyLine(publicKey: KeyObject): string {
  const exported = exportSshPublicKeyBlob(publicKey);
  const keyType = new SshBinaryReader(exported.blob).utf8String();
  return `${keyType} ${exported.blob.toString("base64")}`;
}

function loadError(text: string, passphrase?: string): SshPrivateKeyLoadError {
  try {
    loadPrivateKey(text, passphrase);
  } catch (error) {
    expect(error).toBeInstanceOf(SshPrivateKeyLoadError);
    return error as SshPrivateKeyLoadError;
  }
  throw new Error("Expected the key to fail loading.");
}

/** An mpint must not carry a leading zero byte unless the next byte has its high bit set. */
function minimalMpint(value: Buffer): Buffer {
  expect(value.length).toBeGreaterThan(0);
  expect((value[0] & 0x80) === 0).toBe(true);
  if (value[0] === 0) {
    expect(value.length).toBeGreaterThan(1);
    expect(value[1] & 0x80).toBe(0x80);
    return value.subarray(1);
  }
  return value;
}

function fixedLength(value: Buffer, length: number): Buffer {
  return Buffer.concat([Buffer.alloc(length - value.length), value]);
}

function openSshEnvelope(options: { cipher: string; rounds: number }): string {
  const envelope = Buffer.concat([
    Buffer.from("openssh-key-v1\0", "utf8"),
    new SshBinaryWriter()
      .string(options.cipher)
      .string("bcrypt")
      .string(new SshBinaryWriter().string(Buffer.alloc(16, 3)).uint32(options.rounds).toBuffer())
      .uint32(1)
      .string(new SshBinaryWriter().string("ssh-ed25519").string(Buffer.alloc(32, 1)).toBuffer())
      .string(Buffer.alloc(64, 2))
      .toBuffer()
  ]);
  const base64 = envelope.toString("base64").match(/.{1,70}/gu)?.join("\n") ?? "";
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${base64}\n-----END OPENSSH PRIVATE KEY-----`;
}
