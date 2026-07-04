import { generateKeyPairSync, sign as nodeSign, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ChannelStateManager } from "../src/core/ssh/channel-state.js";
import {
  encodeEd25519PublicKeyBlob,
  encodeRsaPublicKeyBlob,
  encodeSshSignatureBlob,
  exportSshPublicKeyBlob,
  verifySshSignature
} from "../src/core/ssh/host-key.js";
import { deriveKey, deriveTransportKeys, transportKeyLengthsFor } from "../src/core/ssh/key-derivation.js";
import { bufferToBigInt } from "../src/core/ssh/kex-group14.js";
import { SshPacketProtector } from "../src/core/ssh/packet-codec.js";
import {
  SshPrivateKeyLoadError,
  assertSshPrivateKeyText,
  buildPublicKeyAuthSigningPayload,
  buildSignedPublicKeyAuthRequest,
  loadPrivateKey,
  signSshData
} from "../src/core/ssh/private-key.js";
import { SshBinaryReader, SshBinaryWriter } from "../src/core/ssh/binary.js";

describe("SSH transport key derivation and packet protection", () => {
  it("derives deterministic RFC-style keys", () => {
    const first = deriveKey(123456789n, Buffer.alloc(32, 1), Buffer.alloc(32, 2), "A", 40);
    const second = deriveKey(123456789n, Buffer.alloc(32, 1), Buffer.alloc(32, 2), "A", 40);
    const different = deriveKey(123456789n, Buffer.alloc(32, 1), Buffer.alloc(32, 2), "B", 40);

    expect(first).toHaveLength(40);
    expect(first).toEqual(second);
    expect(first).not.toEqual(different);
  });

  it("encrypts, authenticates, and decrypts packets", () => {
    const keys = deriveTransportKeys(987654321n, Buffer.alloc(32, 3), Buffer.alloc(32, 4), transportKeyLengthsFor("aes256-ctr", "hmac-sha2-256"));
    const sender = new SshPacketProtector({
      cipherName: "aes256-ctr",
      encryptionKey: keys.encryptionKeyClientToServer,
      initialIv: keys.initialIvClientToServer,
      macName: "hmac-sha2-256",
      macKey: keys.integrityKeyClientToServer
    });
    const receiver = new SshPacketProtector({
      cipherName: "aes256-ctr",
      encryptionKey: keys.encryptionKeyClientToServer,
      initialIv: keys.initialIvClientToServer,
      macName: "hmac-sha2-256",
      macKey: keys.integrityKeyClientToServer
    });

    const protectedPacket = sender.protect(Buffer.from("payload"));
    expect(receiver.unprotect(protectedPacket)).toEqual(Buffer.from("payload"));
    expect(sender.getSequenceNumber()).toBe(1);
    expect(receiver.getSequenceNumber()).toBe(1);
  });

  it("rejects tampered MACs", () => {
    const keys = deriveTransportKeys(987654321n, Buffer.alloc(32, 3), Buffer.alloc(32, 4), transportKeyLengthsFor("aes128-ctr", "hmac-sha2-256"));
    const config = {
      cipherName: "aes128-ctr" as const,
      encryptionKey: keys.encryptionKeyClientToServer,
      initialIv: keys.initialIvClientToServer,
      macName: "hmac-sha2-256" as const,
      macKey: keys.integrityKeyClientToServer
    };
    const sender = new SshPacketProtector(config);
    const receiver = new SshPacketProtector(config);
    const packet = sender.protect(Buffer.from("payload"));
    packet.mac[0] ^= 0xff;

    expect(() => receiver.unprotect(packet)).toThrow("MAC verification failed");
  });
});

describe("SSH host-key verification and private-key signing", () => {
  it("verifies RSA SHA-256 SSH signature blobs", () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = publicKey.export({ format: "jwk" });
    const modulus = bufferToBigInt(Buffer.from(jwk.n!, "base64url"));
    const exponent = bufferToBigInt(Buffer.from(jwk.e!, "base64url"));
    const hostKeyBlob = encodeRsaPublicKeyBlob(modulus, exponent);
    const data = Buffer.from("exchange-hash");
    const signature = nodeSign("sha256", data, privateKey);
    const signatureBlob = encodeSshSignatureBlob("rsa-sha2-256", signature);

    expect(verifySshSignature(hostKeyBlob, data, signatureBlob)).toBe(true);
    expect(verifySshSignature(hostKeyBlob, Buffer.from("wrong"), signatureBlob)).toBe(false);
  });

  it("verifies Ed25519 SSH signature blobs", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const spki = publicKey.export({ format: "der", type: "spki" });
    const rawPublicKey = spki.subarray(-32);
    const hostKeyBlob = encodeEd25519PublicKeyBlob(rawPublicKey);
    const data = Buffer.from("exchange-hash");
    const signatureBlob = encodeSshSignatureBlob("ssh-ed25519", nodeSign(null, data, privateKey));

    expect(verifySshSignature(hostKeyBlob, data, signatureBlob)).toBe(true);
  });

  it("loads private keys and signs public-key auth payloads", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const loaded = loadPrivateKey(pem);
    const payload = buildPublicKeyAuthSigningPayload({
      sessionId: Buffer.alloc(32, 9),
      username: "alice",
      service: "ssh-connection",
      publicKeyAlgorithm: "ssh-ed25519",
      publicKeyBlob: encodeEd25519PublicKeyBlob(loaded.publicKey.export({ format: "der", type: "spki" }).subarray(-32))
    });
    const signatureBlob = signSshData(loaded.privateKey, "ssh-ed25519", payload);

    expect(signatureBlob.length).toBeGreaterThan(64);
  });

  it("normalizes escaped newlines before loading private keys", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const escaped = pem.trim().replace(/\n/gu, "\\n");

    const loaded = loadPrivateKey(escaped);

    expect(loaded.privateKey.type).toBe("private");
  });

  it("loads unencrypted OpenSSH Ed25519 private keys", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const openSshPem = encodeOpenSshEd25519PrivateKey(privateKey);

    const loaded = loadPrivateKey(openSshPem);
    const payload = buildPublicKeyAuthSigningPayload({
      sessionId: Buffer.alloc(32, 8),
      username: "alice",
      service: "ssh-connection",
      publicKeyAlgorithm: "ssh-ed25519",
      publicKeyBlob: encodeEd25519PublicKeyBlob(loaded.publicKey.export({ format: "der", type: "spki" }).subarray(-32))
    });
    const signatureBlob = signSshData(loaded.privateKey, "ssh-ed25519", payload);

    expect(signatureBlob.length).toBeGreaterThan(64);
  });

  it("reports safe private-key parse diagnostics", () => {
    const malformed = "-----BEGIN OPENSSH PRIVATE KEY-----\\nnot-a-key\\n-----END OPENSSH PRIVATE KEY-----";

    expect(() => loadPrivateKey(malformed)).toThrow(SshPrivateKeyLoadError);

    try {
      loadPrivateKey(malformed);
    } catch (error) {
      expect(error).toBeInstanceOf(SshPrivateKeyLoadError);
      const diagnostics = (error as SshPrivateKeyLoadError).diagnostics.join("; ");
      expect(diagnostics).toContain("format=openssh");
      expect(diagnostics).toContain("containsEscapedNewlines=true");
      expect(diagnostics).toContain("normalizedLineCount=3");
      expect(diagnostics).toContain("parserError=");
      expect(diagnostics).not.toContain("not-a-key");
    }
  });

  it("reports unsupported encrypted OpenSSH private keys explicitly", () => {
    const encryptedOpenSsh = encodeOpenSshEnvelope(
      new SshBinaryWriter()
        .string("aes256-ctr")
        .string("bcrypt")
        .string(new SshBinaryWriter().string(Buffer.alloc(16, 1)).uint32(16).toBuffer())
        .uint32(1)
        .string(Buffer.alloc(0))
        .string(Buffer.alloc(16))
        .toBuffer()
    );

    expect(() => loadPrivateKey(encryptedOpenSsh, "secret")).toThrow(/Encrypted OpenSSH private keys are not supported yet/);

    try {
      loadPrivateKey(encryptedOpenSsh, "secret");
    } catch (error) {
      expect(error).toBeInstanceOf(SshPrivateKeyLoadError);
      const diagnostics = (error as SshPrivateKeyLoadError).diagnostics.join("; ");
      expect(diagnostics).toContain("openSshCipher=aes256-ctr");
      expect(diagnostics).toContain("openSshKdf=bcrypt");
      expect(diagnostics).toContain("passphraseProvided=true");
    }
  });

  it("rejects non-private-key text with actionable errors", () => {
    expect(() => assertSshPrivateKeyText("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample user@host")).toThrow(/public key/i);
    expect(() => loadPrivateKey("C:\\Users\\Administrator\\.ssh\\id_ed25519")).toThrow(/Paste the key contents/i);
  });

  it("exports SSH public key blobs and builds signed auth requests", () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const exported = exportSshPublicKeyBlob(publicKey, "rsa-sha2-256");
    expect(exported.algorithm).toBe("rsa-sha2-256");
    expect(new SshBinaryReader(exported.blob).utf8String()).toBe("ssh-rsa");

    const request = buildSignedPublicKeyAuthRequest({
      sessionId: Buffer.alloc(32, 7),
      username: "alice",
      service: "ssh-connection",
      privateKey,
      publicKey,
      algorithm: "rsa-sha2-256"
    });
    const reader = new SshBinaryReader(request);
    expect(reader.byte()).toBe(50);
    expect(reader.utf8String()).toBe("alice");
    expect(reader.utf8String()).toBe("ssh-connection");
    expect(reader.utf8String()).toBe("publickey");
    expect(reader.boolean()).toBe(true);
    expect(reader.utf8String()).toBe("rsa-sha2-256");
    const publicKeyBlob = reader.string();
    expect(publicKeyBlob).toEqual(exported.blob);
    expect(new SshBinaryReader(publicKeyBlob).utf8String()).toBe("ssh-rsa");
    expect(reader.string().length).toBeGreaterThan(128);
  });
});

describe("SSH channel state manager", () => {
  it("tracks channel open, window consumption, EOF, and close", () => {
    const manager = new ChannelStateManager();
    const opening = manager.open("direct-tcpip");
    expect(opening.localId).toBe(0);
    expect(opening.lifecycle).toBe("opening");

    const open = manager.confirmOpen(opening.localId, 42, 1024, 32768);
    expect(open.remoteId).toBe(42);
    expect(open.lifecycle).toBe("open");

    expect(manager.consumeRemoteWindow(open.localId, 100).remoteWindow).toBe(924);
    expect(() => manager.consumeRemoteWindow(open.localId, 925)).toThrow("remote window exhausted");
    expect(manager.markEofSent(open.localId).lifecycle).toBe("eof-sent");
    expect(manager.markEofReceived(open.localId).lifecycle).toBe("closed");
    expect(manager.close(open.localId).lifecycle).toBe("closed");
    expect(manager.get(open.localId)).toBeUndefined();
  });

  it("allows local channel writes after receiving remote EOF", () => {
    const manager = new ChannelStateManager();
    const opening = manager.open("direct-tcpip");
    const open = manager.confirmOpen(opening.localId, 42, 1024, 32768);

    expect(manager.markEofReceived(open.localId).lifecycle).toBe("eof-received");
    expect(manager.consumeRemoteWindow(open.localId, 100).remoteWindow).toBe(924);
    expect(manager.markEofSent(open.localId).lifecycle).toBe("closed");
    expect(manager.close(open.localId).lifecycle).toBe("closed");
    expect(manager.get(open.localId)).toBeUndefined();
  });
});

function encodeOpenSshEd25519PrivateKey(privateKey: KeyObject): string {
  const jwk = privateKey.export({ format: "jwk" });
  const publicKey = Buffer.from(jwk.x!, "base64url");
  const seed = Buffer.from(jwk.d!, "base64url");
  const publicBlob = new SshBinaryWriter().string("ssh-ed25519").string(publicKey).toBuffer();
  const privateBody = new SshBinaryWriter()
    .uint32(0x12345678)
    .uint32(0x12345678)
    .string("ssh-ed25519")
    .string(publicKey)
    .string(Buffer.concat([seed, publicKey]))
    .string("vitest")
    .toBuffer();
  const paddingLength = 8 - (privateBody.length % 8 || 8);
  const padding = Buffer.alloc(paddingLength);
  for (let index = 0; index < padding.length; index += 1) {
    padding[index] = index + 1;
  }
  const privateBlock = Buffer.concat([privateBody, padding]);
  const envelope = Buffer.concat([
    Buffer.from("openssh-key-v1\0", "utf8"),
    new SshBinaryWriter()
      .string("none")
      .string("none")
      .string(Buffer.alloc(0))
      .uint32(1)
      .string(publicBlob)
      .string(privateBlock)
      .toBuffer()
  ]);
  return encodeOpenSshEnvelope(envelope.subarray(Buffer.from("openssh-key-v1\0", "utf8").length));
}

function encodeOpenSshEnvelope(payload: Buffer): string {
  const envelope = Buffer.concat([Buffer.from("openssh-key-v1\0", "utf8"), payload]);
  const base64 = envelope.toString("base64").match(/.{1,70}/gu)?.join("\n") ?? "";
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${base64}\n-----END OPENSSH PRIVATE KEY-----`;
}
