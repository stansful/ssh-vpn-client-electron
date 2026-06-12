import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
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
import { buildPublicKeyAuthSigningPayload, buildSignedPublicKeyAuthRequest, loadPrivateKey, signSshData } from "../src/core/ssh/private-key.js";
import { SshBinaryReader } from "../src/core/ssh/binary.js";

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
});
