import { diffieHellman, generateKeyPairSync, getDiffieHellman } from "node:crypto";
import { describe, expect, it } from "vitest";
import { negotiateAlgorithms } from "../src/core/ssh/algorithms.js";
import {
  encodePasswordAuthRequest,
  encodePublicKeyAuthProbe,
  encodeServiceRequest,
  SSH_MSG_SERVICE_REQUEST,
  SSH_MSG_USERAUTH_REQUEST
} from "../src/core/ssh/auth-messages.js";
import { SshBinaryReader } from "../src/core/ssh/binary.js";
import {
  encodeChannelData,
  encodeDirectTcpIpChannelOpen,
  encodePtyRequest,
  encodeSessionChannelOpen,
  encodeShellRequest,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_OPEN,
  SSH_MSG_CHANNEL_REQUEST
} from "../src/core/ssh/channel-messages.js";
import { sha256Fingerprint } from "../src/core/ssh/fingerprint.js";
import {
  bigIntToBuffer,
  bufferToBigInt,
  computeGroup14Sha256ExchangeHash,
  createGroup14Sha256ClientExchange,
  decodeKexDhReply,
  encodeKexDhInit,
  SSH_MSG_KEXDH_INIT,
  SSH_MSG_KEXDH_REPLY
} from "../src/core/ssh/kex-group14.js";
import { createCurve25519ClientExchange, exportRawX25519PublicKey, importRawX25519PublicKey } from "../src/core/ssh/kex-curve25519.js";
import { createDefaultKexInit, encodeKexInit } from "../src/core/ssh/messages.js";
import { SshBinaryWriter } from "../src/core/ssh/binary.js";

describe("SSH algorithm negotiation", () => {
  it("chooses the first client-preferred algorithm also offered by the server", () => {
    const client = createDefaultKexInit();
    const server = {
      ...createDefaultKexInit(),
      kexAlgorithms: ["diffie-hellman-group14-sha256", "curve25519-sha256"],
      encryptionAlgorithmsClientToServer: ["aes128-ctr"],
      encryptionAlgorithmsServerToClient: ["aes128-ctr"]
    };

    const negotiated = negotiateAlgorithms(client, server);
    expect(negotiated.kexAlgorithm).toBe("curve25519-sha256");
    expect(negotiated.encryptionClientToServer).toBe("aes128-ctr");
    expect(client.encryptionAlgorithmsClientToServer[0]).toBe("aes128-ctr");
  });

  it("computes SHA256 host key fingerprints", () => {
    expect(sha256Fingerprint(Buffer.from("host-key"))).toMatch(/^SHA256:[A-Za-z0-9+/]+$/u);
  });
});

describe("SSH group14 SHA-256 key exchange primitives", () => {
  it("computes the same shared secret as a peer Diffie-Hellman exchange", () => {
    const client = createGroup14Sha256ClientExchange();
    const serverDh = getDiffieHellman("modp14");
    serverDh.generateKeys();

    const serverPublic = bufferToBigInt(serverDh.getPublicKey());
    const clientSecret = client.computeSharedSecret(serverPublic);
    const serverSecret = bufferToBigInt(serverDh.computeSecret(bigIntToBuffer(client.exchangeValue)));

    expect(clientSecret).toBe(serverSecret);
  });

  it("encodes KEXDH_INIT and decodes KEXDH_REPLY", () => {
    const init = new SshBinaryReader(encodeKexDhInit(123n));
    expect(init.byte()).toBe(SSH_MSG_KEXDH_INIT);
    expect(init.mpint()).toBe(123n);

    const replyPayload = new SshBinaryWriter()
      .byte(SSH_MSG_KEXDH_REPLY)
      .string(Buffer.from("host-key"))
      .mpint(456n)
      .string(Buffer.from("signature"))
      .toBuffer();
    expect(decodeKexDhReply(replyPayload)).toEqual({
      hostKey: Buffer.from("host-key"),
      serverExchangeValue: 456n,
      signature: Buffer.from("signature")
    });
  });

  it("computes a stable exchange hash", () => {
    const clientKex = encodeKexInit(createDefaultKexInit());
    const serverKex = encodeKexInit(createDefaultKexInit());
    const hashA = computeGroup14Sha256ExchangeHash({
      clientVersion: "SSH-2.0-client\r\n",
      serverVersion: "SSH-2.0-server\r\n",
      clientKexInitPayload: clientKex,
      serverKexInitPayload: serverKex,
      serverHostKey: Buffer.from("host-key"),
      clientExchangeValue: 123n,
      serverExchangeValue: 456n,
      sharedSecret: 789n
    });
    const hashB = computeGroup14Sha256ExchangeHash({
      clientVersion: "SSH-2.0-client",
      serverVersion: "SSH-2.0-server",
      clientKexInitPayload: clientKex,
      serverKexInitPayload: serverKex,
      serverHostKey: Buffer.from("host-key"),
      clientExchangeValue: 123n,
      serverExchangeValue: 456n,
      sharedSecret: 789n
    });

    expect(hashA).toHaveLength(32);
    expect(hashA).toEqual(hashB);
  });
});

describe("SSH curve25519 SHA-256 key exchange primitives", () => {
  it("computes the same X25519 shared secret as a peer exchange", () => {
    const client = createCurve25519ClientExchange();
    const server = generateKeyPairSync("x25519");
    const serverPublic = exportRawX25519PublicKey(server.publicKey);

    const clientSecret = client.computeSharedSecret(serverPublic);
    const serverSecret = bufferToBigInt(
      diffieHellman({
        privateKey: server.privateKey,
        publicKey: importRawX25519PublicKey(client.publicKey)
      })
    );

    expect(clientSecret).toBe(serverSecret);
  });
});

describe("SSH auth and channel message encoders", () => {
  it("encodes service and password auth requests", () => {
    const service = new SshBinaryReader(encodeServiceRequest("ssh-userauth"));
    expect(service.byte()).toBe(SSH_MSG_SERVICE_REQUEST);
    expect(service.utf8String()).toBe("ssh-userauth");

    const auth = new SshBinaryReader(encodePasswordAuthRequest({ username: "alice", password: "secret" }));
    expect(auth.byte()).toBe(SSH_MSG_USERAUTH_REQUEST);
    expect(auth.utf8String()).toBe("alice");
    expect(auth.utf8String()).toBe("ssh-connection");
    expect(auth.utf8String()).toBe("password");
    expect(auth.boolean()).toBe(false);
    expect(auth.utf8String()).toBe("secret");
  });

  it("encodes public key auth probes without signatures", () => {
    const auth = new SshBinaryReader(
      encodePublicKeyAuthProbe({ username: "alice", publicKeyAlgorithm: "ssh-ed25519", publicKeyBlob: Buffer.from("pub") })
    );

    expect(auth.byte()).toBe(SSH_MSG_USERAUTH_REQUEST);
    expect(auth.utf8String()).toBe("alice");
    expect(auth.utf8String()).toBe("ssh-connection");
    expect(auth.utf8String()).toBe("publickey");
    expect(auth.boolean()).toBe(false);
    expect(auth.utf8String()).toBe("ssh-ed25519");
    expect(auth.string()).toEqual(Buffer.from("pub"));
  });

  it("encodes session and direct-tcpip channel opens", () => {
    const session = new SshBinaryReader(encodeSessionChannelOpen({ senderChannel: 7 }));
    expect(session.byte()).toBe(SSH_MSG_CHANNEL_OPEN);
    expect(session.utf8String()).toBe("session");
    expect(session.uint32()).toBe(7);

    const direct = new SshBinaryReader(
      encodeDirectTcpIpChannelOpen({
        senderChannel: 8,
        hostToConnect: "youtube.com",
        portToConnect: 443,
        originatorIpAddress: "127.0.0.1",
        originatorPort: 55000
      })
    );
    expect(direct.byte()).toBe(SSH_MSG_CHANNEL_OPEN);
    expect(direct.utf8String()).toBe("direct-tcpip");
    expect(direct.uint32()).toBe(8);
    direct.uint32();
    direct.uint32();
    expect(direct.utf8String()).toBe("youtube.com");
    expect(direct.uint32()).toBe(443);
  });

  it("encodes terminal shell requests and channel data", () => {
    const pty = new SshBinaryReader(encodePtyRequest({ recipientChannel: 1, columns: 120, rows: 32 }));
    expect(pty.byte()).toBe(SSH_MSG_CHANNEL_REQUEST);
    expect(pty.uint32()).toBe(1);
    expect(pty.utf8String()).toBe("pty-req");

    const shell = new SshBinaryReader(encodeShellRequest({ recipientChannel: 1 }));
    expect(shell.byte()).toBe(SSH_MSG_CHANNEL_REQUEST);
    expect(shell.uint32()).toBe(1);
    expect(shell.utf8String()).toBe("shell");

    const data = new SshBinaryReader(encodeChannelData({ recipientChannel: 1, data: Buffer.from("ls\n") }));
    expect(data.byte()).toBe(SSH_MSG_CHANNEL_DATA);
    expect(data.uint32()).toBe(1);
    expect(data.string()).toEqual(Buffer.from("ls\n"));
  });
});
