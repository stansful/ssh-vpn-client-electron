import { diffieHellman, generateKeyPairSync, sign as nodeSign, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import { SshBinaryReader, SshBinaryWriter } from "../src/core/ssh/binary.js";
import {
  SSH_MSG_CHANNEL_CLOSE,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_EOF,
  SSH_MSG_CHANNEL_EXTENDED_DATA,
  SSH_MSG_CHANNEL_FAILURE,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_CHANNEL_SUCCESS,
  SSH_MSG_CHANNEL_WINDOW_ADJUST,
  SSH_MSG_NEWKEYS,
  SSH_MSG_SERVICE_ACCEPT,
  SSH_MSG_USERAUTH_FAILURE,
  SSH_MSG_USERAUTH_SUCCESS
} from "../src/core/ssh/connection-messages.js";
import {
  SSH_MSG_CHANNEL_OPEN,
  SSH_MSG_CHANNEL_OPEN_FAILURE,
  SSH_MSG_CHANNEL_REQUEST
} from "../src/core/ssh/channel-messages.js";
import { deriveTransportKeys, transportKeyLengthsFor } from "../src/core/ssh/key-derivation.js";
import { SshPacketProtector } from "../src/core/ssh/packet-codec.js";
import { SshSessionStateMachine } from "../src/core/ssh/session-state.js";
import { createDefaultKexInit, encodeKexInit } from "../src/core/ssh/messages.js";
import {
  computeCurve25519Sha256ExchangeHash,
  exportRawX25519PublicKey,
  importRawX25519PublicKey
} from "../src/core/ssh/kex-curve25519.js";
import { bufferToBigInt } from "../src/core/ssh/kex-group14.js";
import { encodeEd25519PublicKeyBlob, encodeSshSignatureBlob } from "../src/core/ssh/host-key.js";
import { sha256Fingerprint } from "../src/core/ssh/fingerprint.js";

describe("SSH packet codec stream state", () => {
  it("round-trips multiple packets without resetting CTR IV", () => {
    const keys = deriveTransportKeys(777n, Buffer.alloc(32, 1), Buffer.alloc(32, 2), transportKeyLengthsFor("aes256-ctr", "hmac-sha2-256"));
    const config = {
      cipherName: "aes256-ctr" as const,
      encryptionKey: keys.encryptionKeyClientToServer,
      initialIv: keys.initialIvClientToServer,
      macName: "hmac-sha2-256" as const,
      macKey: keys.integrityKeyClientToServer
    };
    const sender = new SshPacketProtector(config);
    const receiver = new SshPacketProtector(config);

    const first = sender.protect(Buffer.from("first"));
    const second = sender.protect(Buffer.from("second"));

    expect(receiver.unprotect(first)).toEqual(Buffer.from("first"));
    expect(receiver.unprotect(second)).toEqual(Buffer.from("second"));
  });
});

describe("SSH session state machine", () => {
  it("starts KEX and negotiates preferred curve25519 algorithm", () => {
    const session = new SshSessionStateMachine({
      clientVersion: "SSH-2.0-client",
      serverVersion: "SSH-2.0-server"
    });
    const started = session.startKex();
    expect(started.clientKexInitPayload.length).toBeGreaterThan(0);
    const result = session.receiveServerKexInit(
      encodeKexInit({
        ...createDefaultKexInit(),
        kexAlgorithms: ["curve25519-sha256", "diffie-hellman-group14-sha256"]
      })
    );

    expect(result.negotiated.kexAlgorithm).toBe("curve25519-sha256");
    expect(new SshBinaryReader(result.kexDhInitPayload).byte()).toBe(30);
    expect(result.ignoreNextServerKexPacket).toBe(false);
  });

  it("marks a speculative server KEX packet for discard when the server guessed the wrong algorithm", () => {
    const session = new SshSessionStateMachine({
      clientVersion: "SSH-2.0-client",
      serverVersion: "SSH-2.0-server"
    });
    session.startKex();

    const result = session.receiveServerKexInit(
      encodeKexInit({
        ...createDefaultKexInit(),
        kexAlgorithms: ["diffie-hellman-group14-sha256", "curve25519-sha256"],
        firstKexPacketFollows: true
      })
    );

    expect(result.negotiated.kexAlgorithm).toBe("curve25519-sha256");
    expect(result.ignoreNextServerKexPacket).toBe(true);
  });

  it("falls back to group14 when curve25519 is unavailable", () => {
    const session = new SshSessionStateMachine({
      clientVersion: "SSH-2.0-client",
      serverVersion: "SSH-2.0-server"
    });
    session.startKex();
    const result = session.receiveServerKexInit(
      encodeKexInit({
        ...createDefaultKexInit(),
        kexAlgorithms: ["diffie-hellman-group14-sha256"]
      })
    );

    expect(result.negotiated.kexAlgorithm).toBe("diffie-hellman-group14-sha256");
  });

  it("accepts a signed server host key without requiring a pinned fingerprint", () => {
    const hostIdentity = createEd25519HostIdentity();
    const session = new SshSessionStateMachine({
      clientVersion: "SSH-2.0-client",
      serverVersion: "SSH-2.0-server"
    });
    const exchange = prepareCurveExchange(session, hostIdentity);

    const result = session.completeKex(exchange.replyPayload);

    expect(result.serverHostKeyFingerprint).toBe(hostIdentity.fingerprint);
    expect(session.getPhase()).toBe("newkeys-sent");
  });

  it("still enforces an explicitly configured fingerprint pin", () => {
    const hostIdentity = createEd25519HostIdentity();
    const session = new SshSessionStateMachine({
      clientVersion: "SSH-2.0-client",
      serverVersion: "SSH-2.0-server",
      expectedServerFingerprint: `SHA256:${"A".repeat(43)}`
    });
    const exchange = prepareCurveExchange(session, hostIdentity);

    expect(() => session.completeKex(exchange.replyPayload)).toThrow("SSH server fingerprint mismatch");
    expect(session.getPhase()).toBe("kexdh-sent");
  });

  it("preserves the first session id and authenticated phase across runtime rekey", () => {
    const hostIdentity = createEd25519HostIdentity();
    const session = new SshSessionStateMachine({
      clientVersion: "SSH-2.0-client",
      serverVersion: "SSH-2.0-server"
    });
    const firstExchange = prepareCurveExchange(session, hostIdentity);
    const first = session.completeKex(firstExchange.replyPayload);
    session.receiveNewKeys(Buffer.from([SSH_MSG_NEWKEYS]));
    expect(session.getPhase()).toBe("encrypted");

    forcePhase(session, "authenticated");
    const secondExchange = prepareCurveExchange(session, hostIdentity);
    const second = session.completeKex(secondExchange.replyPayload);
    expect(second.exchangeHash).not.toEqual(first.exchangeHash);
    expect(second.sessionId).toEqual(first.sessionId);
    session.receiveNewKeys(Buffer.from([SSH_MSG_NEWKEYS]));
    expect(session.getPhase()).toBe("authenticated");
  });

  it("rejects a host-key change during rekey even without a configured pin", () => {
    const firstHost = createEd25519HostIdentity();
    const replacementHost = createEd25519HostIdentity();
    const session = new SshSessionStateMachine({
      clientVersion: "SSH-2.0-client",
      serverVersion: "SSH-2.0-server"
    });
    const firstExchange = prepareCurveExchange(session, firstHost);
    session.completeKex(firstExchange.replyPayload);
    session.receiveNewKeys(Buffer.from([SSH_MSG_NEWKEYS]));
    forcePhase(session, "authenticated");

    const replacementExchange = prepareCurveExchange(session, replacementHost);
    expect(() => session.completeKex(replacementExchange.replyPayload)).toThrow("SSH server host key changed during rekey");
  });

  it("moves through NEWKEYS, service accept, and password auth success", () => {
    const session = new SshSessionStateMachine({
      clientVersion: "SSH-2.0-client",
      serverVersion: "SSH-2.0-server"
    });

    expect(session.getPhase()).toBe("idle");
    session.startKex();
    expect(session.getPhase()).toBe("kexinit-sent");

    expect(() => session.receiveNewKeys(Buffer.from([SSH_MSG_NEWKEYS]))).toThrow("Invalid SSH session phase");
    forcePhase(session, "newkeys-sent");
    session.receiveNewKeys(Buffer.from([SSH_MSG_NEWKEYS]));
    expect(session.getPhase()).toBe("encrypted");

    const serviceRequest = session.requestUserAuthService();
    expect(new SshBinaryReader(serviceRequest).byte()).toBe(5);
    expect(session.receiveServiceAccept(new SshBinaryWriter().byte(SSH_MSG_SERVICE_ACCEPT).string("ssh-userauth").toBuffer())).toBe("ssh-userauth");

    const passwordAuth = session.buildPasswordAuth("alice", "secret");
    const authReader = new SshBinaryReader(passwordAuth);
    authReader.byte();
    expect(authReader.utf8String()).toBe("alice");
    expect(session.receiveAuthResult(Buffer.from([SSH_MSG_USERAUTH_SUCCESS]))).toBe("success");
    expect(session.getPhase()).toBe("authenticated");
  });

  it("decodes auth failures without leaving authenticating phase", () => {
    const session = authenticatedReadySession("authenticating");
    const failure = session.receiveAuthResult(
      new SshBinaryWriter().byte(SSH_MSG_USERAUTH_FAILURE).nameList(["publickey", "password"]).boolean(false).toBuffer()
    );

    expect(failure).toEqual({ methodsThatCanContinue: ["publickey", "password"], partialSuccess: false });
    expect(session.getPhase()).toBe("authenticating");
  });

  it("tracks direct-tcpip channel confirmation, data windows, and close", () => {
    const session = authenticatedReadySession("authenticated");
    const opened = session.openDirectTcpIpChannel({
      hostToConnect: "youtube.com",
      portToConnect: 443,
      originatorIpAddress: "127.0.0.1",
      originatorPort: 50000
    });
    expect(opened.channel.localId).toBe(0);

    const event = session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        .uint32(opened.channel.localId)
        .uint32(44)
        .uint32(8)
        .uint32(32768)
        .toBuffer()
    );
    expect(event).toEqual({ type: "open-confirmed", localChannel: 0 });
    expect(session.getChannel(0)?.remoteId).toBe(44);

    const payload = session.buildChannelData(0, Buffer.from("hello"));
    const dataReader = new SshBinaryReader(payload);
    expect(dataReader.byte()).toBe(SSH_MSG_CHANNEL_DATA);
    expect(dataReader.uint32()).toBe(44);
    expect(session.getChannel(0)?.remoteWindow).toBe(3);

    session.receiveChannelMessage(new SshBinaryWriter().byte(SSH_MSG_CHANNEL_WINDOW_ADJUST).uint32(0).uint32(10).toBuffer());
    expect(session.getChannel(0)?.remoteWindow).toBe(13);

    const close = session.receiveChannelMessage(new SshBinaryWriter().byte(SSH_MSG_CHANNEL_CLOSE).uint32(0).toBuffer());
    expect(close).toMatchObject({ type: "close", localChannel: 0 });
    const reciprocalClose = new SshBinaryReader(close.responsePayload!);
    expect(reciprocalClose.byte()).toBe(SSH_MSG_CHANNEL_CLOSE);
    expect(reciprocalClose.uint32()).toBe(44);
    expect(session.getChannel(0)).toBeUndefined();
    expect(session.receiveChannelMessage(new SshBinaryWriter().byte(SSH_MSG_CHANNEL_CLOSE).uint32(0).toBuffer())).toMatchObject({
      type: "ignored",
      localChannel: 0
    });
  });

  it("chunks outbound channel data by remote packet size and remote window", () => {
    const session = authenticatedReadySession("authenticated");
    const opened = session.openDirectTcpIpChannel({
      hostToConnect: "download.example.com",
      portToConnect: 443,
      originatorIpAddress: "127.0.0.1",
      originatorPort: 50000
    });
    session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        .uint32(opened.channel.localId)
        .uint32(12)
        .uint32(10)
        .uint32(4)
        .toBuffer()
    );

    const result = session.buildChannelDataFrames(opened.channel.localId, Buffer.from("abcdefghijklmnop"));
    expect(result.bytesWritten).toBe(10);
    expect(result.payloads).toHaveLength(3);
    const frameSizes = result.payloads.map((payload) => {
      const reader = new SshBinaryReader(payload);
      expect(reader.byte()).toBe(SSH_MSG_CHANNEL_DATA);
      expect(reader.uint32()).toBe(12);
      return reader.string().length;
    });
    expect(frameSizes).toEqual([4, 4, 2]);
    expect(session.getChannel(opened.channel.localId)?.remoteWindow).toBe(0);
  });

  it("rejects single outbound channel data frames larger than the remote packet size", () => {
    const session = authenticatedReadySession("authenticated");
    const opened = session.openDirectTcpIpChannel({
      hostToConnect: "download.example.com",
      portToConnect: 443,
      originatorIpAddress: "127.0.0.1",
      originatorPort: 50000
    });
    session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        .uint32(opened.channel.localId)
        .uint32(12)
        .uint32(10)
        .uint32(4)
        .toBuffer()
    );

    expect(() => session.buildChannelData(opened.channel.localId, Buffer.from("abcde"))).toThrow("maximum packet size exceeded");
  });

  it("treats remote channel id zero as a valid confirmed channel", () => {
    const session = authenticatedReadySession("authenticated");
    const opened = session.openDirectTcpIpChannel({
      hostToConnect: "example.com",
      portToConnect: 443,
      originatorIpAddress: "127.0.0.1",
      originatorPort: 50000
    });
    session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        .uint32(opened.channel.localId)
        .uint32(0)
        .uint32(1024)
        .uint32(32768)
        .toBuffer()
    );

    const payload = session.buildChannelData(opened.channel.localId, Buffer.from("ok"));
    const reader = new SshBinaryReader(payload);
    reader.byte();
    expect(reader.uint32()).toBe(0);
  });

  it("sends window adjust only after inbound data is acknowledged by the downstream sink", () => {
    const session = authenticatedReadySession("authenticated");
    const opened = session.openDirectTcpIpChannel({
      hostToConnect: "video-edge.example.com",
      portToConnect: 443,
      originatorIpAddress: "127.0.0.1",
      originatorPort: 50000
    });
    session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        .uint32(opened.channel.localId)
        .uint32(7)
        .uint32(1024 * 1024)
        .uint32(65536)
        .toBuffer()
    );

    const chunk = Buffer.alloc(64 * 1024);
    let adjustPayload: Buffer | undefined;
    for (let index = 0; index < 128; index += 1) {
      const event = session.receiveChannelMessage(
        new SshBinaryWriter().byte(SSH_MSG_CHANNEL_DATA).uint32(opened.channel.localId).string(chunk).toBuffer()
      );
      expect(event.type).toBe("data");
      expect(event.windowAdjustPayload).toBeUndefined();
      adjustPayload = session.acknowledgeChannelData(opened.channel.localId, chunk.length) ?? adjustPayload;
    }

    expect(adjustPayload).toBeDefined();
    const adjust = new SshBinaryReader(adjustPayload!);
    expect(adjust.byte()).toBe(SSH_MSG_CHANNEL_WINDOW_ADJUST);
    expect(adjust.uint32()).toBe(7);
    expect(adjust.uint32()).toBe(8 * 1024 * 1024);
    expect(session.getChannel(opened.channel.localId)?.localWindow).toBe(16 * 1024 * 1024);
  });

  it("rejects inbound channel data frames above the advertised local maximum", () => {
    const session = authenticatedReadySession("authenticated");
    const opened = session.openDirectTcpIpChannel({
      hostToConnect: "video-edge.example.com",
      portToConnect: 443,
      originatorIpAddress: "127.0.0.1",
      originatorPort: 50000
    });
    session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        .uint32(opened.channel.localId)
        .uint32(7)
        .uint32(1024 * 1024)
        .uint32(65536)
        .toBuffer()
    );

    expect(() => session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_DATA)
        .uint32(opened.channel.localId)
        .string(Buffer.alloc(65537))
        .toBuffer()
    )).toThrow("inbound maximum packet size exceeded");
  });

  it("ignores late channel messages for locally closed direct-tcpip checks", () => {
    const session = authenticatedReadySession("authenticated");
    const opened = session.openDirectTcpIpChannel({
      hostToConnect: "example.com",
      portToConnect: 443,
      originatorIpAddress: "127.0.0.1",
      originatorPort: 50000
    });
    session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        .uint32(opened.channel.localId)
        .uint32(7)
        .uint32(1024 * 1024)
        .uint32(65536)
        .toBuffer()
    );

    session.buildChannelClose(opened.channel.localId);
    expect(session.getChannel(opened.channel.localId)).toBeUndefined();

    const lateMessages = [
      new SshBinaryWriter().byte(SSH_MSG_CHANNEL_EOF).uint32(opened.channel.localId).toBuffer(),
      new SshBinaryWriter().byte(SSH_MSG_CHANNEL_CLOSE).uint32(opened.channel.localId).toBuffer(),
      new SshBinaryWriter().byte(SSH_MSG_CHANNEL_DATA).uint32(opened.channel.localId).string(Buffer.from("late")).toBuffer(),
      new SshBinaryWriter().byte(SSH_MSG_CHANNEL_WINDOW_ADJUST).uint32(opened.channel.localId).uint32(1024).toBuffer(),
      new SshBinaryWriter().byte(SSH_MSG_CHANNEL_SUCCESS).uint32(opened.channel.localId).toBuffer(),
      new SshBinaryWriter().byte(SSH_MSG_CHANNEL_FAILURE).uint32(opened.channel.localId).toBuffer()
    ];

    for (const payload of lateMessages) {
      expect(session.receiveChannelMessage(payload)).toMatchObject({
        type: "ignored",
        localChannel: opened.channel.localId
      });
    }
  });

  it("closes a late channel confirmation after a timed-out local open was abandoned", () => {
    const session = authenticatedReadySession("authenticated");
    const opened = session.openDirectTcpIpChannel({
      hostToConnect: "slow.example.com",
      portToConnect: 443,
      originatorIpAddress: "127.0.0.1",
      originatorPort: 50000
    });
    expect(session.abortChannel(opened.channel.localId)).toBeUndefined();

    const late = session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        .uint32(opened.channel.localId)
        .uint32(77)
        .uint32(1024)
        .uint32(32768)
        .toBuffer()
    );

    expect(late).toMatchObject({ type: "ignored", localChannel: opened.channel.localId });
    const close = new SshBinaryReader(late.responsePayload!);
    expect(close.byte()).toBe(SSH_MSG_CHANNEL_CLOSE);
    expect(close.uint32()).toBe(77);
  });

  it("accounts for extended channel data and rejects unsupported inbound requests with replies", () => {
    const session = authenticatedReadySession("authenticated");
    const opened = session.openSessionChannel();
    session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        .uint32(opened.channel.localId)
        .uint32(44)
        .uint32(1024)
        .uint32(65536)
        .toBuffer()
    );

    const extended = session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_EXTENDED_DATA)
        .uint32(opened.channel.localId)
        .uint32(1)
        .string(Buffer.from("stderr"))
        .toBuffer()
    );
    expect(extended).toMatchObject({
      type: "extended-data",
      localChannel: opened.channel.localId,
      dataTypeCode: 1,
      data: Buffer.from("stderr")
    });
    expect(session.getChannel(opened.channel.localId)?.localWindow).toBe(16 * 1024 * 1024 - 6);

    const request = session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_REQUEST)
        .uint32(opened.channel.localId)
        .string("custom@example.com")
        .boolean(true)
        .string("payload")
        .toBuffer()
    );
    const failure = new SshBinaryReader(request.responsePayload!);
    expect(failure.byte()).toBe(SSH_MSG_CHANNEL_FAILURE);
    expect(failure.uint32()).toBe(44);

    const noReply = session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_REQUEST)
        .uint32(opened.channel.localId)
        .string("exit-status")
        .boolean(false)
        .uint32(0)
        .toBuffer()
    );
    expect(noReply.responsePayload).toBeUndefined();
  });

  it("rejects unsupported server-initiated channels instead of leaving them unanswered", () => {
    const session = authenticatedReadySession("authenticated");
    const event = session.receiveChannelMessage(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_OPEN)
        .string("forwarded-tcpip")
        .uint32(91)
        .uint32(1024)
        .uint32(32768)
        .string("example.com")
        .toBuffer()
    );

    const failure = new SshBinaryReader(event.responsePayload!);
    expect(failure.byte()).toBe(SSH_MSG_CHANNEL_OPEN_FAILURE);
    expect(failure.uint32()).toBe(91);
    expect(failure.uint32()).toBe(1);
  });
});

function authenticatedReadySession(phase: "authenticating" | "authenticated"): SshSessionStateMachine {
  const session = new SshSessionStateMachine({
    clientVersion: "SSH-2.0-client",
    serverVersion: "SSH-2.0-server"
  });
  forcePhase(session, phase);
  return session;
}

function forcePhase(session: SshSessionStateMachine, phase: string): void {
  (session as unknown as { phase: string }).phase = phase;
}

interface TestHostIdentity {
  privateKey: KeyObject;
  hostKeyBlob: Buffer;
  fingerprint: string;
}

function createEd25519HostIdentity(): TestHostIdentity {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const rawPublicKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const hostKeyBlob = encodeEd25519PublicKeyBlob(rawPublicKey);
  return { privateKey, hostKeyBlob, fingerprint: sha256Fingerprint(hostKeyBlob) };
}

function prepareCurveExchange(session: SshSessionStateMachine, hostIdentity: TestHostIdentity): { replyPayload: Buffer } {
  const started = session.startKex();
  const serverKexInitPayload = encodeKexInit({
    ...createDefaultKexInit(),
    kexAlgorithms: ["curve25519-sha256"],
    serverHostKeyAlgorithms: ["ssh-ed25519"]
  });
  const kexInit = session.receiveServerKexInit(serverKexInitPayload);
  const clientInit = new SshBinaryReader(kexInit.kexDhInitPayload);
  expect(clientInit.byte()).toBe(30);
  const clientPublicKey = clientInit.string();

  const serverExchange = generateKeyPairSync("x25519");
  const serverPublicKey = exportRawX25519PublicKey(serverExchange.publicKey);
  const sharedSecret = bufferToBigInt(
    diffieHellman({
      privateKey: serverExchange.privateKey,
      publicKey: importRawX25519PublicKey(clientPublicKey)
    })
  );
  const exchangeHash = computeCurve25519Sha256ExchangeHash({
    clientVersion: "SSH-2.0-client",
    serverVersion: "SSH-2.0-server",
    clientKexInitPayload: started.clientKexInitPayload,
    serverKexInitPayload,
    serverHostKey: hostIdentity.hostKeyBlob,
    clientPublicKey,
    serverPublicKey,
    sharedSecret
  });
  const signature = encodeSshSignatureBlob("ssh-ed25519", nodeSign(null, exchangeHash, hostIdentity.privateKey));
  return {
    replyPayload: new SshBinaryWriter()
      .byte(31)
      .string(hostIdentity.hostKeyBlob)
      .string(serverPublicKey)
      .string(signature)
      .toBuffer()
  };
}
