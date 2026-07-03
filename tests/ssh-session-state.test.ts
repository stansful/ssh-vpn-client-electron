import { describe, expect, it } from "vitest";
import { SshBinaryReader, SshBinaryWriter } from "../src/core/ssh/binary.js";
import {
  SSH_MSG_CHANNEL_CLOSE,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_EOF,
  SSH_MSG_CHANNEL_FAILURE,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_CHANNEL_SUCCESS,
  SSH_MSG_CHANNEL_WINDOW_ADJUST,
  SSH_MSG_NEWKEYS,
  SSH_MSG_SERVICE_ACCEPT,
  SSH_MSG_USERAUTH_FAILURE,
  SSH_MSG_USERAUTH_SUCCESS
} from "../src/core/ssh/connection-messages.js";
import { deriveTransportKeys, transportKeyLengthsFor } from "../src/core/ssh/key-derivation.js";
import { SshPacketProtector } from "../src/core/ssh/packet-codec.js";
import { SshSessionStateMachine } from "../src/core/ssh/session-state.js";
import { createDefaultKexInit, encodeKexInit } from "../src/core/ssh/messages.js";

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

    expect(session.receiveChannelMessage(new SshBinaryWriter().byte(SSH_MSG_CHANNEL_CLOSE).uint32(0).toBuffer())).toEqual({
      type: "close",
      localChannel: 0
    });
    expect(session.getChannel(0)).toBeUndefined();
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

  it("sends window adjust when inbound streaming data drains the local window", () => {
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

    const chunk = Buffer.alloc(9 * 1024 * 1024);
    const event = session.receiveChannelMessage(
      new SshBinaryWriter().byte(SSH_MSG_CHANNEL_DATA).uint32(opened.channel.localId).string(chunk).toBuffer()
    );

    expect(event.type).toBe("data");
    expect(event.windowAdjustPayload).toBeDefined();
    const adjust = new SshBinaryReader(event.windowAdjustPayload!);
    expect(adjust.byte()).toBe(SSH_MSG_CHANNEL_WINDOW_ADJUST);
    expect(adjust.uint32()).toBe(7);
    expect(adjust.uint32()).toBe(9 * 1024 * 1024);
    expect(session.getChannel(opened.channel.localId)?.localWindow).toBe(16 * 1024 * 1024);
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
