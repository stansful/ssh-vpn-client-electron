import { ChannelStateManager, type ChannelState } from "./channel-state.js";
import {
  decodeChannelData,
  decodeChannelEndpoint,
  decodeChannelOpenConfirmation,
  decodeChannelOpenFailure,
  decodeChannelWindowAdjust,
  decodeServiceAccept,
  decodeUserAuthFailure,
  messageNumber,
  SSH_MSG_CHANNEL_CLOSE,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_EOF,
  SSH_MSG_CHANNEL_FAILURE,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_CHANNEL_OPEN_FAILURE,
  SSH_MSG_CHANNEL_SUCCESS,
  SSH_MSG_CHANNEL_WINDOW_ADJUST,
  SSH_MSG_NEWKEYS,
  SSH_MSG_USERAUTH_FAILURE,
  SSH_MSG_USERAUTH_SUCCESS
} from "./connection-messages.js";
import { negotiateAlgorithms, type NegotiatedAlgorithms } from "./algorithms.js";
import { encodePasswordAuthRequest, encodeServiceRequest, SSH_SERVICE_USERAUTH } from "./auth-messages.js";
import {
  encodeChannelClose,
  encodeChannelData,
  encodeChannelEof,
  encodeChannelWindowAdjust,
  encodeDirectTcpIpChannelOpen,
  encodePtyRequest,
  encodeSessionChannelOpen,
  encodeShellRequest,
  encodeWindowChangeRequest
} from "./channel-messages.js";
import { sha256Fingerprint } from "./fingerprint.js";
import { verifySshSignature } from "./host-key.js";
import { deriveTransportKeys, transportKeyLengthsFor, type DerivedTransportKeys } from "./key-derivation.js";
import {
  computeGroup14Sha256ExchangeHash,
  createGroup14Sha256ClientExchange,
  decodeKexDhReply,
  encodeKexDhInit,
  type Group14Sha256ClientExchange
} from "./kex-group14.js";
import {
  computeCurve25519Sha256ExchangeHash,
  createCurve25519ClientExchange,
  decodeCurve25519KexReply,
  encodeCurve25519KexInit,
  type Curve25519ClientExchange
} from "./kex-curve25519.js";
import { createDefaultKexInit, decodeKexInit, encodeKexInit, type SshKexInit } from "./messages.js";

export type SshSessionPhase =
  | "idle"
  | "kexinit-sent"
  | "kexdh-sent"
  | "newkeys-sent"
  | "encrypted"
  | "service-request-sent"
  | "authenticating"
  | "authenticated"
  | "closed";

export interface SshSessionStateMachineOptions {
  clientVersion: string;
  serverVersion: string;
  expectedServerFingerprint?: string;
  clientKexInit?: SshKexInit;
}

export interface KexStartResult {
  clientKexInitPayload: Buffer;
}

export interface KexDhInitResult {
  negotiated: NegotiatedAlgorithms;
  kexDhInitPayload: Buffer;
}

export interface KexCompleteResult {
  newKeysPayload: Buffer;
  exchangeHash: Buffer;
  sessionId: Buffer;
  transportKeys: DerivedTransportKeys;
  serverHostKeyFingerprint: string;
}

export interface AuthFailureResult {
  methodsThatCanContinue: string[];
  partialSuccess: boolean;
}

export interface ChannelEvent {
  type: "open-confirmed" | "open-failed" | "window-adjust" | "data" | "eof" | "close" | "success" | "failure" | "ignored";
  localChannel?: number;
  data?: Buffer;
  description?: string;
  windowAdjustPayload?: Buffer;
}

export class SshSessionStateMachine {
  private phase: SshSessionPhase = "idle";
  private readonly channels = new ChannelStateManager();
  private readonly clientKexInit: SshKexInit;
  private clientKexInitPayload?: Buffer;
  private serverKexInitPayload?: Buffer;
  private negotiated?: NegotiatedAlgorithms;
  private clientExchange?: Group14Sha256ClientExchange | Curve25519ClientExchange;
  private sessionId?: Buffer;

  constructor(private readonly options: SshSessionStateMachineOptions) {
    this.clientKexInit = options.clientKexInit ?? createDefaultKexInit();
  }

  getPhase(): SshSessionPhase {
    return this.phase;
  }

  startKex(): KexStartResult {
    this.requirePhase("idle");
    this.clientKexInitPayload = encodeKexInit(this.clientKexInit);
    this.phase = "kexinit-sent";
    return {
      clientKexInitPayload: this.clientKexInitPayload
    };
  }

  receiveServerKexInit(serverKexInitPayload: Buffer): KexDhInitResult {
    this.requirePhase("kexinit-sent");
    const serverKexInit = decodeKexInit(serverKexInitPayload);
    this.negotiated = negotiateAlgorithms(this.clientKexInit, serverKexInit);
    this.serverKexInitPayload = serverKexInitPayload;
    if (isCurve25519Kex(this.negotiated.kexAlgorithm)) {
      this.clientExchange = createCurve25519ClientExchange();
      this.phase = "kexdh-sent";
      return {
        negotiated: this.negotiated,
        kexDhInitPayload: encodeCurve25519KexInit(this.clientExchange.publicKey)
      };
    }
    if (this.negotiated.kexAlgorithm !== "diffie-hellman-group14-sha256") {
      throw new Error(`Unsupported KEX algorithm ${this.negotiated.kexAlgorithm}.`);
    }

    this.clientExchange = createGroup14Sha256ClientExchange();
    this.phase = "kexdh-sent";
    return {
      negotiated: this.negotiated,
      kexDhInitPayload: encodeKexDhInit(this.clientExchange.exchangeValue)
    };
  }

  completeKex(kexDhReplyPayload: Buffer): KexCompleteResult {
    this.requirePhase("kexdh-sent");
    if (!this.clientExchange || !this.clientKexInitPayload || !this.serverKexInitPayload || !this.negotiated) {
      throw new Error("KEX state is incomplete.");
    }

    const kex = completeKexExchange({
      algorithm: this.negotiated.kexAlgorithm,
      clientExchange: this.clientExchange,
      payload: kexDhReplyPayload,
      clientVersion: this.options.clientVersion,
      serverVersion: this.options.serverVersion,
      clientKexInitPayload: this.clientKexInitPayload,
      serverKexInitPayload: this.serverKexInitPayload
    });

    const fingerprint = sha256Fingerprint(kex.hostKey);
    if (this.options.expectedServerFingerprint && this.options.expectedServerFingerprint !== fingerprint) {
      throw new Error(`SSH server fingerprint mismatch: expected ${this.options.expectedServerFingerprint}, got ${fingerprint}.`);
    }
    if (!verifySshSignature(kex.hostKey, kex.exchangeHash, kex.signature)) {
      throw new Error("SSH host key signature verification failed.");
    }

    this.sessionId ??= kex.exchangeHash;
    this.phase = "newkeys-sent";
    return {
      newKeysPayload: Buffer.from([SSH_MSG_NEWKEYS]),
      exchangeHash: kex.exchangeHash,
      sessionId: this.sessionId,
      transportKeys: deriveTransportKeys(
        kex.sharedSecret,
        kex.exchangeHash,
        this.sessionId,
        transportKeyLengthsFor(this.negotiated.encryptionClientToServer, this.negotiated.macClientToServer)
      ),
      serverHostKeyFingerprint: fingerprint
    };
  }

  receiveNewKeys(payload: Buffer): void {
    this.requirePhase("newkeys-sent");
    if (messageNumber(payload) !== SSH_MSG_NEWKEYS) {
      throw new Error("Expected SSH_MSG_NEWKEYS.");
    }
    this.phase = "encrypted";
  }

  requestUserAuthService(): Buffer {
    this.requirePhase("encrypted");
    this.phase = "service-request-sent";
    return encodeServiceRequest(SSH_SERVICE_USERAUTH);
  }

  receiveServiceAccept(payload: Buffer): string {
    this.requirePhase("service-request-sent");
    const accepted = decodeServiceAccept(payload);
    if (accepted !== SSH_SERVICE_USERAUTH) {
      throw new Error(`Unexpected SSH service accept ${accepted}.`);
    }
    this.phase = "authenticating";
    return accepted;
  }

  buildPasswordAuth(username: string, password: string): Buffer {
    this.requirePhase("authenticating");
    return encodePasswordAuthRequest({ username, password });
  }

  receiveAuthResult(payload: Buffer): "success" | AuthFailureResult {
    this.requirePhase("authenticating");
    const number = messageNumber(payload);
    if (number === SSH_MSG_USERAUTH_SUCCESS) {
      this.phase = "authenticated";
      return "success";
    }
    if (number === SSH_MSG_USERAUTH_FAILURE) {
      return decodeUserAuthFailure(payload);
    }
    throw new Error(`Unexpected SSH auth result message ${number}.`);
  }

  openSessionChannel(): { channel: ChannelState; payload: Buffer } {
    this.requirePhase("authenticated");
    const channel = this.channels.open("session");
    return {
      channel,
      payload: encodeSessionChannelOpen({ senderChannel: channel.localId, initialWindowSize: channel.localWindow, maximumPacketSize: channel.maximumPacketSize })
    };
  }

  openDirectTcpIpChannel(request: {
    hostToConnect: string;
    portToConnect: number;
    originatorIpAddress: string;
    originatorPort: number;
  }): { channel: ChannelState; payload: Buffer } {
    this.requirePhase("authenticated");
    const channel = this.channels.open("direct-tcpip");
    return {
      channel,
      payload: encodeDirectTcpIpChannelOpen({
        senderChannel: channel.localId,
        initialWindowSize: channel.localWindow,
        maximumPacketSize: channel.maximumPacketSize,
        ...request
      })
    };
  }

  buildPtyAndShellRequests(localChannel: number, columns: number, rows: number): { pty: Buffer; shell: Buffer } {
    const channel = this.channels.get(localChannel);
    if (!channel || channel.remoteId === undefined) {
      throw new Error(`Channel ${localChannel} is not confirmed.`);
    }
    return {
      pty: encodePtyRequest({ recipientChannel: channel.remoteId, columns, rows }),
      shell: encodeShellRequest({ recipientChannel: channel.remoteId })
    };
  }

  buildChannelData(localChannel: number, data: Buffer): Buffer {
    const channel = this.channels.get(localChannel);
    if (!channel || channel.remoteId === undefined) {
      throw new Error(`Channel ${localChannel} is not confirmed.`);
    }
    if (data.length > channel.maximumPacketSize) {
      throw new Error(`Channel ${localChannel} maximum packet size exceeded.`);
    }
    this.channels.consumeRemoteWindow(localChannel, data.length);
    return encodeChannelData({ recipientChannel: channel.remoteId, data });
  }

  buildChannelDataFrames(localChannel: number, data: Buffer): { payloads: Buffer[]; bytesWritten: number } {
    const payloads: Buffer[] = [];
    let offset = 0;
    while (offset < data.length) {
      const channel = this.channels.get(localChannel);
      if (!channel || channel.remoteId === undefined) {
        throw new Error(`Channel ${localChannel} is not confirmed.`);
      }
      const chunkLength = Math.min(channel.maximumPacketSize, channel.remoteWindow, data.length - offset);
      if (chunkLength <= 0) {
        break;
      }
      payloads.push(this.buildChannelData(localChannel, data.subarray(offset, offset + chunkLength)));
      offset += chunkLength;
    }
    return { payloads, bytesWritten: offset };
  }

  buildWindowChange(localChannel: number, columns: number, rows: number): Buffer {
    const channel = this.channels.get(localChannel);
    if (!channel || channel.remoteId === undefined) {
      throw new Error(`Channel ${localChannel} is not confirmed.`);
    }
    return encodeWindowChangeRequest({ recipientChannel: channel.remoteId, columns, rows });
  }

  buildChannelEof(localChannel: number): Buffer {
    const channel = this.channels.get(localChannel);
    if (!channel || channel.remoteId === undefined) {
      throw new Error(`Channel ${localChannel} is not confirmed.`);
    }
    this.channels.markEofSent(localChannel);
    return encodeChannelEof(channel.remoteId);
  }

  buildChannelClose(localChannel: number): Buffer {
    const channel = this.channels.get(localChannel);
    if (!channel || channel.remoteId === undefined) {
      throw new Error(`Channel ${localChannel} is not confirmed.`);
    }
    this.channels.close(localChannel);
    return encodeChannelClose(channel.remoteId);
  }

  getSessionId(): Buffer {
    if (!this.sessionId) {
      throw new Error("SSH session id is not established.");
    }
    return this.sessionId;
  }

  receiveChannelMessage(payload: Buffer): ChannelEvent {
    const number = messageNumber(payload);
    if (number === SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
      const confirmation = decodeChannelOpenConfirmation(payload);
      this.channels.confirmOpen(
        confirmation.recipientChannel,
        confirmation.senderChannel,
        confirmation.initialWindowSize,
        confirmation.maximumPacketSize
      );
      return { type: "open-confirmed", localChannel: confirmation.recipientChannel };
    }
    if (number === SSH_MSG_CHANNEL_OPEN_FAILURE) {
      const failure = decodeChannelOpenFailure(payload);
      this.channels.close(failure.recipientChannel);
      return { type: "open-failed", localChannel: failure.recipientChannel, description: failure.description };
    }
    if (number === SSH_MSG_CHANNEL_WINDOW_ADJUST) {
      const adjust = decodeChannelWindowAdjust(payload);
      if (!this.channels.get(adjust.recipientChannel)) {
        return { type: "ignored", localChannel: adjust.recipientChannel, description: "window-adjust for unknown channel" };
      }
      this.channels.expandRemoteWindow(adjust.recipientChannel, adjust.bytesToAdd);
      return { type: "window-adjust", localChannel: adjust.recipientChannel };
    }
    if (number === SSH_MSG_CHANNEL_DATA) {
      const data = decodeChannelData(payload);
      if (!this.channels.get(data.recipientChannel)) {
        return { type: "ignored", localChannel: data.recipientChannel, description: "data for unknown channel" };
      }
      const channel = this.channels.consumeLocalWindow(data.recipientChannel, data.data.length);
      const replenishThreshold = Math.floor(channel.localWindowMaximum / 2);
      if (channel.localWindow <= replenishThreshold) {
        const bytesToAdd = channel.localWindowMaximum - channel.localWindow;
        const replenished = this.channels.replenishLocalWindow(data.recipientChannel, bytesToAdd);
        if (replenished.remoteId !== undefined) {
          return {
            type: "data",
            localChannel: data.recipientChannel,
            data: data.data,
            windowAdjustPayload: encodeChannelWindowAdjust(replenished.remoteId, bytesToAdd)
          };
        }
      }
      return { type: "data", localChannel: data.recipientChannel, data: data.data };
    }
    if (number === SSH_MSG_CHANNEL_EOF) {
      const localChannel = decodeChannelEndpoint(payload, SSH_MSG_CHANNEL_EOF);
      if (!this.channels.get(localChannel)) {
        return { type: "ignored", localChannel, description: "eof for unknown channel" };
      }
      this.channels.markEofReceived(localChannel);
      return { type: "eof", localChannel };
    }
    if (number === SSH_MSG_CHANNEL_CLOSE) {
      const localChannel = decodeChannelEndpoint(payload, SSH_MSG_CHANNEL_CLOSE);
      if (!this.channels.get(localChannel)) {
        return { type: "ignored", localChannel, description: "close for unknown channel" };
      }
      this.channels.close(localChannel);
      return { type: "close", localChannel };
    }
    if (number === SSH_MSG_CHANNEL_SUCCESS) {
      const localChannel = decodeChannelEndpoint(payload, SSH_MSG_CHANNEL_SUCCESS);
      if (!this.channels.get(localChannel)) {
        return { type: "ignored", localChannel, description: "success for unknown channel" };
      }
      return { type: "success", localChannel };
    }
    if (number === SSH_MSG_CHANNEL_FAILURE) {
      const localChannel = decodeChannelEndpoint(payload, SSH_MSG_CHANNEL_FAILURE);
      if (!this.channels.get(localChannel)) {
        return { type: "ignored", localChannel, description: "failure for unknown channel" };
      }
      return { type: "failure", localChannel };
    }
    throw new Error(`Unexpected SSH channel message ${number}.`);
  }

  getChannel(localChannel: number): ChannelState | undefined {
    return this.channels.get(localChannel);
  }

  private requirePhase(expected: SshSessionPhase): void {
    if (this.phase !== expected) {
      throw new Error(`Invalid SSH session phase ${this.phase}; expected ${expected}.`);
    }
  }
}

function isCurve25519Kex(algorithm: string): boolean {
  return algorithm === "curve25519-sha256" || algorithm === "curve25519-sha256@libssh.org";
}

function completeKexExchange(input: {
  algorithm: string;
  clientExchange: Group14Sha256ClientExchange | Curve25519ClientExchange;
  payload: Buffer;
  clientVersion: string;
  serverVersion: string;
  clientKexInitPayload: Buffer;
  serverKexInitPayload: Buffer;
}): { hostKey: Buffer; signature: Buffer; exchangeHash: Buffer; sharedSecret: bigint } {
  if (isCurve25519Kex(input.algorithm)) {
    const clientExchange = input.clientExchange as Curve25519ClientExchange;
    const reply = decodeCurve25519KexReply(input.payload);
    const sharedSecret = clientExchange.computeSharedSecret(reply.serverPublicKey);
    return {
      hostKey: reply.hostKey,
      signature: reply.signature,
      sharedSecret,
      exchangeHash: computeCurve25519Sha256ExchangeHash({
        clientVersion: input.clientVersion,
        serverVersion: input.serverVersion,
        clientKexInitPayload: input.clientKexInitPayload,
        serverKexInitPayload: input.serverKexInitPayload,
        serverHostKey: reply.hostKey,
        clientPublicKey: clientExchange.publicKey,
        serverPublicKey: reply.serverPublicKey,
        sharedSecret
      })
    };
  }

  const clientExchange = input.clientExchange as Group14Sha256ClientExchange;
  const reply = decodeKexDhReply(input.payload);
  const sharedSecret = clientExchange.computeSharedSecret(reply.serverExchangeValue);
  return {
    hostKey: reply.hostKey,
    signature: reply.signature,
    sharedSecret,
    exchangeHash: computeGroup14Sha256ExchangeHash({
      clientVersion: input.clientVersion,
      serverVersion: input.serverVersion,
      clientKexInitPayload: input.clientKexInitPayload,
      serverKexInitPayload: input.serverKexInitPayload,
      serverHostKey: reply.hostKey,
      clientExchangeValue: clientExchange.exchangeValue,
      serverExchangeValue: reply.serverExchangeValue,
      sharedSecret
    })
  };
}
