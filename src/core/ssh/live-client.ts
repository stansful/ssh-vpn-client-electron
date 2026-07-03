import { EventEmitter } from "node:events";
import { SSH_SERVICE_CONNECTION } from "./auth-messages.js";
import type { DirectTcpIpChannel, DirectTcpIpTarget } from "../network/local-tcp-proxy.js";
import {
  SSH_MSG_CHANNEL_CLOSE,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_EOF,
  SSH_MSG_CHANNEL_FAILURE,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_CHANNEL_OPEN_FAILURE,
  SSH_MSG_CHANNEL_SUCCESS,
  SSH_MSG_CHANNEL_WINDOW_ADJUST,
  SSH_MSG_NEWKEYS,
  SSH_MSG_SERVICE_ACCEPT,
  SSH_MSG_USERAUTH_FAILURE,
  SSH_MSG_USERAUTH_SUCCESS,
  messageNumber
} from "./connection-messages.js";
import { SshPrivateKeyLoadError, buildSignedPublicKeyAuthRequest, loadPrivateKey } from "./private-key.js";
import type { PacketProtectionConfig } from "./packet-codec.js";
import { SshSessionStateMachine, type ChannelEvent } from "./session-state.js";
import { SshSocketTransport, type SshIdentificationExchange, type SshPacketTransportEvent } from "./socket-transport.js";
import {
  SSH_MSG_DISCONNECT,
  SSH_MSG_REQUEST_FAILURE,
  SSH_MSG_REQUEST_SUCCESS,
  encodeDisconnect,
  encodeKeepaliveRequest
} from "./transport-messages.js";
import { SSH_MSG_KEXINIT } from "./messages.js";

export interface SshLiveClientOptions {
  host: string;
  port: number;
  username: string;
  expectedServerFingerprint?: string;
  password?: string;
  privateKey?: string;
  privateKeyPassphrase?: string;
  connectTimeoutMs?: number;
  operationTimeoutMs?: number;
  keepaliveIntervalSec?: number;
}

export type SshLiveClientEvent =
  | { type: "ready" }
  | { type: "terminal-data"; data: Buffer }
  | { type: "error"; error: Error }
  | { type: "close" };

export class SshAuthenticationError extends Error {
  readonly diagnostics: string[];

  constructor(message: string, diagnostics: string[]) {
    super(message);
    this.name = "SshAuthenticationError";
    this.diagnostics = diagnostics;
  }
}

type PayloadWaiter = {
  predicate: (payload: Buffer) => boolean;
  resolve: (payload: Buffer) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
};

type ChannelWaiter = {
  localChannel: number;
  predicate: (event: ChannelEvent) => boolean;
  resolve: (event: ChannelEvent) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
};

export class SshLiveClient {
  private readonly events = new EventEmitter();
  private readonly session: SshSessionStateMachine;
  private readonly payloadQueue: Buffer[] = [];
  private readonly payloadWaiters: PayloadWaiter[] = [];
  private readonly channelWaiters: ChannelWaiter[] = [];
  private readonly channelEmitters = new Map<number, EventEmitter>();
  private runtimeDispatchEnabled = false;
  private closed = false;
  private terminalChannel: number | undefined;
  private keepaliveTimer: NodeJS.Timeout | undefined;
  private lastActivityAt = Date.now();

  private constructor(
    private readonly transport: SshSocketTransport,
    private readonly identification: SshIdentificationExchange,
    private readonly options: SshLiveClientOptions
  ) {
    this.session = new SshSessionStateMachine({
      clientVersion: identification.clientLine,
      serverVersion: identification.serverLine,
      expectedServerFingerprint: options.expectedServerFingerprint || undefined
    });
    this.transport.onEvent((event) => this.handleTransportEvent(event));
  }

  static async connect(options: SshLiveClientOptions): Promise<SshLiveClient> {
    const transport = await SshSocketTransport.connect({
      host: options.host,
      port: options.port,
      timeoutMs: options.connectTimeoutMs,
      clientSoftwareVersion: "shadow-ssh-desktop"
    });
    const identification = await transport.exchangeIdentification("shadow-ssh-desktop");
    const client = new SshLiveClient(transport, identification, options);
    await client.performKex();
    await client.authenticate();
    client.startRuntimeDispatch();
    client.startKeepalive();
    client.events.emit("event", { type: "ready" } satisfies SshLiveClientEvent);
    return client;
  }

  onEvent(listener: (event: SshLiveClientEvent) => void): () => void {
    this.events.on("event", listener);
    return () => this.events.off("event", listener);
  }

  async openShell(columns = 120, rows = 32): Promise<void> {
    const { channel, payload } = this.session.openSessionChannel();
    this.channelEmitters.set(channel.localId, new EventEmitter());
    this.transport.send(payload);
    await this.waitForChannelOpen(channel.localId);

    const requests = this.session.buildPtyAndShellRequests(channel.localId, columns, rows);
    this.transport.send(requests.pty);
    await this.waitForChannelRequest(channel.localId, "PTY allocation failed.");
    this.transport.send(requests.shell);
    await this.waitForChannelRequest(channel.localId, "Shell request failed.");
    this.terminalChannel = channel.localId;
  }

  async writeShell(data: Buffer | string): Promise<void> {
    if (this.terminalChannel === undefined) {
      throw new Error("SSH shell channel is not open.");
    }
    await this.writeChannelDataFlowControlled(this.terminalChannel, Buffer.isBuffer(data) ? data : Buffer.from(data));
  }

  async closeShell(): Promise<void> {
    if (this.terminalChannel === undefined) {
      return;
    }
    const localChannel = this.terminalChannel;
    this.terminalChannel = undefined;
    this.markActivity();
    try {
      this.transport.send(this.session.buildChannelEof(localChannel));
    } catch {
      // Shell channel may already be closed by the server.
    }
    try {
      this.transport.send(this.session.buildChannelClose(localChannel));
    } catch {
      // Shell channel may already be closed by the server.
    }
    this.channelEmitters.delete(localChannel);
    this.rejectChannelWaiters(localChannel, new Error(`SSH channel ${localChannel} was closed.`));
  }

  async resizePty(columns: number, rows: number): Promise<void> {
    if (this.terminalChannel === undefined) {
      throw new Error("SSH shell channel is not open.");
    }
    this.transport.send(this.session.buildWindowChange(this.terminalChannel, columns, rows));
  }

  async openDirectTcpIpChannel(target: DirectTcpIpTarget, originator: { address: string; port: number }): Promise<DirectTcpIpChannel> {
    const { channel, payload } = this.session.openDirectTcpIpChannel({
      hostToConnect: target.host,
      portToConnect: target.port,
      originatorIpAddress: originator.address,
      originatorPort: originator.port
    });
    const emitter = new EventEmitter();
    this.channelEmitters.set(channel.localId, emitter);
    this.transport.send(payload);
    await this.waitForChannelOpen(channel.localId);
    return new SshDirectTcpIpChannel(channel.localId, emitter, this);
  }

  async writeDirectChannel(localChannel: number, data: Buffer): Promise<void> {
    await this.writeChannelDataFlowControlled(localChannel, data);
  }

  closeDirectChannel(localChannel: number): void {
    this.markActivity();
    try {
      this.transport.send(this.session.buildChannelEof(localChannel));
    } catch {
      // Channel may already be closed by the server.
    }
    try {
      this.transport.send(this.session.buildChannelClose(localChannel));
    } catch {
      // Channel may already be closed by the server.
    }
    this.channelEmitters.delete(localChannel);
    this.rejectChannelWaiters(localChannel, new Error(`SSH channel ${localChannel} was closed.`));
  }

  async checkTunnel(endpoint: string): Promise<void> {
    const target = parseEndpoint(endpoint);
    const channel = await this.openDirectTcpIpChannel(target, { address: "127.0.0.1", port: 0 });
    await channel.close();
  }

  async sendKeepalive(): Promise<void> {
    this.markActivity();
    this.transport.send(encodeKeepaliveRequest());
    await this.waitForGlobalResponse(this.operationTimeoutMs());
  }

  async disconnect(description = "Client disconnect."): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.stopKeepalive();
    try {
      this.transport.send(encodeDisconnect(11, description));
    } catch {
      // Socket may already be closed.
    }
    this.transport.close();
    this.rejectWaiters(new Error("SSH client disconnected."));
  }

  destroy(error?: Error): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.stopKeepalive();
    this.transport.destroy(error);
    this.rejectWaiters(error ?? new Error("SSH client destroyed."));
  }

  private async performKex(): Promise<void> {
    const start = this.session.startKex();
    this.transport.send(start.clientKexInitPayload);

    const serverKexInit = await this.waitForPayload((payload) => messageNumber(payload) === SSH_MSG_KEXINIT, this.operationTimeoutMs());
    const kexInit = this.session.receiveServerKexInit(serverKexInit);
    this.transport.send(kexInit.kexDhInitPayload);

    const kexReply = await this.waitForPayload((payload) => messageNumber(payload) === 31, this.operationTimeoutMs());
    const complete = this.session.completeKex(kexReply);
    this.transport.send(complete.newKeysPayload);

    const newKeys = await this.waitForPayload((payload) => messageNumber(payload) === SSH_MSG_NEWKEYS, this.operationTimeoutMs());
    this.session.receiveNewKeys(newKeys);
    this.transport.enableEncryption(
      {
        cipherName: kexInit.negotiated.encryptionServerToClient as PacketProtectionConfig["cipherName"],
        encryptionKey: complete.transportKeys.encryptionKeyServerToClient,
        initialIv: complete.transportKeys.initialIvServerToClient,
        macName: kexInit.negotiated.macServerToClient as PacketProtectionConfig["macName"],
        macKey: complete.transportKeys.integrityKeyServerToClient
      },
      {
        cipherName: kexInit.negotiated.encryptionClientToServer as PacketProtectionConfig["cipherName"],
        encryptionKey: complete.transportKeys.encryptionKeyClientToServer,
        initialIv: complete.transportKeys.initialIvClientToServer,
        macName: kexInit.negotiated.macClientToServer as PacketProtectionConfig["macName"],
        macKey: complete.transportKeys.integrityKeyClientToServer
      }
    );
  }

  private async authenticate(): Promise<void> {
    this.transport.send(this.session.requestUserAuthService());
    const serviceAccept = await this.waitForPayload((payload) => messageNumber(payload) === SSH_MSG_SERVICE_ACCEPT, this.operationTimeoutMs());
    this.session.receiveServiceAccept(serviceAccept);

    const errors: string[] = [];
    const diagnostics: string[] = [];
    if (this.options.privateKey) {
      try {
        const key = loadPrivateKey(this.options.privateKey, this.options.privateKeyPassphrase || undefined);
        this.transport.send(
          buildSignedPublicKeyAuthRequest({
            sessionId: this.session.getSessionId(),
            username: this.options.username,
            service: SSH_SERVICE_CONNECTION,
            privateKey: key.privateKey,
            publicKey: key.publicKey
          })
        );
        if (await this.waitForAuthSuccess()) {
          return;
        }
        errors.push("private-key auth rejected");
      } catch (error) {
        errors.push(error instanceof Error ? error.message : String(error));
        if (error instanceof SshPrivateKeyLoadError) {
          diagnostics.push(...error.diagnostics);
        }
      }
    }

    if (this.options.password !== undefined) {
      this.transport.send(this.session.buildPasswordAuth(this.options.username, this.options.password));
      if (await this.waitForAuthSuccess()) {
        return;
      }
      errors.push("password auth rejected");
    }

    throw new SshAuthenticationError(
      errors.length > 0 ? `SSH authentication failed: ${errors.join("; ")}` : "SSH authentication failed: no auth method available.",
      diagnostics
    );
  }

  private async waitForAuthSuccess(): Promise<boolean> {
    const payload = await this.waitForPayload(
      (candidate) => {
        const number = messageNumber(candidate);
        return number === SSH_MSG_USERAUTH_SUCCESS || number === SSH_MSG_USERAUTH_FAILURE;
      },
      this.operationTimeoutMs()
    );
    return this.session.receiveAuthResult(payload) === "success";
  }

  private startRuntimeDispatch(): void {
    this.runtimeDispatchEnabled = true;
    const queued = this.payloadQueue.splice(0);
    for (const payload of queued) {
      this.dispatchRuntimePayload(payload);
    }
  }

  private startKeepalive(): void {
    const configuredIntervalSec = this.options.keepaliveIntervalSec ?? 0;
    const intervalMs = (configuredIntervalSec <= 0 ? 0 : Math.max(60, configuredIntervalSec)) * 1000;
    if (intervalMs <= 0) {
      return;
    }
    this.keepaliveTimer = setInterval(() => {
      if (Date.now() - this.lastActivityAt < intervalMs) {
        return;
      }
      void this.sendKeepalive().catch((error: unknown) => {
        const normalized = error instanceof Error ? error : new Error(String(error));
        this.events.emit("event", { type: "error", error: normalized } satisfies SshLiveClientEvent);
        this.destroy(normalized);
      });
    }, intervalMs);
    this.keepaliveTimer.unref();
  }

  private stopKeepalive(): void {
    if (this.keepaliveTimer) {
      clearInterval(this.keepaliveTimer);
      this.keepaliveTimer = undefined;
    }
  }

  private handleTransportEvent(event: SshPacketTransportEvent): void {
    if (event.type === "payload") {
      this.markActivity();
      if (this.runtimeDispatchEnabled) {
        this.dispatchRuntimePayload(event.payload);
      } else {
        this.payloadQueue.push(event.payload);
        this.flushPayloadWaiters();
      }
      return;
    }
    if (event.type === "error") {
      this.events.emit("event", { type: "error", error: event.error } satisfies SshLiveClientEvent);
      this.rejectWaiters(event.error);
      return;
    }
    this.closed = true;
    this.stopKeepalive();
    this.rejectWaiters(new Error("SSH transport closed."));
    this.events.emit("event", { type: "close" } satisfies SshLiveClientEvent);
  }

  private dispatchRuntimePayload(payload: Buffer): void {
    const number = messageNumber(payload);
    if (number === SSH_MSG_REQUEST_SUCCESS || number === SSH_MSG_REQUEST_FAILURE) {
      this.events.emit("global-response", number);
      return;
    }
    if (number === SSH_MSG_DISCONNECT) {
      this.closed = true;
      this.stopKeepalive();
      this.events.emit("event", { type: "close" } satisfies SshLiveClientEvent);
      return;
    }
    if (isChannelMessage(number)) {
      const channelEvent = this.session.receiveChannelMessage(payload);
      if (channelEvent.windowAdjustPayload) {
        this.transport.send(channelEvent.windowAdjustPayload);
      }
      this.emitChannelEvent(channelEvent);
    }
  }

  private emitChannelEvent(event: ChannelEvent): void {
    this.events.emit("channel-event", event);
    this.flushChannelWaiters(event);
    if (event.localChannel === undefined) {
      return;
    }
    const emitter = this.channelEmitters.get(event.localChannel);
    if (!emitter) {
      return;
    }
    if (event.type === "data" && event.data) {
      emitter.emit("data", event.data);
      if (event.localChannel === this.terminalChannel) {
        this.events.emit("event", { type: "terminal-data", data: event.data } satisfies SshLiveClientEvent);
      }
    }
    if (event.type === "eof" || event.type === "close" || event.type === "open-failed") {
      emitter.emit("close");
      this.channelEmitters.delete(event.localChannel);
      if (event.localChannel === this.terminalChannel) {
        this.terminalChannel = undefined;
      }
    }
  }

  private async waitForChannelOpen(localChannel: number): Promise<void> {
    const event = await this.waitForChannelEvent(
      localChannel,
      (candidate) => candidate.type === "open-confirmed" || candidate.type === "open-failed",
      this.operationTimeoutMs()
    );
    if (event.type === "open-failed") {
      throw new Error(event.description || `SSH channel ${localChannel} open failed.`);
    }
  }

  private async waitForChannelRequest(localChannel: number, failureMessage: string): Promise<void> {
    const event = await this.waitForChannelEvent(
      localChannel,
      (candidate) => candidate.type === "success" || candidate.type === "failure",
      this.operationTimeoutMs()
    );
    if (event.type === "failure") {
      throw new Error(failureMessage);
    }
  }

  private async waitForGlobalResponse(timeoutMs: number): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error("SSH keepalive timed out."));
      }, timeoutMs);
      timer.unref();
      const onResponse = (): void => {
        cleanup();
        resolve();
      };
      const cleanup = (): void => {
        clearTimeout(timer);
        this.events.off("global-response", onResponse);
      };
      this.events.on("global-response", onResponse);
    });
  }

  private waitForPayload(predicate: (payload: Buffer) => boolean, timeoutMs: number): Promise<Buffer> {
    const queuedIndex = this.payloadQueue.findIndex(predicate);
    if (queuedIndex >= 0) {
      const [payload] = this.payloadQueue.splice(queuedIndex, 1);
      return Promise.resolve(payload);
    }

    return new Promise<Buffer>((resolve, reject) => {
      const waiter: PayloadWaiter = {
        predicate,
        resolve,
        reject,
        timer: setTimeout(() => {
          this.payloadWaiters.splice(this.payloadWaiters.indexOf(waiter), 1);
          reject(new Error("Timed out waiting for SSH packet."));
        }, timeoutMs)
      };
      waiter.timer.unref();
      this.payloadWaiters.push(waiter);
    });
  }

  private flushPayloadWaiters(): void {
    for (const waiter of [...this.payloadWaiters]) {
      const queuedIndex = this.payloadQueue.findIndex(waiter.predicate);
      if (queuedIndex < 0) {
        continue;
      }
      const [payload] = this.payloadQueue.splice(queuedIndex, 1);
      this.payloadWaiters.splice(this.payloadWaiters.indexOf(waiter), 1);
      clearTimeout(waiter.timer);
      waiter.resolve(payload);
    }
  }

  private waitForChannelEvent(localChannel: number, predicate: (event: ChannelEvent) => boolean, timeoutMs: number): Promise<ChannelEvent> {
    return new Promise<ChannelEvent>((resolve, reject) => {
      const waiter: ChannelWaiter = {
        localChannel,
        predicate,
        resolve,
        reject,
        timer: setTimeout(() => {
          this.channelWaiters.splice(this.channelWaiters.indexOf(waiter), 1);
          reject(new Error(`Timed out waiting for SSH channel ${localChannel}.`));
        }, timeoutMs)
      };
      waiter.timer.unref();
      this.channelWaiters.push(waiter);
    });
  }

  private flushChannelWaiters(event: ChannelEvent): void {
    if (event.localChannel === undefined) {
      return;
    }
    for (const waiter of [...this.channelWaiters]) {
      if (waiter.localChannel !== event.localChannel || !waiter.predicate(event)) {
        continue;
      }
      this.channelWaiters.splice(this.channelWaiters.indexOf(waiter), 1);
      clearTimeout(waiter.timer);
      waiter.resolve(event);
    }
  }

  private async writeChannelDataFlowControlled(localChannel: number, data: Buffer): Promise<void> {
    let offset = 0;
    while (offset < data.length) {
      const { payloads, bytesWritten } = this.session.buildChannelDataFrames(localChannel, data.subarray(offset));
      if (payloads.length > 0) {
        this.markActivity();
        for (const payload of payloads) {
          this.transport.send(payload);
        }
        offset += bytesWritten;
        continue;
      }
      await this.waitForChannelWriteWindow(localChannel);
    }
  }

  private async waitForChannelWriteWindow(localChannel: number): Promise<void> {
    const event = await this.waitForChannelEvent(
      localChannel,
      (candidate) =>
        candidate.type === "window-adjust" ||
        candidate.type === "close" ||
        candidate.type === "eof" ||
        candidate.type === "open-failed",
      this.operationTimeoutMs()
    );
    if (event.type !== "window-adjust") {
      throw new Error(`SSH channel ${localChannel} closed before queued data was written.`);
    }
  }

  private rejectWaiters(error: Error): void {
    for (const waiter of this.payloadWaiters.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
    for (const waiter of this.channelWaiters.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
  }

  private rejectChannelWaiters(localChannel: number, error: Error): void {
    for (const waiter of [...this.channelWaiters]) {
      if (waiter.localChannel !== localChannel) {
        continue;
      }
      this.channelWaiters.splice(this.channelWaiters.indexOf(waiter), 1);
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
  }

  private operationTimeoutMs(): number {
    return this.options.operationTimeoutMs ?? 15000;
  }

  private markActivity(): void {
    this.lastActivityAt = Date.now();
  }
}

class SshDirectTcpIpChannel implements DirectTcpIpChannel {
  private closed = false;
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly localChannel: number,
    private readonly emitter: EventEmitter,
    private readonly client: SshLiveClient
  ) {}

  async write(data: Buffer): Promise<void> {
    if (this.closed) {
      throw new Error("Direct TCP channel is closed.");
    }
    const write = this.writeQueue.then(() => {
      if (this.closed) {
        throw new Error("Direct TCP channel is closed.");
      }
      return this.client.writeDirectChannel(this.localChannel, data);
    });
    this.writeQueue = write.catch(() => undefined);
    await write;
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.client.closeDirectChannel(this.localChannel);
  }

  onData(listener: (data: Buffer) => void): () => void {
    this.emitter.on("data", listener);
    return () => this.emitter.off("data", listener);
  }

  onClose(listener: () => void): () => void {
    const wrapped = (): void => {
      this.closed = true;
      listener();
    };
    this.emitter.on("close", wrapped);
    return () => this.emitter.off("close", wrapped);
  }

  onError(listener: (error: Error) => void): () => void {
    this.emitter.on("error", listener);
    return () => this.emitter.off("error", listener);
  }
}

function isChannelMessage(number: number): boolean {
  return (
    number === SSH_MSG_CHANNEL_OPEN_CONFIRMATION ||
    number === SSH_MSG_CHANNEL_OPEN_FAILURE ||
    number === SSH_MSG_CHANNEL_WINDOW_ADJUST ||
    number === SSH_MSG_CHANNEL_DATA ||
    number === SSH_MSG_CHANNEL_EOF ||
    number === SSH_MSG_CHANNEL_CLOSE ||
    number === SSH_MSG_CHANNEL_SUCCESS ||
    number === SSH_MSG_CHANNEL_FAILURE
  );
}

function parseEndpoint(endpoint: string): DirectTcpIpTarget {
  const trimmed = endpoint.trim();
  if (!trimmed) {
    throw new Error("Endpoint is required.");
  }

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//iu.test(trimmed) ? trimmed : `tcp://${trimmed}`;
  const url = new URL(withScheme);
  const port = Number(url.port);
  if (!url.hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Malformed endpoint ${endpoint}. Use host:port.`);
  }
  return { host: url.hostname.replace(/^\[(.*)\]$/u, "$1"), port };
}
