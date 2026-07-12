import { EventEmitter } from "node:events";
import { SSH_SERVICE_CONNECTION } from "./auth-messages.js";
import type { DirectTcpIpChannel, DirectTcpIpTarget } from "../network/local-tcp-proxy.js";
import {
  SSH_MSG_CHANNEL_CLOSE,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_EXTENDED_DATA,
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
import { SSH_MSG_CHANNEL_OPEN, SSH_MSG_CHANNEL_REQUEST } from "./channel-messages.js";
import { SshPrivateKeyLoadError, buildSignedPublicKeyAuthRequest, loadPrivateKey } from "./private-key.js";
import type { PacketProtectionConfig } from "./packet-codec.js";
import { SshSessionStateMachine, type ChannelEvent } from "./session-state.js";
import { SshSocketTransport, type SshIdentificationExchange, type SshPacketTransportEvent } from "./socket-transport.js";
import {
  SSH_MSG_DISCONNECT,
  SSH_MSG_GLOBAL_REQUEST,
  SSH_MSG_REQUEST_FAILURE,
  SSH_MSG_REQUEST_SUCCESS,
  decodeGlobalRequest,
  encodeDisconnect,
  encodeKeepaliveRequest,
  encodeRequestFailure
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
  rekeyAfterBytes?: number;
  rekeyIntervalMs?: number;
}

export type SshLiveClientEvent =
  | { type: "ready" }
  | { type: "terminal-data"; data: Buffer; stream: "stdout" | "stderr" }
  | { type: "terminal-close" }
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

type ChannelDeliveryState = {
  emitter: EventEmitter;
  ready: boolean;
  readyScheduled: boolean;
  pending: ChannelEvent[];
  pendingDataBytes: number;
};

const MAX_PRE_AUTH_QUEUED_PAYLOADS = 128;
const MAX_PRE_AUTH_QUEUED_BYTES = 1024 * 1024;
const MAX_REKEY_QUEUED_PAYLOADS = 2048;
const MAX_REKEY_QUEUED_BYTES = 32 * 1024 * 1024;
const DEFAULT_REKEY_AFTER_BYTES = 1024 * 1024 * 1024;
const DEFAULT_REKEY_INTERVAL_MS = 60 * 60 * 1000;
const MAX_TIMER_DELAY_MS = 2_147_000_000;
const GRACEFUL_DISCONNECT_TIMEOUT_MS = 1_000;
const MAX_PENDING_CHANNEL_EVENTS = 512;
const MAX_PENDING_CHANNEL_DATA_BYTES = 16 * 1024 * 1024;
const MAX_TOTAL_PENDING_CHANNEL_DATA_BYTES = 32 * 1024 * 1024;

export class SshLiveClient {
  private readonly events = new EventEmitter();
  private readonly session: SshSessionStateMachine;
  private readonly payloadQueue: Buffer[] = [];
  private payloadQueueBytes = 0;
  private readonly payloadWaiters: PayloadWaiter[] = [];
  private readonly channelWaiters: ChannelWaiter[] = [];
  private readonly channelDeliveries = new Map<number, ChannelDeliveryState>();
  private totalPendingChannelDataBytes = 0;
  private runtimeDispatchEnabled = false;
  private closed = false;
  private terminalChannel: number | undefined;
  private maintenanceTimer: NodeJS.Timeout | undefined;
  private keepalivePromise: Promise<void> | undefined;
  private rekeyPromise: Promise<void> | undefined;
  private rekeyBytesBaseline = 0;
  private lastRekeyAt = Date.now();
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
    let transport: SshSocketTransport | undefined;
    try {
      transport = await SshSocketTransport.connect({
        host: options.host,
        port: options.port,
        timeoutMs: options.connectTimeoutMs,
        clientSoftwareVersion: "shadow-ssh-desktop",
        keepAliveInitialDelayMs: sshKernelKeepaliveInitialDelayMs(options.keepaliveIntervalSec)
      });
      const identification = await transport.exchangeIdentification(
        "shadow-ssh-desktop",
        options.connectTimeoutMs ?? options.operationTimeoutMs ?? 10000
      );
      const client = new SshLiveClient(transport, identification, options);
      await client.performKex();
      await client.authenticate();
      client.resetRekeyCounters();
      client.startRuntimeDispatch();
      client.startKeepalive();
      client.startRekeyMonitor();
      client.events.emit("event", { type: "ready" } satisfies SshLiveClientEvent);
      return client;
    } catch (error) {
      transport?.destroy(error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
  }

  onEvent(listener: (event: SshLiveClientEvent) => void): () => void {
    this.events.on("event", listener);
    return () => this.events.off("event", listener);
  }

  async openShell(columns = 120, rows = 32): Promise<void> {
    const { channel, payload } = await this.withRuntimeGate(() => this.session.openSessionChannel());
    this.createChannelDelivery(channel.localId);
    try {
      const openResponse = this.waitForChannelOpen(channel.localId);
      await this.sendRuntimeAndWaitForChannel(channel.localId, payload, openResponse);

      const requests = this.session.buildPtyAndShellRequests(channel.localId, columns, rows);
      const ptyResponse = this.waitForChannelRequest(channel.localId, "PTY allocation failed.");
      await this.sendRuntimeAndWaitForChannel(channel.localId, requests.pty, ptyResponse);

      // The server may coalesce CHANNEL_SUCCESS and the first prompt DATA.
      // Install and activate the terminal consumer before sending "shell".
      this.terminalChannel = channel.localId;
      this.markChannelConsumerReady(channel.localId);
      const shellResponse = this.waitForChannelRequest(channel.localId, "Shell request failed.");
      await this.sendRuntimeAndWaitForChannel(channel.localId, requests.shell, shellResponse);
      if (this.terminalChannel !== channel.localId) {
        throw new Error("SSH shell channel closed while it was opening.");
      }
    } catch (error) {
      if (this.terminalChannel === channel.localId) {
        this.terminalChannel = undefined;
      }
      this.deleteChannelDelivery(channel.localId);
      await this.abortChannel(channel.localId);
      throw error;
    }
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
      await this.sendRuntimePayload(this.session.buildChannelEof(localChannel));
    } catch {
      // Shell channel may already be closed by the server.
    }
    try {
      await this.sendRuntimePayload(this.session.buildChannelClose(localChannel));
    } catch {
      // Shell channel may already be closed by the server.
    }
    this.deleteChannelDelivery(localChannel);
    this.rejectChannelWaiters(localChannel, new Error(`SSH channel ${localChannel} was closed.`));
  }

  async resizePty(columns: number, rows: number): Promise<void> {
    if (this.terminalChannel === undefined) {
      throw new Error("SSH shell channel is not open.");
    }
    await this.sendRuntimePayload(this.session.buildWindowChange(this.terminalChannel, columns, rows));
  }

  async openDirectTcpIpChannel(target: DirectTcpIpTarget, originator: { address: string; port: number }): Promise<DirectTcpIpChannel> {
    const { channel, payload } = await this.withRuntimeGate(() =>
      this.session.openDirectTcpIpChannel({
        hostToConnect: target.host,
        portToConnect: target.port,
        originatorIpAddress: originator.address,
        originatorPort: originator.port
      })
    );
    const delivery = this.createChannelDelivery(channel.localId);
    try {
      const openResponse = this.waitForChannelOpen(channel.localId);
      await this.sendRuntimeAndWaitForChannel(channel.localId, payload, openResponse);
    } catch (error) {
      this.deleteChannelDelivery(channel.localId);
      await this.abortChannel(channel.localId);
      throw error;
    }
    return new SshDirectTcpIpChannel(
      channel.localId,
      delivery.emitter,
      this,
      () => this.scheduleChannelConsumerReady(channel.localId)
    );
  }

  async writeDirectChannel(localChannel: number, data: Buffer): Promise<void> {
    await this.writeChannelDataFlowControlled(localChannel, data);
  }

  async closeDirectChannel(localChannel: number, eofAlreadySent = false): Promise<void> {
    this.markActivity();
    if (!eofAlreadySent) {
      try {
        await this.sendRuntimePayload(this.session.buildChannelEof(localChannel));
      } catch {
        // Channel may already be closed by the server.
      }
    }
    try {
      await this.sendRuntimePayload(this.session.buildChannelClose(localChannel));
    } catch {
      // Channel may already be closed by the server.
    }
    this.deleteChannelDelivery(localChannel);
    this.rejectChannelWaiters(localChannel, new Error(`SSH channel ${localChannel} was closed.`));
  }

  async endDirectChannel(localChannel: number): Promise<void> {
    this.markActivity();
    await this.sendRuntimePayload(this.session.buildChannelEof(localChannel));
  }

  async acknowledgeDirectChannelData(localChannel: number, bytes: number): Promise<void> {
    const adjust = this.session.acknowledgeChannelData(localChannel, bytes);
    if (adjust) {
      await this.sendRuntimePayload(adjust);
    }
  }

  async checkTunnel(endpoint: string): Promise<void> {
    const target = parseEndpoint(endpoint);
    const channel = await this.openDirectTcpIpChannel(target, { address: "127.0.0.1", port: 0 });
    await channel.close();
  }

  sendKeepalive(): Promise<void> {
    if (this.keepalivePromise) {
      return this.keepalivePromise;
    }
    this.markActivity();
    const work = this.sendRuntimeAndWaitForGlobalResponse(encodeKeepaliveRequest(), this.operationTimeoutMs());
    this.keepalivePromise = work;
    void work.then(
      () => {
        if (this.keepalivePromise === work) {
          this.keepalivePromise = undefined;
          this.rescheduleMaintenance();
        }
      },
      () => {
        if (this.keepalivePromise === work) {
          this.keepalivePromise = undefined;
          this.rescheduleMaintenance();
        }
      }
    );
    return work;
  }

  async disconnect(description = "Client disconnect."): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.stopKeepalive();
    this.stopRekeyMonitor();
    const disconnectSent = await settlesSuccessfullyWithin(
      this.transport.sendOwned(encodeDisconnect(11, description)),
      GRACEFUL_DISCONNECT_TIMEOUT_MS
    );
    if (disconnectSent) {
      this.transport.close();
    } else {
      // Bulk traffic may legitimately use the long transport write deadline,
      // but application shutdown must not wait up to two minutes on a stalled
      // socket merely to send the courtesy disconnect packet.
      this.transport.destroy();
    }
    this.rejectWaiters(new Error("SSH client disconnected."));
    this.clearChannelDeliveries();
  }

  destroy(error?: Error): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.stopKeepalive();
    this.stopRekeyMonitor();
    this.transport.destroy(error);
    this.rejectWaiters(error ?? new Error("SSH client destroyed."));
    this.clearChannelDeliveries();
  }

  async rekey(): Promise<void> {
    if (!this.runtimeDispatchEnabled || this.closed) {
      throw new Error("SSH client is not ready for rekey.");
    }
    await this.beginRuntimeRekey();
  }

  private async performKex(serverKexInitPayload?: Buffer, runtimeRekey = false): Promise<void> {
    const start = this.session.startKex();
    if (runtimeRekey && serverKexInitPayload) {
      // The peer has already entered KEX. Hold any ordinary frames that were
      // queued locally but not yet written, and let only KEX packets proceed.
      this.transport.beginRuntimeKeyExchange();
    }
    await this.transport.sendOwned(start.clientKexInitPayload);
    if (runtimeRekey && !serverKexInitPayload) {
      // For a client-initiated rekey, KEXINIT stays behind all frames already
      // accepted into the ordered transport queue. Once written, activate the
      // barrier so nothing except KEX/NEWKEYS can follow under the old keys.
      this.transport.beginRuntimeKeyExchange();
    }

    const serverKexInit = serverKexInitPayload ?? await this.waitForPayload(
      (payload) => messageNumber(payload) === SSH_MSG_KEXINIT,
      this.operationTimeoutMs()
    );
    const kexInit = this.session.receiveServerKexInit(serverKexInit);
    if (kexInit.ignoreNextServerKexPacket) {
      // The peer advertised a speculative first KEX packet, but its first
      // algorithm choices did not win negotiation. Consume that packet before
      // arming the KEX_REPLY parser pause; otherwise a guessed message 31 would
      // be mistaken for the real reply and strand the parser barrier.
      await this.waitForPayload(() => true, this.operationTimeoutMs());
    }
    this.transport.pausePacketParsingAfter(31);
    await this.transport.sendOwned(kexInit.kexDhInitPayload);

    const kexReply = await this.waitForPayload((payload) => messageNumber(payload) === 31, this.operationTimeoutMs());
    const complete = this.session.completeKex(kexReply);
    const inbound: PacketProtectionConfig = {
      cipherName: kexInit.negotiated.encryptionServerToClient as PacketProtectionConfig["cipherName"],
      encryptionKey: complete.transportKeys.encryptionKeyServerToClient,
      initialIv: complete.transportKeys.initialIvServerToClient,
      macName: kexInit.negotiated.macServerToClient as PacketProtectionConfig["macName"],
      macKey: complete.transportKeys.integrityKeyServerToClient
    };
    const outbound: PacketProtectionConfig = {
      cipherName: kexInit.negotiated.encryptionClientToServer as PacketProtectionConfig["cipherName"],
      encryptionKey: complete.transportKeys.encryptionKeyClientToServer,
      initialIv: complete.transportKeys.initialIvClientToServer,
      macName: kexInit.negotiated.macClientToServer as PacketProtectionConfig["macName"],
      macKey: complete.transportKeys.integrityKeyClientToServer
    };
    this.transport.prepareInboundEncryption(inbound);
    await this.transport.sendOwned(complete.newKeysPayload);
    this.transport.enableOutboundEncryption(outbound);
    this.transport.resumePacketParsing();

    const newKeys = await this.waitForPayload((payload) => messageNumber(payload) === SSH_MSG_NEWKEYS, this.operationTimeoutMs());
    this.session.receiveNewKeys(newKeys);
    if (runtimeRekey) {
      this.transport.finishRuntimeKeyExchange();
    }
  }

  private async authenticate(): Promise<void> {
    await this.transport.sendOwned(this.session.requestUserAuthService());
    const serviceAccept = await this.waitForPayload((payload) => messageNumber(payload) === SSH_MSG_SERVICE_ACCEPT, this.operationTimeoutMs());
    this.session.receiveServiceAccept(serviceAccept);

    const errors: string[] = [];
    const diagnostics: string[] = [];
    if (this.options.privateKey) {
      try {
        const key = loadPrivateKey(this.options.privateKey, this.options.privateKeyPassphrase || undefined);
        await this.transport.sendOwned(
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
      await this.transport.sendOwned(this.session.buildPasswordAuth(this.options.username, this.options.password));
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
    const queued = this.takeAllQueuedPayloads();
    for (const payload of queued) {
      this.handleRuntimePayload(payload);
    }
  }

  private startKeepalive(): void {
    this.rescheduleMaintenance();
  }

  private stopKeepalive(): void {
    this.stopMaintenanceTimer();
  }

  private startRekeyMonitor(): void {
    this.rescheduleMaintenance();
  }

  private stopRekeyMonitor(): void {
    this.stopMaintenanceTimer();
  }

  private rescheduleMaintenance(): void {
    this.stopMaintenanceTimer();
    if (this.closed || !this.runtimeDispatchEnabled || this.rekeyPromise) {
      return;
    }

    const deadlines: number[] = [];
    const keepaliveIntervalMs = this.keepaliveIntervalMs();
    if (keepaliveIntervalMs > 0 && !this.keepalivePromise) {
      deadlines.push(this.lastActivityAt + keepaliveIntervalMs);
    }
    const rekeyIntervalMs = this.rekeyIntervalMs();
    if (rekeyIntervalMs > 0) {
      deadlines.push(this.lastRekeyAt + rekeyIntervalMs);
    }
    if (deadlines.length === 0) {
      // Byte-only rekey is checked synchronously on traffic, so an idle tunnel
      // does not need a periodic polling wakeup.
      return;
    }

    const delayMs = Math.min(MAX_TIMER_DELAY_MS, Math.max(1, Math.min(...deadlines) - Date.now()));
    this.maintenanceTimer = setTimeout(() => {
      this.maintenanceTimer = undefined;
      this.runMaintenance();
    }, delayMs);
    this.maintenanceTimer.unref();
  }

  private stopMaintenanceTimer(): void {
    if (!this.maintenanceTimer) {
      return;
    }
    clearTimeout(this.maintenanceTimer);
    this.maintenanceTimer = undefined;
  }

  private runMaintenance(): void {
    if (this.closed) {
      return;
    }
    this.maybeStartAutomaticRekey();
    if (this.rekeyPromise) {
      return;
    }

    const keepaliveIntervalMs = this.keepaliveIntervalMs();
    if (keepaliveIntervalMs > 0 && !this.keepalivePromise && Date.now() - this.lastActivityAt >= keepaliveIntervalMs) {
      void this.sendKeepalive().catch((error: unknown) => {
        const normalized = error instanceof Error ? error : new Error(String(error));
        this.events.emit("event", { type: "error", error: normalized } satisfies SshLiveClientEvent);
        this.destroy(normalized);
      });
    }
    this.rescheduleMaintenance();
  }

  private keepaliveIntervalMs(): number {
    return normalizedSshKeepaliveIntervalMs(this.options.keepaliveIntervalSec);
  }

  private rekeyIntervalMs(): number {
    const configuredIntervalMs = this.options.rekeyIntervalMs ?? DEFAULT_REKEY_INTERVAL_MS;
    if (configuredIntervalMs <= 0) {
      return 0;
    }
    return Number.isFinite(configuredIntervalMs) ? configuredIntervalMs : DEFAULT_REKEY_INTERVAL_MS;
  }

  private handleTransportEvent(event: SshPacketTransportEvent): void {
    if (event.type === "payload") {
      this.markActivity();
      if (messageNumber(event.payload) === SSH_MSG_DISCONNECT) {
        this.handlePeerDisconnect();
        return;
      }
      if (this.runtimeDispatchEnabled) {
        this.handleRuntimePayload(event.payload);
      } else {
        this.enqueuePayload(event.payload, MAX_PRE_AUTH_QUEUED_PAYLOADS, MAX_PRE_AUTH_QUEUED_BYTES);
        this.flushPayloadWaiters();
      }
      return;
    }
    if (event.type === "error") {
      if (this.closed) {
        return;
      }
      this.events.emit("event", { type: "error", error: event.error } satisfies SshLiveClientEvent);
      this.rejectWaiters(event.error);
      return;
    }
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.stopKeepalive();
    this.stopRekeyMonitor();
    this.rejectWaiters(new Error("SSH transport closed."));
    this.clearChannelDeliveries();
    this.events.emit("event", { type: "close" } satisfies SshLiveClientEvent);
  }

  private handleRuntimePayload(payload: Buffer): void {
    const number = messageNumber(payload);
    if (number === SSH_MSG_KEXINIT) {
      if (this.rekeyPromise) {
        this.enqueuePayload(payload, MAX_REKEY_QUEUED_PAYLOADS, MAX_REKEY_QUEUED_BYTES);
        this.flushPayloadWaiters();
      } else {
        void this.beginRuntimeRekey(payload);
      }
      return;
    }
    if (this.rekeyPromise) {
      this.enqueuePayload(payload, MAX_REKEY_QUEUED_PAYLOADS, MAX_REKEY_QUEUED_BYTES);
      this.flushPayloadWaiters();
      return;
    }
    this.dispatchRuntimePayload(payload);
    this.maybeStartAutomaticRekey();
  }

  private dispatchRuntimePayload(payload: Buffer): void {
    const number = messageNumber(payload);
    if (number === SSH_MSG_REQUEST_SUCCESS || number === SSH_MSG_REQUEST_FAILURE) {
      this.events.emit("global-response", number);
      return;
    }
    if (number === SSH_MSG_GLOBAL_REQUEST) {
      const request = decodeGlobalRequest(payload);
      if (request.wantReply) {
        void this.sendRuntimePayload(encodeRequestFailure()).catch((error: unknown) => this.handleFatalError(error));
      }
      return;
    }
    if (number === SSH_MSG_DISCONNECT) {
      this.handlePeerDisconnect();
      return;
    }
    if (isChannelMessage(number)) {
      const channelEvent = this.session.receiveChannelMessage(payload);
      if (channelEvent.windowAdjustPayload) {
        void this.sendRuntimePayload(channelEvent.windowAdjustPayload).catch((error: unknown) => this.handleFatalError(error));
      }
      if (channelEvent.responsePayload) {
        void this.sendRuntimePayload(channelEvent.responsePayload).catch((error: unknown) => this.handleFatalError(error));
      }
      this.emitChannelEvent(channelEvent);
    }
  }

  private handlePeerDisconnect(): void {
    if (this.closed) {
      return;
    }
    const error = new Error("SSH server disconnected.");
    this.closed = true;
    this.stopKeepalive();
    this.stopRekeyMonitor();
    this.transport.destroy(error);
    this.rejectWaiters(error);
    this.clearChannelDeliveries();
    this.events.emit("event", { type: "close" } satisfies SshLiveClientEvent);
  }

  private emitChannelEvent(event: ChannelEvent): void {
    this.events.emit("channel-event", event);
    this.flushChannelWaiters(event);
    if (event.localChannel === undefined) {
      return;
    }
    const delivery = this.channelDeliveries.get(event.localChannel);
    if (!delivery) {
      return;
    }
    if (event.type !== "data" && event.type !== "extended-data" && event.type !== "eof" && event.type !== "close") {
      return;
    }
    if (!delivery.ready) {
      this.bufferChannelDelivery(event.localChannel, delivery, event);
      return;
    }
    this.deliverChannelEvent(event.localChannel, delivery, event);
  }

  private deliverChannelEvent(localChannel: number, delivery: ChannelDeliveryState, event: ChannelEvent): void {
    if ((event.type === "data" || event.type === "extended-data") && event.data && event.data.length > 0) {
      if (event.type === "data") {
        delivery.emitter.emit("data", event.data);
      }
      if (localChannel === this.terminalChannel) {
        this.events.emit("event", {
          type: "terminal-data",
          data: event.data,
          stream: event.type === "extended-data" ? "stderr" : "stdout"
        } satisfies SshLiveClientEvent);
      }
      // Extended data is meaningful for session channels (normally stderr)
      // but must never be injected into a direct-tcpip byte stream. In both
      // cases it consumed the SSH receive window and therefore must be acked.
      if ((localChannel === this.terminalChannel || event.type === "extended-data") && this.session.getChannel(localChannel)) {
        const adjust = this.session.acknowledgeChannelData(localChannel, event.data.length);
        if (adjust) {
          void this.sendRuntimePayload(adjust).catch((error: unknown) => this.handleFatalError(error));
        }
      }
      return;
    }
    if (event.type === "eof") {
      delivery.emitter.emit("end");
      if (localChannel === this.terminalChannel) {
        delivery.emitter.emit("close");
        this.deleteChannelDelivery(localChannel);
        this.terminalChannel = undefined;
        this.events.emit("event", { type: "terminal-close" } satisfies SshLiveClientEvent);
        void this.abortChannel(localChannel);
      }
      return;
    }
    if (event.type === "close") {
      delivery.emitter.emit("close");
      this.deleteChannelDelivery(localChannel);
      if (localChannel === this.terminalChannel) {
        this.terminalChannel = undefined;
        this.events.emit("event", { type: "terminal-close" } satisfies SshLiveClientEvent);
      }
    }
  }

  private createChannelDelivery(localChannel: number): ChannelDeliveryState {
    if (this.channelDeliveries.has(localChannel)) {
      throw new Error(`SSH channel ${localChannel} delivery already exists.`);
    }
    const delivery: ChannelDeliveryState = {
      emitter: new EventEmitter(),
      ready: false,
      readyScheduled: false,
      pending: [],
      pendingDataBytes: 0
    };
    this.channelDeliveries.set(localChannel, delivery);
    return delivery;
  }

  private bufferChannelDelivery(localChannel: number, delivery: ChannelDeliveryState, event: ChannelEvent): void {
    const dataBytes = event.type === "data" || event.type === "extended-data" ? event.data?.length ?? 0 : 0;
    if (
      delivery.pending.length >= MAX_PENDING_CHANNEL_EVENTS ||
      delivery.pendingDataBytes + dataBytes > MAX_PENDING_CHANNEL_DATA_BYTES ||
      this.totalPendingChannelDataBytes + dataBytes > MAX_TOTAL_PENDING_CHANNEL_DATA_BYTES
    ) {
      throw new Error(`SSH channel ${localChannel} consumer-ready buffer limit exceeded.`);
    }
    delivery.pending.push(event);
    delivery.pendingDataBytes += dataBytes;
    this.totalPendingChannelDataBytes += dataBytes;
  }

  private scheduleChannelConsumerReady(localChannel: number): void {
    const delivery = this.channelDeliveries.get(localChannel);
    if (!delivery || delivery.ready || delivery.readyScheduled) {
      return;
    }
    delivery.readyScheduled = true;
    queueMicrotask(() => {
      try {
        this.markChannelConsumerReady(localChannel);
      } catch (error) {
        this.handleFatalError(error);
      }
    });
  }

  private markChannelConsumerReady(localChannel: number): void {
    const delivery = this.channelDeliveries.get(localChannel);
    if (!delivery || delivery.ready) {
      return;
    }
    delivery.ready = true;
    delivery.readyScheduled = false;
    const pending = delivery.pending.splice(0);
    this.totalPendingChannelDataBytes = Math.max(0, this.totalPendingChannelDataBytes - delivery.pendingDataBytes);
    delivery.pendingDataBytes = 0;
    for (const event of pending) {
      this.deliverChannelEvent(localChannel, delivery, event);
    }
  }

  private deleteChannelDelivery(localChannel: number): void {
    const delivery = this.channelDeliveries.get(localChannel);
    if (!delivery) {
      return;
    }
    this.totalPendingChannelDataBytes = Math.max(0, this.totalPendingChannelDataBytes - delivery.pendingDataBytes);
    delivery.pending.length = 0;
    delivery.pendingDataBytes = 0;
    this.channelDeliveries.delete(localChannel);
  }

  private clearChannelDeliveries(): void {
    for (const localChannel of this.channelDeliveries.keys()) {
      this.deleteChannelDelivery(localChannel);
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

  private async sendRuntimeAndWaitForChannel(
    localChannel: number,
    payload: Buffer,
    response: Promise<void>
  ): Promise<void> {
    try {
      await Promise.all([this.sendRuntimePayload(payload), response]);
    } catch (error) {
      const normalized = error instanceof Error ? error : new Error(String(error));
      this.rejectChannelWaiters(localChannel, normalized);
      throw normalized;
    }
  }

  private async sendRuntimeAndWaitForGlobalResponse(payload: Buffer, timeoutMs: number): Promise<void> {
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
      const onFailure = (error: Error): void => {
        cleanup();
        reject(error);
      };
      const cleanup = (): void => {
        clearTimeout(timer);
        this.events.off("global-response", onResponse);
        this.events.off("global-error", onFailure);
      };
      this.events.on("global-response", onResponse);
      this.events.on("global-error", onFailure);
      void this.sendRuntimePayload(payload).catch((error: unknown) => {
        cleanup();
        reject(error instanceof Error ? error : new Error(String(error)));
      });
    });
  }

  private waitForPayload(predicate: (payload: Buffer) => boolean, timeoutMs: number): Promise<Buffer> {
    const queuedIndex = this.payloadQueue.findIndex(predicate);
    if (queuedIndex >= 0) {
      return Promise.resolve(this.takeQueuedPayload(queuedIndex));
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
      const payload = this.takeQueuedPayload(queuedIndex);
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
      const { payloads, bytesWritten } = await this.withRuntimeGate(
        () => this.session.buildChannelDataFrames(localChannel, data.subarray(offset))
      );
      if (payloads.length > 0) {
        this.markActivity();
        for (const payload of payloads) {
          await this.sendChannelRuntimePayload(localChannel, payload);
        }
        offset += bytesWritten;
        this.maybeStartAutomaticRekey();
        continue;
      }
      await this.waitForChannelWriteWindow(localChannel);
    }
  }

  private async waitForChannelWriteWindow(localChannel: number): Promise<void> {
    const channel = this.session.getChannel(localChannel);
    if (!channel) {
      throw new Error(`SSH channel ${localChannel} closed before queued data was written.`);
    }
    if (channel.remoteWindow > 0) {
      return;
    }
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
    this.events.emit("global-error", error);
  }

  private enqueuePayload(payload: Buffer, maximumPayloads: number, maximumBytes: number): void {
    if (this.payloadQueue.length >= maximumPayloads || this.payloadQueueBytes + payload.length > maximumBytes) {
      throw new Error(`SSH queued payload limit exceeded (${maximumPayloads} packets / ${maximumBytes} bytes).`);
    }
    this.payloadQueue.push(payload);
    this.payloadQueueBytes += payload.length;
  }

  private takeQueuedPayload(index: number): Buffer {
    const [payload] = this.payloadQueue.splice(index, 1);
    this.payloadQueueBytes -= payload.length;
    return payload;
  }

  private takeAllQueuedPayloads(): Buffer[] {
    const payloads = this.payloadQueue.splice(0);
    this.payloadQueueBytes = 0;
    return payloads;
  }

  private async sendRuntimePayload(payload: Buffer): Promise<void> {
    await this.withRuntimeGate(() => this.transport.sendOwned(payload));
  }

  private async abortChannel(localChannel: number): Promise<void> {
    const closePayload = this.session.abortChannel(localChannel);
    if (!closePayload || this.closed) {
      return;
    }
    await this.sendRuntimePayload(closePayload).catch(() => undefined);
  }

  private async sendChannelRuntimePayload(localChannel: number, payload: Buffer): Promise<void> {
    await this.withRuntimeGate(() => {
      if (!this.session.getChannel(localChannel)) {
        throw new Error(`SSH channel ${localChannel} closed before queued data was written.`);
      }
      return this.transport.sendOwned(payload);
    });
  }

  private async withRuntimeGate<T>(action: () => T | Promise<T>): Promise<T> {
    while (this.rekeyPromise) {
      await this.rekeyPromise;
    }
    // No event callback can interleave between this check and invoking action,
    // so a payload is either queued before KEXINIT or held until rekey ends.
    return action();
  }

  private beginRuntimeRekey(serverKexInitPayload?: Buffer): Promise<void> {
    if (this.rekeyPromise) {
      if (serverKexInitPayload) {
        this.enqueuePayload(serverKexInitPayload, MAX_REKEY_QUEUED_PAYLOADS, MAX_REKEY_QUEUED_BYTES);
        this.flushPayloadWaiters();
      }
      return this.rekeyPromise;
    }
    if (this.closed || this.session.getPhase() !== "authenticated") {
      return Promise.reject(new Error("SSH session is not ready for runtime rekey."));
    }

    const work = this.performKex(serverKexInitPayload, true);
    this.rekeyPromise = work;
    this.rescheduleMaintenance();
    void work.then(
      () => {
        if (this.rekeyPromise !== work) {
          return;
        }
        this.rekeyPromise = undefined;
        this.resetRekeyCounters();
        const queued = this.takeAllQueuedPayloads();
        for (const payload of queued) {
          this.handleRuntimePayload(payload);
        }
        this.rescheduleMaintenance();
      },
      (error: unknown) => {
        if (this.rekeyPromise === work) {
          this.rekeyPromise = undefined;
        }
        this.handleFatalError(error);
      }
    );
    return work;
  }

  private maybeStartAutomaticRekey(): void {
    if (this.closed || this.rekeyPromise || !this.runtimeDispatchEnabled || this.session.getPhase() !== "authenticated") {
      return;
    }
    const intervalLimit = this.rekeyIntervalMs();
    const byteLimit = this.options.rekeyAfterBytes ?? DEFAULT_REKEY_AFTER_BYTES;
    const transferred = this.transport.getTransferredBytes();
    const totalBytes = transferred.sent + transferred.received;
    const bytesExceeded = byteLimit > 0 && totalBytes - this.rekeyBytesBaseline >= byteLimit;
    const timeExceeded = intervalLimit > 0 && Date.now() - this.lastRekeyAt >= intervalLimit;
    if (bytesExceeded || timeExceeded) {
      void this.beginRuntimeRekey();
    }
  }

  private resetRekeyCounters(): void {
    const transferred = this.transport.getTransferredBytes();
    this.rekeyBytesBaseline = transferred.sent + transferred.received;
    this.lastRekeyAt = Date.now();
  }

  private handleFatalError(error: unknown): void {
    const normalized = error instanceof Error ? error : new Error(String(error));
    this.events.emit("event", { type: "error", error: normalized } satisfies SshLiveClientEvent);
    this.destroy(normalized);
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
  private endRequested = false;
  private eofSent = false;
  private endPromise: Promise<void> | undefined;
  private closePromise: Promise<void> | undefined;
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly localChannel: number,
    private readonly emitter: EventEmitter,
    private readonly client: SshLiveClient,
    private readonly scheduleConsumerReady: () => void
  ) {}

  async write(data: Buffer): Promise<void> {
    if (this.closed || this.endRequested) {
      throw new Error("Direct TCP channel is closed.");
    }
    const write = this.writeQueue.then(() => {
      if (this.closed || this.endRequested) {
        throw new Error("Direct TCP channel is closed.");
      }
      return this.client.writeDirectChannel(this.localChannel, data);
    });
    this.writeQueue = write.catch(() => undefined);
    await write;
  }

  end(): Promise<void> {
    if (this.closed) {
      return Promise.resolve();
    }
    if (this.endPromise) {
      return this.endPromise;
    }
    this.endRequested = true;
    this.endPromise = (async () => {
      await this.writeQueue;
      await this.client.endDirectChannel(this.localChannel);
      this.eofSent = true;
    })();
    return this.endPromise;
  }

  async acknowledgeData(bytes: number): Promise<void> {
    if (this.closed) {
      return;
    }
    await this.client.acknowledgeDirectChannelData(this.localChannel, bytes);
  }

  close(): Promise<void> {
    if (this.closePromise) {
      return this.closePromise;
    }
    if (this.closed) {
      return Promise.resolve();
    }
    this.closed = true;
    this.closePromise = (async () => {
      await this.endPromise?.catch(() => undefined);
      await this.writeQueue.catch(() => undefined);
      await this.client.closeDirectChannel(this.localChannel, this.eofSent);
    })();
    return this.closePromise;
  }

  onData(listener: (data: Buffer) => void): () => void {
    this.emitter.on("data", listener);
    this.scheduleConsumerReady();
    return () => this.emitter.off("data", listener);
  }

  onEnd(listener: () => void): () => void {
    this.emitter.on("end", listener);
    this.scheduleConsumerReady();
    return () => this.emitter.off("end", listener);
  }

  onClose(listener: () => void): () => void {
    const wrapped = (): void => {
      this.closed = true;
      listener();
    };
    this.emitter.on("close", wrapped);
    this.scheduleConsumerReady();
    return () => this.emitter.off("close", wrapped);
  }

  onError(listener: (error: Error) => void): () => void {
    this.emitter.on("error", listener);
    this.scheduleConsumerReady();
    return () => this.emitter.off("error", listener);
  }
}

export function normalizedSshKeepaliveIntervalMs(configuredIntervalSec: number | undefined): number {
  if (!Number.isFinite(configuredIntervalSec) || Number(configuredIntervalSec) <= 0) {
    return 0;
  }
  return Math.max(60, Number(configuredIntervalSec)) * 1000;
}

export function sshKernelKeepaliveInitialDelayMs(configuredIntervalSec: number | undefined): number {
  const applicationIntervalMs = normalizedSshKeepaliveIntervalMs(configuredIntervalSec);
  return Math.max(120_000, applicationIntervalMs * 2);
}

function isChannelMessage(number: number): boolean {
  return (
    number === SSH_MSG_CHANNEL_OPEN ||
    number === SSH_MSG_CHANNEL_OPEN_CONFIRMATION ||
    number === SSH_MSG_CHANNEL_OPEN_FAILURE ||
    number === SSH_MSG_CHANNEL_WINDOW_ADJUST ||
    number === SSH_MSG_CHANNEL_DATA ||
    number === SSH_MSG_CHANNEL_EXTENDED_DATA ||
    number === SSH_MSG_CHANNEL_EOF ||
    number === SSH_MSG_CHANNEL_CLOSE ||
    number === SSH_MSG_CHANNEL_SUCCESS ||
    number === SSH_MSG_CHANNEL_FAILURE ||
    number === SSH_MSG_CHANNEL_REQUEST
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

async function settlesSuccessfullyWithin(promise: Promise<unknown>, timeoutMs: number): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise.then(
        () => true,
        () => false
      ),
      new Promise<boolean>((resolve) => {
        timer = setTimeout(() => resolve(false), timeoutMs);
        timer.unref();
      })
    ]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}
