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
  directTcpIpOpenTimeoutMs?: number;
  keepaliveIntervalSec?: number;
  /**
   * How long a keepalive may go unanswered before the transport is declared
   * dead. Any packet from the server during the wait counts as an answer, the
   * way OpenSSH's ServerAliveCountMax treats received data, so a reply queued
   * behind a busy download does not tear a healthy session down.
   */
  keepaliveTimeoutMs?: number;
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
  detachAbort?: () => void;
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
/**
 * OpenSSH declares a peer dead after ServerAliveInterval x ServerAliveCountMax
 * (15 s x 3) without any received data. The keepalive here fires no more often
 * than once a minute, so the wait for its answer is the part that decides how
 * quickly a half-open socket is noticed; half a minute keeps that under two
 * minutes end to end while still tolerating a slow link.
 */
export const DEFAULT_KEEPALIVE_TIMEOUT_MS = 30_000;
/**
 * A probe issued because the machine just woke up or changed networks. The
 * link is either back or it is not; there is nothing to gain from waiting the
 * full keepalive timeout before rebuilding a session that will not answer.
 */
export const LIVENESS_PROBE_TIMEOUT_MS = 15_000;
/**
 * Sending for this long without hearing anything back is the earliest sign
 * of a half-open socket that does not depend on the keepalive cadence: a
 * healthy server answers a channel open within a round trip and adjusts the
 * window while data flows. The check costs one keepalive per silent window
 * and nothing at all while the peer is talking.
 */
export const SILENT_SEND_PROBE_DELAY_MS = 10_000;

type KeepaliveOutcome = "answered" | "abandoned";

type KeepaliveRequest = {
  /**
   * Settles "answered" when the server replies, "abandoned" when a waiter gave
   * up on the reply because other traffic proved the peer alive, and rejects
   * when the client dies first.
   */
  promise: Promise<KeepaliveOutcome>;
  /**
   * Resolves once the request has actually been written to the socket. A
   * deadline measured from before that would count a local upload backlog
   * against the server.
   */
  written: Promise<void>;
  abandon: () => void;
};

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
  private keepaliveRequest: KeepaliveRequest | undefined;
  private rekeyPromise: Promise<void> | undefined;
  private rekeyBytesBaseline = 0;
  private lastRekeyAt = Date.now();
  /**
   * When the server last sent us anything. Keepalives are scheduled from this
   * alone: bytes we write prove nothing about the peer, and a proxy client
   * retrying through a dead tunnel would otherwise keep postponing the one
   * probe that could notice it.
   */
  private lastInboundAt = Date.now();
  /** Set by a runtime write, cleared by the next inbound packet: one-way traffic while true. */
  private unansweredOutbound = false;
  private silentSendProbeTimer: NodeJS.Timeout | undefined;

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

  /** The address this session's TCP socket is connected to. */
  get serverAddress(): string | undefined {
    return this.transport.remoteAddress;
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

  async openDirectTcpIpChannel(
    target: DirectTcpIpTarget,
    originator: { address: string; port: number },
    signal?: AbortSignal
  ): Promise<DirectTcpIpChannel> {
    if (signal?.aborted) {
      throw channelOpenCancelledError();
    }
    const { channel, payload } = await this.withRuntimeGate(() => {
      // The runtime gate may wait for a rekey. Re-check cancellation after it
      // opens so a local client that already disconnected cannot allocate and
      // enqueue a now-orphaned channel.
      if (signal?.aborted) {
        throw channelOpenCancelledError();
      }
      return this.session.openDirectTcpIpChannel({
        hostToConnect: target.host,
        portToConnect: target.port,
        originatorIpAddress: originator.address,
        originatorPort: originator.port
      });
    });
    // The action above runs before the async gate continuation resumes. A local
    // socket can close in that gap, so check once more before queueing anything.
    if (signal?.aborted) {
      await this.abortChannel(channel.localId);
      throw channelOpenCancelledError();
    }
    const channelOpenController = new AbortController();
    const forwardAbort = (): void => channelOpenController.abort();
    signal?.addEventListener("abort", forwardAbort, { once: true });
    if (signal?.aborted) {
      channelOpenController.abort();
    }
    const delivery = this.createChannelDelivery(channel.localId);
    const openStartedAt = Date.now();
    try {
      const openResponse = this.waitForChannelOpen(
        channel.localId,
        this.directTcpIpOpenTimeoutMs(),
        channelOpenController.signal
      );
      await this.sendRuntimeAndWaitForChannel(
        channel.localId,
        payload,
        openResponse,
        channelOpenController.signal
      );
    } catch (error) {
      // This also removes a CHANNEL_OPEN that is still waiting in the transport
      // queue. A frame that has already started remains on the wire and its late
      // confirmation is handled as an abandoned channel by session-state.
      channelOpenController.abort();
      this.deleteChannelDelivery(channel.localId);
      await this.abortChannel(channel.localId);
      if (isChannelTimeoutError(error)) {
        this.suspectTransportAfterChannelTimeout(openStartedAt);
      }
      throw error;
    } finally {
      signal?.removeEventListener("abort", forwardAbort);
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
    await this.sendRuntimePayload(this.session.buildChannelEof(localChannel));
  }

  async acknowledgeDirectChannelData(localChannel: number, bytes: number): Promise<void> {
    const adjust = this.session.acknowledgeChannelData(localChannel, bytes);
    if (adjust) {
      await this.sendRuntimeReply(adjust);
    }
  }

  /**
   * Sends a keepalive unless one is already in flight and waits for the server
   * to show signs of life within `timeoutMs`.
   *
   * The answer to the global request is the expected sign, but any packet that
   * arrives while we wait is accepted as one: an answer can be queued behind
   * channel data, and a peer that is still sending is not dead. Only a wait
   * with nothing received at all rejects, which is the signal the owner uses
   * to tear the session down.
   */
  sendKeepalive(timeoutMs = this.keepaliveTimeoutMs()): Promise<void> {
    if (this.closed) {
      return Promise.reject(new Error("SSH client is closed."));
    }
    const request = this.keepaliveRequest ?? this.startKeepaliveRequest();
    return this.awaitKeepaliveEvidence(request, timeoutMs);
  }

  /**
   * Asks "is this session still alive?" and answers quickly.
   *
   * Meant for the moments when silence proves nothing - right after the
   * machine wakes up or its network changes - so the owner does not have to
   * wait for the regular keepalive cadence to learn that the socket died while
   * the lid was closed. A failed probe destroys the client and reports the
   * failure through the ordinary `error` event, exactly as a regular keepalive
   * timeout does, so callers may fire and forget.
   */
  async probeLiveness(timeoutMs = LIVENESS_PROBE_TIMEOUT_MS): Promise<void> {
    if (this.closed) {
      throw new Error("SSH client is closed.");
    }
    try {
      // Always a fresh request: one that has been pending since before the
      // wake may already have evidence from before it, which is exactly what a
      // probe must not be answered with.
      await this.awaitKeepaliveEvidence(this.startKeepaliveRequest(), timeoutMs);
    } catch (error) {
      this.failFromKeepalive(error);
      throw error;
    }
  }

  private startKeepaliveRequest(): KeepaliveRequest {
    let abandon: () => void = () => undefined;
    let written!: Promise<void>;
    const promise = new Promise<KeepaliveOutcome>((resolve, reject) => {
      const onResponse = (): void => {
        cleanup();
        resolve("answered");
      };
      const onFailure = (error: Error): void => {
        cleanup();
        reject(error);
      };
      const cleanup = (): void => {
        this.events.off("global-response", onResponse);
        this.events.off("global-error", onFailure);
      };
      abandon = () => {
        cleanup();
        resolve("abandoned");
      };
      this.events.on("global-response", onResponse);
      this.events.on("global-error", onFailure);
      written = this.sendRuntimeReply(encodeKeepaliveRequest());
      written.catch((error: unknown) => {
        cleanup();
        reject(error instanceof Error ? error : new Error(String(error)));
      });
    });
    const request: KeepaliveRequest = { promise, written, abandon };
    this.keepaliveRequest = request;
    void promise.then(
      () => this.finishKeepaliveRequest(request),
      () => this.finishKeepaliveRequest(request)
    );
    return request;
  }

  private finishKeepaliveRequest(request: KeepaliveRequest): void {
    if (this.keepaliveRequest === request) {
      this.keepaliveRequest = undefined;
      this.rescheduleMaintenance();
    }
  }

  /**
   * Waits up to `timeoutMs` for the server to prove it is alive: the reply to
   * `request`, or any other packet received after this wait began.
   */
  private awaitKeepaliveEvidence(initialRequest: KeepaliveRequest, timeoutMs: number): Promise<void> {
    let waitingSince = Date.now();
    return new Promise<void>((resolve, reject) => {
      let settled = false;
      let current = initialRequest;
      let timer: NodeJS.Timeout | undefined;
      const hasEvidence = (): boolean => this.lastInboundAt >= waitingSince;
      const finish = (error?: Error): void => {
        if (settled) {
          return;
        }
        settled = true;
        if (timer) {
          clearTimeout(timer);
        }
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      };
      const timedOut = (): void => {
        if (settled) {
          return;
        }
        if (hasEvidence()) {
          // Something arrived while we waited, so the peer is alive even though
          // the reply itself has not. Drop the stale request instead of letting
          // its age excuse every later wait as well.
          this.abandonKeepaliveRequest(current);
          finish();
          return;
        }
        // The timer phase runs before this turn's socket reads. Look once more
        // after them, so a reply that is already in the receive buffer is not
        // mistaken for silence.
        setImmediate(() => {
          if (settled) {
            return;
          }
          if (hasEvidence()) {
            this.abandonKeepaliveRequest(current);
            finish();
            return;
          }
          finish(
            new Error(
              `SSH keepalive timed out: nothing received from the server for ${Math.round((Date.now() - this.lastInboundAt) / 1000)} s.`
            )
          );
        });
      };
      // The deadline starts when the request is on the wire: a keepalive
      // queued behind an upload backlog has not asked the server anything yet.
      initialRequest.written.then(
        () => {
          if (settled) {
            return;
          }
          waitingSince = Math.max(waitingSince, Date.now());
          timer = setTimeout(timedOut, Math.max(1, timeoutMs));
          timer.unref();
        },
        (error: unknown) => finish(error instanceof Error ? error : new Error(String(error)))
      );
      const attach = (request: KeepaliveRequest): void => {
        current = request;
        request.promise.then(
          (outcome) => {
            if (settled) {
              return;
            }
            if (outcome === "answered" || hasEvidence()) {
              finish();
              return;
            }
            // Another waiter gave the request up on evidence older than this
            // wait. This one has seen nothing yet, so it needs a request of
            // its own; its deadline stays where it was.
            if (this.closed) {
              finish(new Error("SSH client is closed."));
              return;
            }
            attach(this.keepaliveRequest ?? this.startKeepaliveRequest());
          },
          (error: unknown) => finish(error instanceof Error ? error : new Error(String(error)))
        );
      };
      attach(initialRequest);
    });
  }

  private abandonKeepaliveRequest(request: KeepaliveRequest): void {
    if (this.keepaliveRequest === request) {
      this.keepaliveRequest = undefined;
      request.abandon();
      this.rescheduleMaintenance();
      return;
    }
    request.abandon();
  }

  private failFromKeepalive(error: unknown): void {
    if (this.closed) {
      return;
    }
    const normalized = error instanceof Error ? error : new Error(String(error));
    this.events.emit("event", { type: "error", error: normalized } satisfies SshLiveClientEvent);
    this.destroy(normalized);
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
    this.clearChannelDeliveries(new Error("SSH client disconnected."));
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
    this.clearChannelDeliveries(error ?? new Error("SSH client destroyed."));
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
    this.stopSilentSendProbe();
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
    if (keepaliveIntervalMs > 0 && !this.keepaliveRequest) {
      deadlines.push(this.lastInboundAt + keepaliveIntervalMs);
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
    if (keepaliveIntervalMs > 0 && !this.keepaliveRequest && Date.now() - this.lastInboundAt >= keepaliveIntervalMs) {
      void this.sendKeepalive().catch((error: unknown) => this.failFromKeepalive(error));
    }
    this.rescheduleMaintenance();
  }

  private keepaliveIntervalMs(): number {
    return normalizedSshKeepaliveIntervalMs(this.options.keepaliveIntervalSec);
  }

  private keepaliveTimeoutMs(): number {
    const configured = this.options.keepaliveTimeoutMs;
    if (configured !== undefined && Number.isFinite(configured) && configured > 0) {
      return configured;
    }
    return DEFAULT_KEEPALIVE_TIMEOUT_MS;
  }

  /**
   * A direct-tcpip open that timed out while the server sent nothing at all
   * is more likely a dead transport than a slow target. Ask, instead of
   * leaving every later proxy connection to time out the same way until the
   * regular keepalive gets around to it.
   */
  private suspectTransportAfterChannelTimeout(openStartedAt: number): void {
    if (this.closed || this.keepaliveRequest || this.keepaliveIntervalMs() <= 0) {
      return;
    }
    if (this.lastInboundAt > openStartedAt) {
      // The server spoke while the open was pending; the target was slow.
      return;
    }
    void this.sendKeepalive(LIVENESS_PROBE_TIMEOUT_MS).catch((error: unknown) => this.failFromKeepalive(error));
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
      this.lastInboundAt = Date.now();
      this.unansweredOutbound = false;
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
    this.clearChannelDeliveries(new Error("SSH transport closed."));
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
        void this.sendRuntimeReply(encodeRequestFailure()).catch((error: unknown) => this.handleFatalError(error));
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
        void this.sendRuntimeReply(channelEvent.windowAdjustPayload).catch((error: unknown) => this.handleFatalError(error));
      }
      if (channelEvent.responsePayload) {
        void this.sendRuntimeReply(channelEvent.responsePayload).catch((error: unknown) => this.handleFatalError(error));
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
    this.clearChannelDeliveries(error);
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
          void this.sendRuntimeReply(adjust).catch((error: unknown) => this.handleFatalError(error));
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

  /**
   * Ends every channel the session still had. The consumers of a channel -
   * the local proxy sockets above all - learn that their stream is gone only
   * from these events; without them an idle WebSocket or long poll would sit
   * on a dead channel for as long as it stays quiet.
   */
  private clearChannelDeliveries(reason?: Error): void {
    for (const [localChannel, delivery] of [...this.channelDeliveries]) {
      this.deleteChannelDelivery(localChannel);
      if (reason && delivery.emitter.listenerCount("error") > 0) {
        delivery.emitter.emit("error", reason);
      } else {
        delivery.emitter.emit("close");
      }
    }
  }

  private async waitForChannelOpen(
    localChannel: number,
    timeoutMs = this.operationTimeoutMs(),
    signal?: AbortSignal
  ): Promise<void> {
    const event = await this.waitForChannelEvent(
      localChannel,
      (candidate) => candidate.type === "open-confirmed" || candidate.type === "open-failed",
      timeoutMs,
      signal
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
    response: Promise<void>,
    signal?: AbortSignal
  ): Promise<void> {
    try {
      await Promise.all([this.sendRuntimePayload(payload, signal), response]);
    } catch (error) {
      const normalized = error instanceof Error ? error : new Error(String(error));
      this.rejectChannelWaiters(localChannel, normalized);
      throw normalized;
    }
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

  private waitForChannelEvent(
    localChannel: number,
    predicate: (event: ChannelEvent) => boolean,
    timeoutMs: number,
    signal?: AbortSignal
  ): Promise<ChannelEvent> {
    return new Promise<ChannelEvent>((resolve, reject) => {
      const waiter: ChannelWaiter = {
        localChannel,
        predicate,
        resolve,
        reject,
        timer: setTimeout(() => {
          this.removeChannelWaiter(waiter);
          reject(new Error(`Timed out waiting for SSH channel ${localChannel}.`));
        }, timeoutMs)
      };
      waiter.timer.unref();
      if (signal) {
        const onAbort = (): void => {
          this.removeChannelWaiter(waiter);
          reject(channelOpenCancelledError());
        };
        if (signal.aborted) {
          clearTimeout(waiter.timer);
          reject(channelOpenCancelledError());
          return;
        }
        signal.addEventListener("abort", onAbort, { once: true });
        waiter.detachAbort = () => signal.removeEventListener("abort", onAbort);
      }
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
      this.removeChannelWaiter(waiter);
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
      waiter.detachAbort?.();
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

  private async sendRuntimePayload(payload: Buffer, signal?: AbortSignal): Promise<void> {
    await this.withRuntimeGate(() => {
      this.noteOutbound();
      return this.transport.sendOwned(payload, signal);
    });
  }

  /**
   * A packet that answers something the server sent (a window adjust, a reply
   * to its global request, our own keepalive). Unlike a write of our own it
   * expects nothing back, so it must not arm the silent-send check.
   */
  private async sendRuntimeReply(payload: Buffer): Promise<void> {
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
      this.noteOutbound();
      return this.transport.sendOwned(payload);
    });
  }

  /**
   * Records a runtime write and, unless one is already pending, arms the
   * silent-send check: if nothing has arrived by the time it fires while we
   * kept sending, the peer is asked directly whether it is still there.
   */
  private noteOutbound(): void {
    this.unansweredOutbound = true;
    if (this.closed || this.silentSendProbeTimer || this.keepaliveRequest || this.keepaliveIntervalMs() <= 0) {
      return;
    }
    this.silentSendProbeTimer = setTimeout(() => {
      this.silentSendProbeTimer = undefined;
      this.checkSilentSend();
    }, SILENT_SEND_PROBE_DELAY_MS);
    this.silentSendProbeTimer.unref();
  }

  private checkSilentSend(): void {
    if (this.closed || this.keepaliveRequest) {
      return;
    }
    if (!this.unansweredOutbound || Date.now() - this.lastInboundAt < SILENT_SEND_PROBE_DELAY_MS) {
      // Either the peer answered after our last write or it spoke recently
      // enough that the silence is not suspicious yet; a later write re-arms
      // the check.
      return;
    }
    void this.sendKeepalive(LIVENESS_PROBE_TIMEOUT_MS).catch((error: unknown) => this.failFromKeepalive(error));
  }

  private stopSilentSendProbe(): void {
    if (this.silentSendProbeTimer) {
      clearTimeout(this.silentSendProbeTimer);
      this.silentSendProbeTimer = undefined;
    }
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
      this.removeChannelWaiter(waiter);
      waiter.reject(error);
    }
  }

  private removeChannelWaiter(waiter: ChannelWaiter): void {
    const index = this.channelWaiters.indexOf(waiter);
    if (index >= 0) {
      this.channelWaiters.splice(index, 1);
    }
    clearTimeout(waiter.timer);
    waiter.detachAbort?.();
    waiter.detachAbort = undefined;
  }

  private operationTimeoutMs(): number {
    return this.options.operationTimeoutMs ?? 15000;
  }

  private directTcpIpOpenTimeoutMs(): number {
    const configured = this.options.directTcpIpOpenTimeoutMs;
    if (configured !== undefined && Number.isFinite(configured) && configured > 0) {
      return configured;
    }
    return Math.min(this.operationTimeoutMs(), 12_000);
  }
}

function isChannelTimeoutError(error: unknown): boolean {
  return error instanceof Error && error.name !== "AbortError" && /Timed out waiting for SSH channel/.test(error.message);
}

function channelOpenCancelledError(): Error {
  const error = new Error("SSH direct-tcpip channel opening was cancelled.");
  error.name = "AbortError";
  return error;
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
