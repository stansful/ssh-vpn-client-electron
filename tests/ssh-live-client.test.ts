import { describe, expect, it, vi } from "vitest";
import {
  SshLiveClient,
  sshKernelKeepaliveInitialDelayMs,
  type SshLiveClientOptions
} from "../src/core/ssh/live-client.js";
import type {
  SshIdentificationExchange,
  SshPacketTransportEvent,
  SshSocketTransport
} from "../src/core/ssh/socket-transport.js";
import type { SshSessionStateMachine } from "../src/core/ssh/session-state.js";
import { SshBinaryReader, SshBinaryWriter } from "../src/core/ssh/binary.js";
import {
  SSH_MSG_CHANNEL_CLOSE,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_EXTENDED_DATA,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_CHANNEL_SUCCESS
} from "../src/core/ssh/connection-messages.js";
import { SSH_MSG_CHANNEL_OPEN, SSH_MSG_CHANNEL_REQUEST } from "../src/core/ssh/channel-messages.js";
import {
  SSH_MSG_DISCONNECT,
  SSH_MSG_GLOBAL_REQUEST,
  SSH_MSG_REQUEST_FAILURE,
  SSH_MSG_REQUEST_SUCCESS
} from "../src/core/ssh/transport-messages.js";

describe("SSH live client rekey coordination", () => {
  it("keeps kernel TCP probes behind application keepalives", () => {
    expect(sshKernelKeepaliveInitialDelayMs(undefined)).toBe(120_000);
    expect(sshKernelKeepaliveInitialDelayMs(30)).toBe(120_000);
    expect(sshKernelKeepaliveInitialDelayMs(120)).toBe(240_000);
    expect(sshKernelKeepaliveInitialDelayMs(600)).toBe(1_200_000);
  });

  it("pauses runtime writes for server- and client-initiated rekey without losing them", async () => {
    const transport = new FakeTransport();
    const client = createTestClient(transport);
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);

    const serverKex = deferred<void>();
    let observedServerKexInit: Buffer | undefined;
    internals.performKex = (payload?: Buffer) => {
      observedServerKexInit = payload;
      return serverKex.promise;
    };
    internals.handleRuntimePayload(Buffer.from([20]));
    const serverQueuedWrite = internals.sendRuntimePayload(Buffer.from([94, 1]));
    await nextTurn();
    expect(observedServerKexInit).toEqual(Buffer.from([20]));
    expect(transport.payloads).toEqual([]);

    serverKex.resolve();
    await serverQueuedWrite;
    expect(transport.payloads).toEqual([Buffer.from([94, 1])]);

    const clientKex = deferred<void>();
    let clientKexWasServerInitiated = true;
    internals.performKex = (payload?: Buffer) => {
      clientKexWasServerInitiated = payload !== undefined;
      return clientKex.promise;
    };
    const rekey = client.rekey();
    const clientQueuedWrite = internals.sendRuntimePayload(Buffer.from([94, 2]));
    await nextTurn();
    expect(clientKexWasServerInitiated).toBe(false);
    expect(transport.payloads).toHaveLength(1);

    clientKex.resolve();
    await Promise.all([rekey, clientQueuedWrite]);
    expect(transport.payloads).toEqual([Buffer.from([94, 1]), Buffer.from([94, 2])]);
  });

  it("bounds the unauthenticated payload queue", () => {
    const client = createTestClient(new FakeTransport());
    const internals = client as unknown as LiveClientInternals;
    for (let index = 0; index < 128; index += 1) {
      internals.handleTransportEvent({ type: "payload", payload: Buffer.from([2]) });
    }
    expect(() => internals.handleTransportEvent({ type: "payload", payload: Buffer.from([2]) })).toThrow(
      "queued payload limit exceeded"
    );
  });

  it("replays DATA and CLOSE coalesced with OPEN_CONFIRMATION after the direct consumer attaches", async () => {
    const transport = new FakeTransport();
    const client = createTestClient(transport);
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    transport.onSend = (payload) => {
      if (payload[0] !== SSH_MSG_CHANNEL_OPEN) {
        return;
      }
      transport.emitPayload(
        new SshBinaryWriter()
          .byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
          .uint32(0)
          .uint32(7)
          .uint32(1024 * 1024)
          .uint32(64 * 1024)
          .toBuffer()
      );
      transport.emitPayload(
        new SshBinaryWriter().byte(SSH_MSG_CHANNEL_DATA).uint32(0).string(Buffer.from("FINAL")).toBuffer()
      );
      transport.emitPayload(new SshBinaryWriter().byte(SSH_MSG_CHANNEL_CLOSE).uint32(0).toBuffer());
    };

    const channel = await client.openDirectTcpIpChannel(
      { host: "example.com", port: 443 },
      { address: "127.0.0.1", port: 50000 }
    );
    const observed: string[] = [];
    channel.onData((data) => observed.push(`data:${data.toString()}`));
    channel.onClose(() => observed.push("close"));
    await nextTurn();

    expect(observed).toEqual(["data:FINAL", "close"]);
    const closeAcknowledgements = transport.payloads.filter((payload) => payload[0] === SSH_MSG_CHANNEL_CLOSE);
    expect(closeAcknowledgements).toHaveLength(1);
    const closeAcknowledgement = new SshBinaryReader(closeAcknowledgements[0]);
    expect(closeAcknowledgement.byte()).toBe(SSH_MSG_CHANNEL_CLOSE);
    expect(closeAcknowledgement.uint32()).toBe(7);
  });

  it("installs shell and global-response consumers before synchronous server replies", async () => {
    const transport = new FakeTransport();
    const client = createTestClient(transport);
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    const terminalData: string[] = [];
    const terminalStreams: string[] = [];
    let terminalCloses = 0;
    client.onEvent((event) => {
      if (event.type === "terminal-data") {
        terminalData.push(event.data.toString());
        terminalStreams.push(event.stream);
      } else if (event.type === "terminal-close") {
        terminalCloses += 1;
      }
    });
    transport.onSend = (payload) => {
      if (payload[0] === SSH_MSG_CHANNEL_OPEN) {
        transport.emitPayload(
          new SshBinaryWriter()
            .byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
            .uint32(0)
            .uint32(9)
            .uint32(1024 * 1024)
            .uint32(64 * 1024)
            .toBuffer()
        );
        return;
      }
      if (payload[0] === SSH_MSG_CHANNEL_REQUEST) {
        const reader = new SshBinaryReader(payload);
        reader.byte();
        reader.uint32();
        const requestType = reader.utf8String();
        transport.emitPayload(new SshBinaryWriter().byte(SSH_MSG_CHANNEL_SUCCESS).uint32(0).toBuffer());
        if (requestType === "shell") {
          transport.emitPayload(
            new SshBinaryWriter().byte(SSH_MSG_CHANNEL_DATA).uint32(0).string(Buffer.from("prompt> ")).toBuffer()
          );
        }
        return;
      }
      if (payload[0] === 80) {
        transport.emitPayload(Buffer.from([SSH_MSG_REQUEST_SUCCESS]));
      }
    };

    await client.openShell();
    transport.emitPayload(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_EXTENDED_DATA)
        .uint32(0)
        .uint32(1)
        .string(Buffer.from("warning\n"))
        .toBuffer()
    );
    transport.emitPayload(
      new SshBinaryWriter().byte(SSH_MSG_CHANNEL_DATA).uint32(0).string(Buffer.alloc(0)).toBuffer()
    );
    await client.sendKeepalive();

    expect(terminalData).toEqual(["prompt> ", "warning\n"]);
    expect(terminalStreams).toEqual(["stdout", "stderr"]);

    transport.emitPayload(new SshBinaryWriter().byte(SSH_MSG_CHANNEL_CLOSE).uint32(0).toBuffer());
    transport.emitPayload(new SshBinaryWriter().byte(SSH_MSG_CHANNEL_CLOSE).uint32(0).toBuffer());
    expect(terminalCloses).toBe(1);
  });

  it("answers server global requests only when a reply was requested", async () => {
    const transport = new FakeTransport();
    const client = createTestClient(transport);
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);

    transport.emitPayload(
      new SshBinaryWriter().byte(SSH_MSG_GLOBAL_REQUEST).string("keepalive@openssh.com").boolean(true).toBuffer()
    );
    transport.emitPayload(
      new SshBinaryWriter().byte(SSH_MSG_GLOBAL_REQUEST).string("notification@example.com").boolean(false).toBuffer()
    );
    await nextTurn();

    expect(transport.payloads.filter((payload) => payload[0] === SSH_MSG_REQUEST_FAILURE)).toHaveLength(1);
  });

  it("coalesces concurrent keepalives into one ordered global request", async () => {
    const transport = new FakeTransport();
    const client = createTestClient(transport);
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);

    const first = client.sendKeepalive();
    const second = client.sendKeepalive();
    expect(transport.payloads.filter((payload) => payload[0] === SSH_MSG_GLOBAL_REQUEST)).toHaveLength(1);

    transport.emitPayload(Buffer.from([SSH_MSG_REQUEST_SUCCESS]));
    await Promise.all([first, second]);
  });

  it("uses one deadline timer and does not poll an idle byte-only rekey", () => {
    vi.useFakeTimers();
    try {
      const scheduled = createTestClient(new FakeTransport(), 100, {
        keepaliveIntervalSec: 60,
        rekeyIntervalMs: 60 * 60 * 1000
      });
      const scheduledInternals = scheduled as unknown as LiveClientInternals;
      scheduledInternals.runtimeDispatchEnabled = true;
      forceAuthenticated(scheduledInternals.session);
      scheduledInternals.startKeepalive();
      scheduledInternals.startRekeyMonitor();
      expect(vi.getTimerCount()).toBe(1);
      scheduledInternals.stopKeepalive();
      scheduledInternals.stopRekeyMonitor();
      expect(vi.getTimerCount()).toBe(0);

      const byteOnly = createTestClient(new FakeTransport(), 100, {
        keepaliveIntervalSec: 0,
        rekeyIntervalMs: 0,
        rekeyAfterBytes: 1024
      });
      const byteOnlyInternals = byteOnly as unknown as LiveClientInternals;
      byteOnlyInternals.runtimeDispatchEnabled = true;
      forceAuthenticated(byteOnlyInternals.session);
      byteOnlyInternals.startKeepalive();
      byteOnlyInternals.startRekeyMonitor();
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("abandons a timed-out channel open and closes a late server confirmation", async () => {
    const transport = new FakeTransport();
    const client = createTestClient(transport, 5);
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);

    await expect(client.openDirectTcpIpChannel(
      { host: "slow.example.com", port: 443 },
      { address: "127.0.0.1", port: 50000 }
    )).rejects.toThrow("Timed out waiting for SSH channel");
    expect(internals.session.getChannel(0)).toBeUndefined();

    transport.emitPayload(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        .uint32(0)
        .uint32(71)
        .uint32(1024)
        .uint32(32768)
        .toBuffer()
    );
    await nextTurn();

    const close = transport.payloads.find((payload) => payload[0] === SSH_MSG_CHANNEL_CLOSE);
    expect(close).toBeDefined();
    const reader = new SshBinaryReader(close!);
    expect(reader.byte()).toBe(SSH_MSG_CHANNEL_CLOSE);
    expect(reader.uint32()).toBe(71);
  });

  it("destroys the transport and rejects pending work on a peer disconnect", async () => {
    const transport = new FakeTransport();
    const client = createTestClient(transport);
    const internals = client as unknown as LiveClientInternals;
    const closes: string[] = [];
    client.onEvent((event) => {
      if (event.type === "close") {
        closes.push(event.type);
      }
    });
    const pending = internals.waitForPayload(() => false, 10_000);
    const rejection = expect(pending).rejects.toThrow("server disconnected");

    transport.emitPayload(Buffer.from([SSH_MSG_DISCONNECT]));
    await rejection;

    expect(transport.destroyed).toBe(true);
    expect(closes).toEqual(["close"]);
    transport.emitClose();
    expect(closes).toEqual(["close"]);
  });
});

interface LiveClientInternals {
  runtimeDispatchEnabled: boolean;
  session: SshSessionStateMachine;
  performKex(payload?: Buffer): Promise<void>;
  handleRuntimePayload(payload: Buffer): void;
  handleTransportEvent(event: { type: "payload"; payload: Buffer }): void;
  waitForPayload(predicate: (payload: Buffer) => boolean, timeoutMs: number): Promise<Buffer>;
  sendRuntimePayload(payload: Buffer): Promise<void>;
  startKeepalive(): void;
  stopKeepalive(): void;
  startRekeyMonitor(): void;
  stopRekeyMonitor(): void;
}

class FakeTransport {
  readonly payloads: Buffer[] = [];
  destroyed = false;
  onSend: ((payload: Buffer) => void) | undefined;
  private listener: ((event: SshPacketTransportEvent) => void) | undefined;

  onEvent(listener: (event: SshPacketTransportEvent) => void): () => void {
    this.listener = listener;
    return () => {
      if (this.listener === listener) {
        this.listener = undefined;
      }
    };
  }

  async send(payload: Buffer): Promise<void> {
    this.payloads.push(Buffer.from(payload));
    this.onSend?.(payload);
  }

  async sendOwned(payload: Buffer): Promise<void> {
    this.payloads.push(payload);
    this.onSend?.(payload);
  }

  emitPayload(payload: Buffer): void {
    this.listener?.({ type: "payload", payload });
  }

  emitClose(): void {
    this.listener?.({ type: "close" });
  }

  getTransferredBytes(): { sent: number; received: number } {
    return { sent: 0, received: 0 };
  }

  destroy(): void {
    this.destroyed = true;
  }
}

function createTestClient(
  transport: FakeTransport,
  operationTimeoutMs = 100,
  overrides: Partial<SshLiveClientOptions> = {}
): SshLiveClient {
  const Constructor = SshLiveClient as unknown as new (
    transport: SshSocketTransport,
    identification: SshIdentificationExchange,
    options: SshLiveClientOptions
  ) => SshLiveClient;
  return new Constructor(
    transport as unknown as SshSocketTransport,
    {
      clientLine: "SSH-2.0-test-client",
      serverLine: "SSH-2.0-test-server",
      serverVersion: {
        protocol: "2.0",
        software: "test-server",
        raw: "SSH-2.0-test-server"
      }
    },
    {
      host: "127.0.0.1",
      port: 22,
      username: "test",
      expectedServerFingerprint: "SHA256:test",
      operationTimeoutMs,
      ...overrides
    }
  );
}

function forceAuthenticated(session: SshSessionStateMachine): void {
  (session as unknown as { phase: string }).phase = "authenticated";
}

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}

function nextTurn(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}
