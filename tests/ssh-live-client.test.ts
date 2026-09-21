import { afterEach, describe, expect, it, vi } from "vitest";
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
    const client = createTestClient(transport, 60_000, { directTcpIpOpenTimeoutMs: 5 });
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

  it("cancels a still-queued channel-open payload when its response deadline expires", async () => {
    const transport = new FakeTransport();
    let queuedSignal: AbortSignal | undefined;
    transport.onSendOwned = (_payload, signal) => {
      queuedSignal = signal;
      return new Promise<void>((_resolve, reject) => {
        const onAbort = (): void => {
          const error = new Error("queued open cancelled");
          error.name = "AbortError";
          reject(error);
        };
        signal?.addEventListener("abort", onAbort, { once: true });
      });
    };
    const client = createTestClient(transport, 60_000, { directTcpIpOpenTimeoutMs: 5 });
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);

    await expect(client.openDirectTcpIpChannel(
      { host: "slow.example.com", port: 443 },
      { address: "127.0.0.1", port: 50000 }
    )).rejects.toThrow("Timed out waiting for SSH channel");

    expect(queuedSignal?.aborted).toBe(true);
    expect(transport.payloads).toEqual([]);
    expect(internals.session.getChannel(0)).toBeUndefined();
  });

  it("does not enqueue a direct-tcpip open cancelled in the async gate continuation", async () => {
    const transport = new FakeTransport();
    const client = createTestClient(transport, 60_000, { directTcpIpOpenTimeoutMs: 30_000 });
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    const controller = new AbortController();

    const opening = client.openDirectTcpIpChannel(
      { host: "unused.example.com", port: 443 },
      { address: "127.0.0.1", port: 50001 },
      controller.signal
    );
    controller.abort();

    await expect(opening).rejects.toMatchObject({ name: "AbortError" });
    expect(transport.payloads).toEqual([]);
    expect(internals.session.getChannel(0)).toBeUndefined();
  });

  it("cancels an orphaned direct-tcpip open as soon as its local proxy client disconnects", async () => {
    const transport = new FakeTransport();
    const client = createTestClient(transport, 60_000, { directTcpIpOpenTimeoutMs: 30_000 });
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    const controller = new AbortController();

    const opening = client.openDirectTcpIpChannel(
      { host: "unused.example.com", port: 443 },
      { address: "127.0.0.1", port: 50001 },
      controller.signal
    );
    const rejection = expect(opening).rejects.toMatchObject({ name: "AbortError" });
    await nextTurn();
    expect(internals.session.getChannel(0)).toBeDefined();

    controller.abort();
    await rejection;
    expect(internals.session.getChannel(0)).toBeUndefined();

    transport.emitPayload(
      new SshBinaryWriter()
        .byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        .uint32(0)
        .uint32(72)
        .uint32(1024)
        .uint32(32768)
        .toBuffer()
    );
    await nextTurn();
    const close = transport.payloads.find((payload) => {
      if (payload[0] !== SSH_MSG_CHANNEL_CLOSE) {
        return false;
      }
      const reader = new SshBinaryReader(payload);
      reader.byte();
      return reader.uint32() === 72;
    });
    expect(close).toBeDefined();
  });

  it("does not allocate a direct-tcpip channel cancelled while a rekey gate is active", async () => {
    const transport = new FakeTransport();
    const client = createTestClient(transport, 60_000, { directTcpIpOpenTimeoutMs: 30_000 });
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    const finishRekey = deferred<void>();
    internals.performKex = () => finishRekey.promise;
    const rekey = client.rekey();
    const controller = new AbortController();

    const opening = client.openDirectTcpIpChannel(
      { host: "unused.example.com", port: 443 },
      { address: "127.0.0.1", port: 50002 },
      controller.signal
    );
    const rejection = expect(opening).rejects.toMatchObject({ name: "AbortError" });
    await nextTurn();
    controller.abort();
    finishRekey.resolve(undefined);

    await rekey;
    await rejection;
    expect(internals.session.getChannel(0)).toBeUndefined();
    expect(transport.payloads).toEqual([]);
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

describe("SSH live client liveness", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("schedules the keepalive from the last inbound packet, not from outbound writes", async () => {
    vi.useFakeTimers();
    const transport = new FakeTransport();
    const client = createTestClient(transport, 60_000, { keepaliveIntervalSec: 60 });
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    internals.startKeepalive();
    transport.onSend = (payload) => {
      if (payload[0] === SSH_MSG_CHANNEL_OPEN) {
        transport.emitPayload(
          new SshBinaryWriter().byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION).uint32(0).uint32(9).uint32(1024 * 1024).uint32(64 * 1024).toBuffer()
        );
      }
    };
    const channel = await client.openDirectTcpIpChannel({ host: "example.com", port: 443 }, { address: "127.0.0.1", port: 50000 });

    // Outbound traffic through a half-open socket used to postpone the probe
    // for as long as the proxied applications kept retrying. Now a write that
    // gets no answer for ten seconds asks the server directly.
    await vi.advanceTimersByTimeAsync(30_000);
    await channel.write(Buffer.from("GET / HTTP/1.1\r\n\r\n"));
    await vi.advanceTimersByTimeAsync(9_000);
    expect(keepalives(transport)).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(keepalives(transport)).toHaveLength(1);

    // The answer is inbound, so the regular probe is a full interval after it.
    await vi.advanceTimersByTimeAsync(1_000);
    transport.emitPayload(Buffer.from([SSH_MSG_REQUEST_SUCCESS]));
    await vi.advanceTimersByTimeAsync(59_000);
    expect(keepalives(transport)).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(keepalives(transport)).toHaveLength(2);
  });

  it("tears down a session that stays silent after being written to", async () => {
    vi.useFakeTimers();
    const transport = new FakeTransport();
    const client = createTestClient(transport, 60_000, { keepaliveIntervalSec: 60 });
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    const events: string[] = [];
    client.onEvent((event) => events.push(event.type));
    internals.startKeepalive();

    // A channel open that the server never confirms: the write arms the check.
    const opening = client.openDirectTcpIpChannel({ host: "dead.example.com", port: 443 }, { address: "127.0.0.1", port: 50000 });
    const openFailure = expect(opening).rejects.toThrow();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(keepalives(transport)).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(14_000);
    expect(transport.destroyed).toBe(false);
    await vi.advanceTimersByTimeAsync(1_005);
    expect(events).toEqual(["error"]);
    expect(transport.destroyed).toBe(true);
    await openFailure;

    // A peer that keeps talking is never probed for one-way traffic.
    const talking = new FakeTransport();
    const talkingClient = createTestClient(talking, 60_000, { keepaliveIntervalSec: 60 });
    const talkingInternals = talkingClient as unknown as LiveClientInternals;
    talkingInternals.runtimeDispatchEnabled = true;
    forceAuthenticated(talkingInternals.session);
    talkingInternals.startKeepalive();
    talking.onSend = (payload) => {
      if (payload[0] === SSH_MSG_CHANNEL_OPEN) {
        talking.emitPayload(
          new SshBinaryWriter().byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION).uint32(0).uint32(9).uint32(1024 * 1024).uint32(64 * 1024).toBuffer()
        );
      }
    };
    const talkingChannel = await talkingClient.openDirectTcpIpChannel({ host: "example.com", port: 443 }, { address: "127.0.0.1", port: 50001 });
    for (let second = 0; second < 30; second += 1) {
      await talkingChannel.write(Buffer.from("ping"));
      talking.emitPayload(new SshBinaryWriter().byte(SSH_MSG_CHANNEL_DATA).uint32(0).string(Buffer.from("pong")).toBuffer());
      await vi.advanceTimersByTimeAsync(1_000);
    }
    expect(keepalives(talking)).toHaveLength(0);
  });

  it("accepts any inbound packet during the keepalive wait as proof of life", async () => {
    vi.useFakeTimers();
    const transport = new FakeTransport();
    const client = createTestClient(transport, 60_000, { keepaliveIntervalSec: 60, keepaliveTimeoutMs: 1_000 });
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    const errors: string[] = [];
    client.onEvent((event) => {
      if (event.type === "error") {
        errors.push(event.error.message);
      }
    });
    internals.startKeepalive();

    await vi.advanceTimersByTimeAsync(60_000);
    expect(keepalives(transport)).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(500);
    // A server-initiated global request that wants no reply: unrelated to
    // our keepalive, but only a live peer sends it.
    transport.emitPayload(
      new SshBinaryWriter().byte(SSH_MSG_GLOBAL_REQUEST).string("hostkeys-00@openssh.com").boolean(false).toBuffer()
    );
    await vi.advanceTimersByTimeAsync(1_000);

    expect(errors).toEqual([]);
    expect(transport.destroyed).toBe(false);
    // The unanswered request is dropped, so the next interval sends a fresh one
    // rather than excusing itself with the old evidence forever.
    await vi.advanceTimersByTimeAsync(60_000);
    expect(keepalives(transport)).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1_005);
    expect(errors).toEqual([expect.stringContaining("SSH keepalive timed out")]);
    expect(transport.destroyed).toBe(true);
  });

  it("destroys the session when a keepalive gets no answer and nothing else arrives", async () => {
    vi.useFakeTimers();
    const transport = new FakeTransport();
    const client = createTestClient(transport, 60_000, { keepaliveIntervalSec: 60, keepaliveTimeoutMs: 1_000 });
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    const events: string[] = [];
    client.onEvent((event) => events.push(event.type));
    internals.startKeepalive();

    await vi.advanceTimersByTimeAsync(60_000);
    expect(keepalives(transport)).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(999);
    expect(transport.destroyed).toBe(false);
    // The verdict waits one more turn for socket reads that may already hold
    // the answer; nothing arrives, so the session goes down.
    await vi.advanceTimersByTimeAsync(5);

    expect(events).toEqual(["error"]);
    expect(transport.destroyed).toBe(true);
  });

  it("does not let evidence older than a probe answer the probe", async () => {
    vi.useFakeTimers();
    const transport = new FakeTransport();
    const client = createTestClient(transport, 60_000, { keepaliveIntervalSec: 60, keepaliveTimeoutMs: 30_000 });
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    const errors: string[] = [];
    client.onEvent((event) => {
      if (event.type === "error") {
        errors.push(event.error.message);
      }
    });
    internals.startKeepalive();

    // t=60: regular keepalive. t=62: an unrelated packet, then the link dies.
    await vi.advanceTimersByTimeAsync(62_000);
    expect(keepalives(transport)).toHaveLength(1);
    transport.emitPayload(
      new SshBinaryWriter().byte(SSH_MSG_GLOBAL_REQUEST).string("hostkeys-00@openssh.com").boolean(false).toBuffer()
    );
    // t=80: the machine woke up; the probe sends its own request instead of
    // riding on the one whose window already holds the t=62 packet.
    await vi.advanceTimersByTimeAsync(18_000);
    const probe = client.probeLiveness(15_000);
    const rejection = expect(probe).rejects.toThrow("SSH keepalive timed out");
    expect(keepalives(transport)).toHaveLength(2);
    // t=90: the regular wait excuses itself with the t=62 packet ...
    await vi.advanceTimersByTimeAsync(10_000);
    expect(errors).toEqual([]);
    // ... but the probe saw nothing in its own window and fails at t=95.
    await vi.advanceTimersByTimeAsync(5_005);
    await rejection;
    expect(errors).toHaveLength(1);
    expect(transport.destroyed).toBe(true);
  });

  it("ends every open channel when the transport dies", async () => {
    const transport = new FakeTransport();
    const client = createTestClient(transport);
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    transport.onSend = (payload) => {
      if (payload[0] === SSH_MSG_CHANNEL_OPEN) {
        transport.emitPayload(
          new SshBinaryWriter().byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION).uint32(0).uint32(9).uint32(1024 * 1024).uint32(64 * 1024).toBuffer()
        );
      }
    };
    const channel = await client.openDirectTcpIpChannel({ host: "chat.example.com", port: 443 }, { address: "127.0.0.1", port: 50000 });
    const observed: string[] = [];
    channel.onError((error) => observed.push(`error:${error.message}`));
    channel.onClose(() => observed.push("close"));
    await nextTurn();

    // An idle WebSocket learns about the dead tunnel only from this; without
    // it the local socket would stay open on a channel that no longer exists.
    transport.emitClose();
    expect(observed).toEqual(["error:SSH transport closed."]);

    // A consumer without an error listener is told through close instead.
    const quiet = new FakeTransport();
    const quietClient = createTestClient(quiet);
    const quietInternals = quietClient as unknown as LiveClientInternals;
    quietInternals.runtimeDispatchEnabled = true;
    forceAuthenticated(quietInternals.session);
    quiet.onSend = (payload) => {
      if (payload[0] === SSH_MSG_CHANNEL_OPEN) {
        quiet.emitPayload(
          new SshBinaryWriter().byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION).uint32(0).uint32(9).uint32(1024 * 1024).uint32(64 * 1024).toBuffer()
        );
      }
    };
    const quietChannel = await quietClient.openDirectTcpIpChannel({ host: "chat.example.com", port: 443 }, { address: "127.0.0.1", port: 50001 });
    const quietObserved: string[] = [];
    quietChannel.onClose(() => quietObserved.push("close"));
    await nextTurn();
    quietClient.destroy(new Error("keepalive gave up"));
    expect(quietObserved).toEqual(["close"]);
  });

  it("starts the keepalive deadline only once the request is on the wire", async () => {
    vi.useFakeTimers();
    const transport = new FakeTransport();
    const client = createTestClient(transport, 60_000, { keepaliveIntervalSec: 60 });
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    const errors: string[] = [];
    client.onEvent((event) => {
      if (event.type === "error") {
        errors.push(event.error.message);
      }
    });
    // The upload backlog holds the keepalive frame for a while.
    const backlog = deferred<undefined>();
    transport.onSendOwned = async (payload) => {
      transport.payloads.push(payload);
      if (payload[0] === SSH_MSG_GLOBAL_REQUEST) {
        await backlog.promise;
      }
    };

    const probe = client.probeLiveness(1_000);
    let settled = false;
    void probe.then(() => {
      settled = true;
    }, () => {
      settled = true;
    });
    await vi.advanceTimersByTimeAsync(5_000);
    expect(settled).toBe(false);
    expect(errors).toEqual([]);

    backlog.resolve(undefined);
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(999);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(5);
    expect(settled).toBe(true);
    expect(errors).toEqual([expect.stringContaining("SSH keepalive timed out")]);
    await expect(probe).rejects.toThrow("SSH keepalive timed out");
  });

  it("probes liveness on demand with its own short deadline", async () => {
    vi.useFakeTimers();
    const transport = new FakeTransport();
    const client = createTestClient(transport, 60_000, { keepaliveIntervalSec: 60 });
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    internals.startKeepalive();

    const healthy = client.probeLiveness(500);
    expect(keepalives(transport)).toHaveLength(1);
    transport.emitPayload(Buffer.from([SSH_MSG_REQUEST_FAILURE]));
    await expect(healthy).resolves.toBeUndefined();
    expect(transport.destroyed).toBe(false);

    const errors: string[] = [];
    client.onEvent((event) => {
      if (event.type === "error") {
        errors.push(event.error.message);
      }
    });
    await vi.advanceTimersByTimeAsync(1);
    const dead = client.probeLiveness(500);
    const rejection = expect(dead).rejects.toThrow("SSH keepalive timed out");
    expect(keepalives(transport)).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(505);
    await rejection;
    expect(errors).toHaveLength(1);
    expect(transport.destroyed).toBe(true);
    await expect(client.probeLiveness(500)).rejects.toThrow("SSH client is closed");
  });

  it("asks the server whether it is alive after a direct-tcpip open times out in silence", async () => {
    const silent = new FakeTransport();
    const client = createTestClient(silent, 60_000, { keepaliveIntervalSec: 60, directTcpIpOpenTimeoutMs: 5 });
    const internals = client as unknown as LiveClientInternals;
    internals.runtimeDispatchEnabled = true;
    forceAuthenticated(internals.session);
    await expect(client.openDirectTcpIpChannel(
      { host: "slow.example.com", port: 443 },
      { address: "127.0.0.1", port: 50000 }
    )).rejects.toThrow("Timed out waiting for SSH channel");
    expect(keepalives(silent)).toHaveLength(1);

    // A peer that is still talking gets no extra probe; the open was slow, not the link.
    const talking = new FakeTransport();
    const talkingClient = createTestClient(talking, 60_000, { keepaliveIntervalSec: 60, directTcpIpOpenTimeoutMs: 5 });
    const talkingInternals = talkingClient as unknown as LiveClientInternals;
    talkingInternals.runtimeDispatchEnabled = true;
    forceAuthenticated(talkingInternals.session);
    talking.onSend = (payload) => {
      if (payload[0] === SSH_MSG_CHANNEL_OPEN) {
        setTimeout(() => {
          talking.emitPayload(
            new SshBinaryWriter().byte(SSH_MSG_GLOBAL_REQUEST).string("hostkeys-00@openssh.com").boolean(false).toBuffer()
          );
        }, 2);
      }
    };
    await expect(talkingClient.openDirectTcpIpChannel(
      { host: "slow.example.com", port: 443 },
      { address: "127.0.0.1", port: 50000 }
    )).rejects.toThrow("Timed out waiting for SSH channel");
    expect(keepalives(talking)).toHaveLength(0);
  });
});

function keepalives(transport: FakeTransport): Buffer[] {
  return transport.payloads.filter((payload) => payload[0] === SSH_MSG_GLOBAL_REQUEST);
}

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
  onSendOwned: ((payload: Buffer, signal?: AbortSignal) => Promise<void>) | undefined;
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

  async sendOwned(payload: Buffer, signal?: AbortSignal): Promise<void> {
    if (this.onSendOwned) {
      await this.onSendOwned(payload, signal);
      return;
    }
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
