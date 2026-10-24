import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DataplaneStartRequest } from "../src/service/local-ipc-protocol.js";

vi.mock("node:child_process", () => ({ spawn: vi.fn() }));

const { spawn } = await import("node:child_process");
const { NativeDataplaneController, classifyHelperStderrLine } = await import("../src/service/native-dataplane.js");
const { NativeHelperClient } = await import("../src/service/native-helper-client.js");

// The dataplane helper owns an adapter and the machine's routing table. These
// cases drive the real controller and helper client against a scripted
// helper process: what it reports, how it dies, and what is owed to it.

type WireCommand = { id: string; type: string; payload?: unknown };
type Reply =
  | { ok: true; payload?: unknown; events?: unknown[] }
  | { ok: false; error: string; events?: unknown[] }
  /** Never answered. */
  | "hang";

class FakeHelper extends EventEmitter {
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  readonly stdin: Writable;
  readonly commands: WireCommand[] = [];
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  killed = false;
  killCalls = 0;
  private buffered = "";

  constructor(
    private readonly respond: (command: WireCommand) => Reply,
    private readonly behaviour: { exitWhenInputEnds?: boolean } = {}
  ) {
    super();
    this.stdin = new Writable({
      write: (chunk: Buffer, _encoding, callback) => {
        this.buffered += chunk.toString("utf8");
        let newline = this.buffered.indexOf("\n");
        while (newline >= 0) {
          const line = this.buffered.slice(0, newline);
          this.buffered = this.buffered.slice(newline + 1);
          this.handle(JSON.parse(line) as WireCommand);
          newline = this.buffered.indexOf("\n");
        }
        callback();
      },
      final: (callback) => {
        callback();
        if (this.behaviour.exitWhenInputEnds) {
          setImmediate(() => this.exit(0));
        }
      }
    });
  }

  ofType(type: string): WireCommand[] {
    return this.commands.filter((command) => command.type === type);
  }

  writeStderr(line: string): void {
    this.stderr.write(`${line}\n`);
  }

  exit(code: number, { closeStreams = true }: { closeStreams?: boolean } = {}): void {
    if (this.exitCode !== null || this.signalCode !== null) {
      return;
    }
    this.exitCode = code;
    if (closeStreams) {
      this.closeStreams();
    }
    this.emit("exit", code, null);
  }

  /** The pipes can close after the exit is reported. */
  closeStreams(): void {
    this.stdout.end();
    this.stderr.end();
  }

  kill(): boolean {
    this.killCalls += 1;
    this.killed = true;
    setImmediate(() => {
      if (this.exitCode === null && this.signalCode === null) {
        this.signalCode = "SIGTERM";
        this.stdout.end();
        this.stderr.end();
        this.emit("exit", null, "SIGTERM");
      }
    });
    return true;
  }

  private handle(command: WireCommand): void {
    this.commands.push(command);
    const reply = this.respond(command);
    if (reply === "hang") {
      return;
    }
    setImmediate(() => {
      if (this.exitCode !== null || this.signalCode !== null) {
        return;
      }
      const response = reply.ok
        ? { kind: "response", id: command.id, ok: true, payload: reply.payload, protocolVersion: 1 }
        : { kind: "response", id: command.id, ok: false, error: reply.error, protocolVersion: 1 };
      this.stdout.write(`${JSON.stringify(response)}\n`);
      for (const event of reply.events ?? []) {
        this.stdout.write(`${JSON.stringify({ kind: "event", event, protocolVersion: 1 })}\n`);
      }
    });
  }
}

function handshake(capabilities: Record<string, unknown> = {}): { ok: true; payload: unknown } {
  return {
    ok: true,
    payload: {
      protocolVersion: 1,
      capabilities: {
        target: {
          platform: "windows",
          arch: "x64",
          serviceExecutableName: "shadow-ssh-service.exe",
          serviceRelativePath: "native/windows/x64/shadow-ssh-service.exe",
          supportsPrivilegedService: true
        },
        ipc: "stdio",
        namedPipeAcl: false,
        unixSocketMode: false,
        serviceControlManager: false,
        wfpInterception: true,
        tunDevice: true,
        routeManipulation: true,
        processConnectionAttribution: true,
        dnsVisibility: false,
        ipv6RouteEnforcement: true,
        udpForwarding: true,
        sshCoreLinked: false,
        ...capabilities
      }
    }
  };
}

function diagnostic(level: string, message: string): unknown {
  return { type: "diagnostics-appended", entry: { id: "e1", at: "2026-10-21T00:00:00.000Z", level, message } };
}

function startRequest(): DataplaneStartRequest {
  return {
    routingMode: "selected-rules",
    routingRules: [],
    routingProxyDomains: [],
    routingDirectDomains: [],
    tunnelProxyEndpoint: "127.0.0.1:51234",
    protectedAddresses: ["203.0.113.9"],
    protectedPort: 22,
    udpSupported: false,
    enforceIpv6: true,
    adapterName: "Shadow SSH",
    journalPath: "C:\\Users\\u\\AppData\\Roaming\\Shadow SSH\\tun-routing-journal.json"
  };
}

/** Like the real helper, it exits once its input ends unless told otherwise. */
function withHelper(respond: (command: WireCommand) => Reply, behaviour: { exitWhenInputEnds?: boolean } = {}): FakeHelper {
  const helper = new FakeHelper(respond, { exitWhenInputEnds: true, ...behaviour });
  vi.mocked(spawn).mockReturnValue(helper as unknown as ReturnType<typeof spawn>);
  return helper;
}

/** A helper that answers everything with success. */
function healthyHelper(behaviour: { exitWhenInputEnds?: boolean } = {}): FakeHelper {
  return withHelper((command) => (command.type === "get-capabilities" ? handshake() : { ok: true, payload: { accepted: true } }), behaviour);
}

function controller(): {
  dataplane: InstanceType<typeof NativeDataplaneController>;
  diagnostics: Array<{ level: string; message: string }>;
} {
  const diagnostics: Array<{ level: string; message: string }> = [];
  const dataplane = new NativeDataplaneController({
    executablePath: "C:\\App\\shadow-ssh-service.exe",
    onDiagnostic: (level, message) => diagnostics.push({ level, message })
  });
  return { dataplane, diagnostics };
}

async function settle(): Promise<void> {
  for (let turn = 0; turn < 5; turn += 1) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

describe("native dataplane controller", () => {
  beforeEach(() => {
    vi.mocked(spawn).mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("asks a running helper again whether it can create an adapter", async () => {
    // A user who reads "wintun.dll was not found" and puts the file in place
    // must not have to restart the app for it to count.
    let wintunInPlace = false;
    const helper = withHelper((command) =>
      command.type === "get-capabilities"
        ? handshake(wintunInPlace ? {} : { tunDevice: false, tunUnavailableReason: "wintun.dll was not found" })
        : { ok: true }
    );
    const { dataplane } = controller();

    await expect(dataplane.probe()).resolves.toMatchObject({ available: false, reason: expect.stringContaining("wintun.dll") });
    wintunInPlace = true;
    await expect(dataplane.probe()).resolves.toEqual({ available: true });

    expect(spawn).toHaveBeenCalledTimes(1);
    expect(helper.ofType("get-capabilities")).toHaveLength(2);
    await dataplane.dispose();
  });

  it("tells its listener, with the helper's own reason, when the dataplane dies", async () => {
    const helper = healthyHelper();
    const { dataplane, diagnostics } = controller();
    const reasons: string[] = [];
    dataplane.onUnexpectedStop((reason) => reasons.push(reason));
    await dataplane.start(startRequest());
    expect(dataplane.isActive).toBe(true);

    helper.writeStderr("dataplane fatal: TUN read stopped: the receive ring is corrupt");
    helper.exit(3);
    await settle();

    expect(reasons).toEqual(["TUN read stopped: the receive ring is corrupt"]);
    expect(dataplane.isActive).toBe(false);
    expect(diagnostics).toContainEqual({ level: "error", message: "dataplane fatal: TUN read stopped: the receive ring is corrupt" });
    // The listener owns reporting it; the controller does not say it twice.
    expect(diagnostics.some((entry) => entry.message.startsWith("TUN dataplane stopped unexpectedly"))).toBe(false);
    await dataplane.dispose();
  });

  it("still reports the death when its exit is read only after a new helper started", async () => {
    // A routing update can probe in the moment between the exit and its
    // stderr being read; the replacement must not swallow the old helper's
    // death, or the session would keep counting on an adapter that is gone.
    const first = healthyHelper();
    const { dataplane } = controller();
    const reasons: string[] = [];
    dataplane.onUnexpectedStop((reason) => reasons.push(reason));
    await dataplane.start(startRequest());

    const second = healthyHelper();
    first.writeStderr("dataplane fatal: the receive ring failed");
    first.exit(3, { closeStreams: false });
    await expect(dataplane.probe()).resolves.toEqual({ available: true });
    expect(spawn).toHaveBeenCalledTimes(2);

    first.closeStreams();
    await settle();
    expect(reasons).toEqual(["the receive ring failed"]);
    expect(dataplane.isActive).toBe(false);
    expect(second.exitCode).toBeNull();
    await dataplane.dispose();
  });

  it("reports the death itself when nobody listens", async () => {
    const helper = healthyHelper();
    const { dataplane, diagnostics } = controller();
    await dataplane.start(startRequest());

    helper.exit(3);
    await settle();

    const report = diagnostics.find((entry) => entry.message.startsWith("TUN dataplane stopped unexpectedly"));
    expect(report).toMatchObject({ level: "error" });
    expect(report?.message).toContain("Native helper exited (3).");
    await dataplane.dispose();
  });

  it("does not call a stop it asked for unexpected", async () => {
    const helper = withHelper((command) => (command.type === "get-capabilities" ? handshake() : command.type === "stop-dataplane" ? "hang" : { ok: true }));
    const { dataplane } = controller();
    const reasons: string[] = [];
    dataplane.onUnexpectedStop((reason) => reasons.push(reason));
    await dataplane.start(startRequest());

    const stopping = dataplane.stop();
    // The helper goes away in the middle of its teardown.
    helper.exit(1);
    await expect(stopping).rejects.toThrow("Native helper exited (1).");
    await settle();

    expect(reasons).toEqual([]);
    expect(dataplane.isActive).toBe(false);
    await dataplane.dispose();
  });

  it("still sends a stop for a start that failed, and none when nothing was started", async () => {
    const helper = withHelper((command) =>
      command.type === "get-capabilities"
        ? handshake()
        : command.type === "start-dataplane"
          ? { ok: false, error: "netsh did not answer" }
          : { ok: true }
    );
    const { dataplane } = controller();
    await dataplane.probe();
    await dataplane.stop();
    expect(helper.ofType("stop-dataplane")).toHaveLength(0);

    // The start may have failed only on this side: the helper serves one
    // command at a time and could still be finishing it.
    await expect(dataplane.start(startRequest())).rejects.toThrow("netsh did not answer");
    await dataplane.stop();
    expect(helper.ofType("stop-dataplane")).toHaveLength(1);
    // That stop settled it; nothing more is owed.
    await dataplane.stop();
    expect(helper.ofType("stop-dataplane")).toHaveLength(1);
    await dataplane.dispose();
  });

  it("stops waiting for a start it was told to give up on, and still owes the helper a stop", async () => {
    // The helper serves one command at a time and cannot be interrupted, so a
    // disconnected session must not sit behind the start until it answers.
    const helper = withHelper((command) =>
      command.type === "get-capabilities" ? handshake() : command.type === "start-dataplane" ? "hang" : { ok: true }
    );
    const { dataplane } = controller();
    await dataplane.probe();
    const abort = new AbortController();
    const starting = dataplane.start(startRequest(), abort.signal);
    await settle();
    expect(helper.ofType("start-dataplane")).toHaveLength(1);
    abort.abort();
    await expect(starting).rejects.toThrow("start-dataplane request was abandoned");
    expect(dataplane.isActive).toBe(false);

    await dataplane.stop();
    expect(helper.ofType("stop-dataplane")).toHaveLength(1);

    // Given up on before it was sent, it is not sent at all.
    await expect(dataplane.start(startRequest(), abort.signal)).rejects.toThrow(/abandoned/u);
    expect(helper.ofType("start-dataplane")).toHaveLength(1);
    await dataplane.dispose();
  });

  it("joins a stop that is already running", async () => {
    let finishStop: (() => void) | undefined;
    const helper = withHelper((command) => {
      if (command.type === "stop-dataplane") {
        finishStop = () => helper.stdout.write(`${JSON.stringify({ kind: "response", id: command.id, ok: true, protocolVersion: 1 })}\n`);
        return "hang";
      }
      return command.type === "get-capabilities" ? handshake() : { ok: true };
    });
    const { dataplane } = controller();
    await dataplane.start(startRequest());

    const first = dataplane.stop();
    const second = dataplane.stop();
    await settle();
    finishStop?.();
    await Promise.all([first, second]);
    expect(helper.ofType("stop-dataplane")).toHaveLength(1);
    await dataplane.dispose();
  });

  it("passes the helper's own diagnostics on, at the level each one has", async () => {
    const helper = withHelper((command) =>
      command.type === "get-capabilities"
        ? handshake()
        : { ok: true, payload: { accepted: true }, events: [diagnostic("info", "TUN dataplane started.")] }
    );
    const { dataplane, diagnostics } = controller();
    await dataplane.start(startRequest());
    helper.writeStderr("dataplane info: routes are being watched");
    helper.writeStderr("dataplane warning: IPv6 is not reachable through the tunnel");
    helper.writeStderr("dataplane error: route restore failed");
    helper.writeStderr("Could not limit DLL loading to the system directory");
    await settle();

    expect(diagnostics).toEqual([
      { level: "info", message: "TUN dataplane started." },
      { level: "info", message: "dataplane info: routes are being watched" },
      { level: "warning", message: "dataplane warning: IPv6 is not reachable through the tunnel" },
      { level: "error", message: "dataplane error: route restore failed" },
      { level: "warning", message: "Could not limit DLL loading to the system directory" }
    ]);
    await dataplane.dispose();
  });

  it("lets the helper exit on its own after closing its input, instead of killing it", async () => {
    const helper = healthyHelper({ exitWhenInputEnds: true });
    const { dataplane } = controller();
    await dataplane.start(startRequest());

    await dataplane.dispose();

    expect(helper.ofType("stop-dataplane")).toHaveLength(1);
    expect(helper.exitCode).toBe(0);
    expect(helper.killCalls).toBe(0);
  });
});

describe("native helper client", () => {
  beforeEach(() => {
    vi.mocked(spawn).mockReset();
  });

  it("sends recover-routes with the journal and reads how much was undone", async () => {
    const helper = withHelper((command) =>
      command.type === "get-capabilities"
        ? handshake({ routeRecovery: true })
        : command.type === "recover-routes"
          ? { ok: true, payload: { recovered: 4 } }
          : { ok: true }
    );
    const client = await NativeHelperClient.start("C:\\App\\shadow-ssh-service.exe");
    expect(client.handshake?.capabilities.routeRecovery).toBe(true);

    await expect(client.recoverRoutes("C:\\Data\\tun-routing-journal.json")).resolves.toBe(4);
    expect(helper.ofType("recover-routes")[0]?.payload).toEqual({ journalPath: "C:\\Data\\tun-routing-journal.json" });
    await client.dispose();
  });

  it("lets only a helper that owns routing outlive the app on Windows", async () => {
    healthyHelper();
    const original = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    try {
      const client = await NativeHelperClient.start("C:\\App\\shadow-ssh-service.exe");
      expect(vi.mocked(spawn).mock.calls[0]?.[2]).toMatchObject({ detached: false, windowsHide: true });
      await client.dispose();

      // Electron's exit kills every other child on Windows, mid-teardown or not.
      withHelper((command) => (command.type === "get-capabilities" ? handshake({ routeRecovery: true }) : { ok: true }));
      const { dataplane } = controller();
      await dataplane.probe();
      expect(vi.mocked(spawn)).toHaveBeenCalledTimes(2);
      expect(vi.mocked(spawn).mock.calls[1]?.[2]).toMatchObject({ detached: true, windowsHide: true });
      await dataplane.dispose();
    } finally {
      if (original) {
        Object.defineProperty(process, "platform", original);
      }
    }
  });

  it("starts a helper built before it hid netsh's console again attached", async () => {
    // A detached helper has no console, so one that still starts netsh
    // without CREATE_NO_WINDOW - the committed binaries `npm run dev` runs
    // until they are rebuilt - would flash a console window for every route.
    const original = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    try {
      const older = new FakeHelper((command) => (command.type === "get-capabilities" ? handshake() : { ok: true }), {
        exitWhenInputEnds: true
      });
      const attached = new FakeHelper((command) => (command.type === "get-capabilities" ? handshake() : { ok: true, payload: { accepted: true } }), {
        exitWhenInputEnds: true
      });
      vi.mocked(spawn)
        .mockReturnValueOnce(older as unknown as ReturnType<typeof spawn>)
        .mockReturnValueOnce(attached as unknown as ReturnType<typeof spawn>);
      const { dataplane, diagnostics } = controller();
      await expect(dataplane.probe()).resolves.toEqual({ available: true });
      expect(vi.mocked(spawn).mock.calls.map((call) => (call[2] as { detached?: boolean }).detached)).toEqual([true, false]);
      expect(older.killed || older.exitCode !== null).toBe(true);

      await dataplane.start(startRequest());
      await settle();
      expect(attached.ofType("start-dataplane")).toHaveLength(1);
      expect(older.ofType("start-dataplane")).toHaveLength(0);
      // The first helper's exit is not taken for the second one's.
      await dataplane.stop();
      expect(attached.ofType("stop-dataplane")).toHaveLength(1);
      expect(diagnostics.filter((entry) => entry.level === "error")).toEqual([]);
      await dataplane.dispose();
    } finally {
      if (original) {
        Object.defineProperty(process, "platform", original);
      }
    }
  });

  it("kills a helper that does not exit within the grace it was given", async () => {
    const helper = healthyHelper({ exitWhenInputEnds: false });
    const client = await NativeHelperClient.start("C:\\App\\shadow-ssh-service.exe");
    const startedAt = Date.now();
    await client.dispose({ exitGraceMs: 50 });
    expect(Date.now() - startedAt).toBeGreaterThanOrEqual(40);
    expect(helper.killCalls).toBe(1);
  });
});

describe("helper stderr classification", () => {
  it("reads the level a line states, and only that", () => {
    expect(classifyHelperStderrLine("dataplane fatal: the adapter went away")).toEqual({
      level: "error",
      message: "dataplane fatal: the adapter went away",
      fatalReason: "the adapter went away"
    });
    expect(classifyHelperStderrLine("dataplane fatal:")).toMatchObject({ level: "error", fatalReason: expect.any(String) });
    expect(classifyHelperStderrLine("dataplane warning: slow netsh")).toEqual({ level: "warning", message: "dataplane warning: slow netsh" });
    expect(classifyHelperStderrLine("dataplane error: teardown failed")).toEqual({ level: "error", message: "dataplane error: teardown failed" });
    expect(classifyHelperStderrLine("dataplane info: started")).toEqual({ level: "info", message: "dataplane info: started" });
    expect(classifyHelperStderrLine('{"level":"error","message":"listen failed"}')).toEqual({ level: "error", message: "listen failed" });
    expect(classifyHelperStderrLine("warning: the clock jumped")).toEqual({ level: "warning", message: "warning: the clock jumped" });
  });

  it("does not file what the helper wrote outside its own forms as progress", () => {
    // Its routine lines all carry the `dataplane <level>:` prefix; an
    // unprefixed one is a failure before the protocol is up, or a crash.
    expect(classifyHelperStderrLine("  TUN read stopped  ")).toEqual({ level: "warning", message: "TUN read stopped" });
    expect(classifyHelperStderrLine("Could not limit DLL loading to the system directory: Access is denied.")).toMatchObject({ level: "warning" });
    // The Go runtime names the cause of a crash on its first line.
    expect(classifyHelperStderrLine("panic: runtime error: invalid memory address or nil pointer dereference")).toMatchObject({ level: "error" });
    expect(classifyHelperStderrLine("fatal error: concurrent map writes")).toMatchObject({ level: "error" });
    expect(classifyHelperStderrLine("goroutine 57 [running]:")).toMatchObject({ level: "warning" });
  });
});
