import { EventEmitter } from "node:events";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { XrayProcess, XrayVersionRun } from "../src/service/xray/process-utils.js";

const network = vi.hoisted(() => ({
  outcomes: [] as boolean[],
  createConnection: vi.fn(() => {
    const listeners = new Map<string, (...args: unknown[]) => void>();
    const socket = {
      setTimeout: vi.fn(),
      destroy: vi.fn(),
      once: vi.fn((event: string, listener: (...args: unknown[]) => void) => {
        listeners.set(event, listener);
        return socket;
      })
    };
    queueMicrotask(() => {
      const ready = network.outcomes.shift() ?? false;
      listeners.get(ready ? "connect" : "error")?.(ready ? undefined : new Error("refused"));
    });
    return socket;
  }),
  createServer: vi.fn()
}));

vi.mock("node:net", () => ({
  default: {
    createConnection: network.createConnection,
    createServer: network.createServer
  }
}));

const {
  parseXrayVersion,
  reserveDistinctLocalTcpPorts,
  terminateProcess,
  waitForProcessStartup,
  XrayVersionDetector
} = await import("../src/service/xray/process-utils.js");

describe("Xray process startup utilities", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    network.outcomes.length = 0;
  });

  it("retries duplicate reservations until it has distinct endpoints", async () => {
    const reserve = vi.fn()
      .mockResolvedValueOnce({ host: "127.0.0.1", port: 30000 })
      .mockResolvedValueOnce({ host: "127.0.0.1", port: 30000 })
      .mockResolvedValueOnce({ host: "127.0.0.1", port: 30001 });

    await expect(reserveDistinctLocalTcpPorts(2, reserve)).resolves.toEqual([
      { host: "127.0.0.1", port: 30000 },
      { host: "127.0.0.1", port: 30001 }
    ]);
    expect(reserve).toHaveBeenCalledTimes(3);
  });

  it("resolves only after every requested listener accepts connections", async () => {
    network.outcomes.push(true, true);
    const processHandle = new FakeProcess();

    await expect(waitForProcessStartup(processHandle as unknown as XrayProcess, [
      { host: "127.0.0.1", port: 30000 },
      { host: "127.0.0.1", port: 30001 }
    ], {
      timeoutMs: 500,
      retryIntervalMs: 5,
      connectTimeoutMs: 50
    })).resolves.toBeUndefined();
    expect(network.createConnection).toHaveBeenCalledTimes(2);
  });

  it("rejects and names listeners that never become ready", async () => {
    network.outcomes.push(false, false, false, false, false, false, false, false);
    const processHandle = new FakeProcess();

    await expect(waitForProcessStartup(processHandle as unknown as XrayProcess, [
      { host: "127.0.0.1", port: 30002 }
    ], {
      timeoutMs: 10,
      retryIntervalMs: 2,
      connectTimeoutMs: 1
    })).rejects.toThrow("127.0.0.1:30002");
  });

  it("cancels listener polling through an external lifecycle signal", async () => {
    network.outcomes.push(false);
    const processHandle = new FakeProcess();
    const controller = new AbortController();
    const waiting = waitForProcessStartup(processHandle as unknown as XrayProcess, [
      { host: "127.0.0.1", port: 30003 }
    ], { timeoutMs: 10_000, signal: controller.signal });

    controller.abort();
    await expect(waiting).rejects.toThrow("cancelled");
  });

  it("stops waiting at an absolute deadline when a child never emits close", async () => {
    vi.useFakeTimers();
    try {
      const processHandle = new FakeProcess();
      const terminating = terminateProcess(processHandle as unknown as XrayProcess);

      await vi.advanceTimersByTimeAsync(3000);
      await expect(terminating).resolves.toBeUndefined();
      expect(processHandle.kill).toHaveBeenNthCalledWith(1, "SIGTERM");
      expect(processHandle.kill).toHaveBeenNthCalledWith(2, "SIGKILL");
      expect(processHandle.listenerCount("close")).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

// The version picks the config shape where Xray releases differ - port
// hopping moved in 26.9.9 - so it has to come from the binary actually run,
// which a user can swap with SHADOW_SSH_XRAY_PATH.
describe("Xray version detection", () => {
  it("reads the version from Xray's banner", () => {
    expect(parseXrayVersion(
      "Xray 26.3.27 (Xray, Penetrates Everything.) Custom (go1.26.1 darwin/arm64)\nA unified platform for anti-censorship.\n"
    )).toBe("26.3.27");
    expect(parseXrayVersion("Xray v1.8.24 (Xray, Penetrates Everything.)")).toBe("1.8.24");
    expect(parseXrayVersion("")).toBeUndefined();
    expect(parseXrayVersion("V2Ray 5.16.1 (V2Fly, a community-driven edition of V2Ray.)")).toBeUndefined();
  });

  it("asks each binary once, and again only when the file changes", async () => {
    let file = { mtimeMs: 1, size: 100 };
    const run = vi.fn<(executablePath: string, timeoutMs: number) => Promise<XrayVersionRun>>(
      async () => answered("Xray 26.3.27 (Xray, Penetrates Everything.)\n")
    );
    const detector = new XrayVersionDetector({ run, stat: async () => file });

    // Concurrent connects share the one spawn.
    await expect(Promise.all([detector.detect("/opt/xray"), detector.detect("/opt/xray")])).resolves.toEqual(["26.3.27", "26.3.27"]);
    await expect(detector.detect("/opt/xray")).resolves.toBe("26.3.27");
    expect(run).toHaveBeenCalledTimes(1);
    expect(run).toHaveBeenCalledWith("/opt/xray", 3_000);

    await detector.detect("/opt/other/xray");
    expect(run).toHaveBeenCalledTimes(2);

    // Replaced in place by an update.
    file = { mtimeMs: 2, size: 100 };
    run.mockResolvedValueOnce(answered("Xray 26.9.9 (Xray, Penetrates Everything.)\n"));
    await expect(detector.detect("/opt/xray")).resolves.toBe("26.9.9");
    expect(run).toHaveBeenCalledTimes(3);
  });

  it("answers undefined instead of throwing, and does not keep asking a binary that answered", async () => {
    const stat = async (): Promise<{ mtimeMs: number; size: number }> => ({ mtimeMs: 1, size: 1 });
    // It ran and exited, just not as Xray: asking again would say the same.
    const notXray = vi.fn(async (): Promise<XrayVersionRun> => answered("V2Ray 5.16.1 (V2Fly, a community-driven edition of V2Ray.)\n"));
    const foreign = new XrayVersionDetector({ run: notXray, stat });
    await expect(foreign.detect("/opt/xray")).resolves.toBeUndefined();
    await expect(foreign.detect("/opt/xray")).resolves.toBeUndefined();
    expect(notXray).toHaveBeenCalledTimes(1);

    const rejecting = new XrayVersionDetector({
      run: async () => {
        throw new Error("spawn EACCES");
      },
      stat
    });
    await expect(rejecting.detect("/opt/xray")).resolves.toBeUndefined();

    const throwing = new XrayVersionDetector({
      run: () => {
        throw new Error("thrown before a promise existed");
      },
      stat
    });
    await expect(throwing.detect("/opt/xray")).resolves.toBeUndefined();

    const malformed = new XrayVersionDetector({ run: async () => undefined as unknown as XrayVersionRun, stat });
    await expect(malformed.detect("/opt/xray")).resolves.toBeUndefined();

    const run = vi.fn(async () => answered("Xray 26.3.27"));
    const missing = new XrayVersionDetector({
      run,
      stat: async () => {
        throw new Error("ENOENT");
      }
    });
    await expect(missing.detect("/missing/xray")).resolves.toBeUndefined();
    expect(run).not.toHaveBeenCalled();
  });

  // A timeout or a spawn failure (EAGAIN, EMFILE) says nothing lasting about
  // the binary. Kept, it would pin the bundled config shape on a swapped
  // binary until the file changed - a whole session of broken port hopping.
  it("asks again after a run that timed out or could not start", async () => {
    const stat = async (): Promise<{ mtimeMs: number; size: number }> => ({ mtimeMs: 1, size: 1 });
    let release!: (run: XrayVersionRun) => void;
    const run = vi.fn<(executablePath: string, timeoutMs: number) => Promise<XrayVersionRun>>()
      .mockImplementationOnce(() => new Promise((resolve) => {
        release = resolve;
      }))
      .mockResolvedValueOnce({ output: "", completed: false })
      .mockResolvedValue(answered("Xray 26.3.27 (Xray, Penetrates Everything.)\n"));
    const detector = new XrayVersionDetector({ run, stat });

    // Concurrent connects still share the one run that is in flight...
    const first = Promise.all([detector.detect("/opt/xray"), detector.detect("/opt/xray")]);
    await vi.waitFor(() => expect(run).toHaveBeenCalledTimes(1));
    release({ output: "", completed: false });
    await expect(first).resolves.toEqual([undefined, undefined]);
    expect(run).toHaveBeenCalledTimes(1);

    // ...but its timeout is not remembered, nor is a spawn failure after it.
    await expect(detector.detect("/opt/xray")).resolves.toBeUndefined();
    expect(run).toHaveBeenCalledTimes(2);
    await expect(detector.detect("/opt/xray")).resolves.toBe("26.3.27");
    expect(run).toHaveBeenCalledTimes(3);

    // A run that completed is kept.
    await expect(detector.detect("/opt/xray")).resolves.toBe("26.3.27");
    expect(run).toHaveBeenCalledTimes(3);
  });

  it.skipIf(process.platform === "win32")("tells a real run that timed out from one that answered", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "shadow-ssh-xray-version-"));
    try {
      // Hangs until a marker file exists, then answers like Xray. Every run
      // is counted, and the script itself never changes, so its signature
      // stays the same throughout.
      const executable = path.join(directory, "xray");
      await writeFile(executable, [
        "#!/bin/sh",
        "echo run >> \"$0.runs\"",
        "if [ -f \"$0.ready\" ]; then echo \"Xray 26.3.27 (Xray, Penetrates Everything.)\"; exit 0; fi",
        "exec sleep 5",
        ""
      ].join("\n"));
      await chmod(executable, 0o755);
      const runs = async (): Promise<number> => (await readFile(`${executable}.runs`, "utf8")).split("\n").filter(Boolean).length;
      // Long enough for the shell to start and answer while the whole suite
      // runs in parallel; 300 ms cut the hanging run off before it was counted.
      const detector = new XrayVersionDetector({ timeoutMs: 1_500 });

      await expect(detector.detect(executable)).resolves.toBeUndefined();
      expect(await runs()).toBe(1);

      await writeFile(`${executable}.ready`, "");
      await expect(detector.detect(executable)).resolves.toBe("26.3.27");
      await expect(detector.detect(executable)).resolves.toBe("26.3.27");
      expect(await runs()).toBe(2);

      // A binary that answers but is not Xray is asked only once too.
      const foreign = path.join(directory, "not-xray");
      await writeFile(foreign, "#!/bin/sh\necho run >> \"$0.runs\"\necho \"not xray\"\nexit 3\n");
      await chmod(foreign, 0o755);
      const foreignDetector = new XrayVersionDetector({ timeoutMs: 5_000 });
      await expect(foreignDetector.detect(foreign)).resolves.toBeUndefined();
      await expect(foreignDetector.detect(foreign)).resolves.toBeUndefined();
      expect((await readFile(`${foreign}.runs`, "utf8")).split("\n").filter(Boolean)).toHaveLength(1);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }, 20_000);

  it("survives a real binary that is not Xray", async () => {
    // Node reads "version" as a script it cannot find, prints nothing on
    // stdout and exits non-zero.
    await expect(new XrayVersionDetector({ timeoutMs: 5_000 }).detect(process.execPath)).resolves.toBeUndefined();
  });
});

function answered(output: string): XrayVersionRun {
  return { output, completed: true };
}

class FakeProcess extends EventEmitter {
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  readonly kill = vi.fn(() => true);
}
