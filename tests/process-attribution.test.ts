import { describe, expect, it, vi } from "vitest";
import { parseNativeProcessConnections } from "../src/service/local-ipc-protocol.js";
import { NativeProcessAttribution } from "../src/service/process-attribution.js";

describe("native process connection payload", () => {
  it("keeps usable rows and drops malformed ones", () => {
    const rows = parseNativeProcessConnections({
      connections: [
        { pid: 10, processName: "Telegram.exe", localAddress: "127.0.0.1", localPort: 41001, remoteAddress: "1.1.1.1", remotePort: 443, protocol: "tcp4" },
        { pid: 11, processName: "", localPort: 41002 },
        { pid: 12, processName: "chrome.exe", localPort: 0 },
        { pid: 13, processName: "chrome.exe", localPort: 70000 },
        "not-a-row"
      ]
    });

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ processName: "Telegram.exe", localPort: 41001 });
  });

  it("returns nothing for a payload without connections", () => {
    expect(parseNativeProcessConnections(undefined)).toEqual([]);
    expect(parseNativeProcessConnections({})).toEqual([]);
  });
});

describe("native process attribution", () => {
  it("normalizes process names and resolves the owner of a local port", async () => {
    const attribution = new NativeProcessAttribution({
      executablePath: "unused",
      snapshotProvider: async () => new Map([[41001, "Telegram.exe"]])
    });

    // Rule values are stored lowercase with an .exe suffix, so the snapshot has
    // to be normalized the same way or no rule would ever match.
    await expect(attribution.resolveProcessName(41001)).resolves.toBe("Telegram.exe");
    await expect(attribution.resolveProcessName(41002)).resolves.toBeUndefined();
    await attribution.dispose();
  });

  it("bounds a burst of concurrent lookups to at most two snapshots", async () => {
    const snapshotProvider = vi.fn(async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      return new Map([[41001, "telegram.exe"], [41002, "chrome.exe"]]);
    });
    const attribution = new NativeProcessAttribution({ executablePath: "unused", snapshotProvider });

    // A browser hands the proxy dozens of sockets in one tick. Each must not
    // cost its own syscall, but none may be answered from a snapshot older
    // than itself, so the burst shares one follow-up capture.
    const owners = await Promise.all([
      attribution.resolveProcessName(41001),
      attribution.resolveProcessName(41002),
      attribution.resolveProcessName(41001),
      attribution.resolveProcessName(41002)
    ]);

    expect(owners).toEqual(["telegram.exe", "chrome.exe", "telegram.exe", "chrome.exe"]);
    expect(snapshotProvider.mock.calls.length).toBeLessThanOrEqual(2);
    await attribution.dispose();
  });

  it("takes a fresh snapshot for a connection that did not exist yet", async () => {
    let generation = 0;
    const snapshotProvider = vi.fn(async () => {
      generation += 1;
      return generation === 1 ? new Map<number, string>() : new Map([[41005, "telegram.exe"]]);
    });
    const attribution = new NativeProcessAttribution({ executablePath: "unused", snapshotProvider });

    await expect(attribution.resolveProcessName(41001)).resolves.toBeUndefined();
    await expect(attribution.resolveProcessName(41005)).resolves.toBe("telegram.exe");
    await attribution.dispose();
  });

  it("comes back after the pause instead of staying disabled for the session", async () => {
    // A helper that dies once - a transport reconnect, a helper restart - used
    // to disable per-process routing until the whole application was quit,
    // while domain rules carried on working. That is the failure this pause
    // must not reproduce.
    let broken = true;
    let clock = 1_000;
    const attribution = new NativeProcessAttribution({
      executablePath: "unused",
      snapshotProvider: async () => {
        if (broken) {
          throw new Error("helper is missing");
        }
        return new Map([[41001, "telegram.exe"]]);
      },
      now: () => clock
    });

    await expect(attribution.isAvailable()).resolves.toBe(false);
    for (let attempt = 0; attempt < 8; attempt += 1) {
      await attribution.resolveProcessName(41001);
    }
    await expect(attribution.isAvailable()).resolves.toBe(false);

    broken = false;
    // Still inside the pause: the point of it is not to re-spawn a broken
    // helper on the hot path of every accepted socket.
    await expect(attribution.isAvailable()).resolves.toBe(false);

    clock += 21_000;
    await expect(attribution.isAvailable()).resolves.toBe(true);
    await expect(attribution.resolveProcessName(41001)).resolves.toBe("telegram.exe");
    await attribution.dispose();
  });

  it("reports itself unavailable and stops retrying once snapshots keep failing", async () => {
    const diagnostics: string[] = [];
    const snapshotProvider = vi.fn(async () => {
      throw new Error("helper is missing");
    });
    const attribution = new NativeProcessAttribution({
      executablePath: "unused",
      snapshotProvider,
      onDiagnostic: (_level, message) => diagnostics.push(message)
    });

    // Routing chooses between local enforcement and the PAC fallback on this
    // answer, so a broken helper must never look usable.
    await expect(attribution.isAvailable()).resolves.toBe(false);
    for (let attempt = 0; attempt < 8; attempt += 1) {
      await attribution.resolveProcessName(41001);
    }

    expect(snapshotProvider.mock.calls.length).toBeLessThanOrEqual(5);
    expect(diagnostics.some((message) => message.includes("helper is missing"))).toBe(true);
    expect(diagnostics.some((message) => message.includes("paused"))).toBe(true);
    await attribution.dispose();
  });

  it("stops answering after disposal", async () => {
    const attribution = new NativeProcessAttribution({
      executablePath: "unused",
      snapshotProvider: async () => new Map([[41001, "telegram.exe"]])
    });

    await attribution.resolveProcessName(41001);
    await attribution.dispose();
    await expect(attribution.resolveProcessName(41001)).resolves.toBeUndefined();
    await expect(attribution.isAvailable()).resolves.toBe(false);
  });
});
