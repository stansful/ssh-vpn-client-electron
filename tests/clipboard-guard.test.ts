import { describe, expect, it } from "vitest";
import { SECRET_CLIPBOARD_CLEAR_MS, SecretClipboardGuard } from "../src/main/app/clipboard-guard.js";

function fakeClipboard(initial = "") {
  const state = { text: initial, clears: 0 };
  return {
    state,
    clipboard: {
      readText: () => state.text,
      writeText: (text: string) => {
        state.text = text;
      },
      clear: () => {
        state.text = "";
        state.clears += 1;
      }
    }
  };
}

function manualTimers() {
  const timers = new Map<number, () => void>();
  let next = 0;
  return {
    timers,
    delays: [] as number[],
    setTimer(callback: () => void, ms: number) {
      next += 1;
      timers.set(next, callback);
      this.delays.push(ms);
      return next;
    },
    clearTimer(timer: unknown) {
      timers.delete(timer as number);
    },
    fireAll() {
      for (const [id, callback] of [...timers]) {
        timers.delete(id);
        callback();
      }
    }
  };
}

const SECRET = "vless://0b1c2d3e@203.0.113.10:443?security=reality#Frankfurt";

describe("secret clipboard guard", () => {
  it("clears a copied secret after 45 seconds if it is still there", () => {
    const { state, clipboard } = fakeClipboard();
    const timers = manualTimers();
    const guard = new SecretClipboardGuard(clipboard, { setTimer: timers.setTimer.bind(timers), clearTimer: timers.clearTimer });

    guard.writeSecret(SECRET);
    expect(state.text).toBe(SECRET);
    expect(timers.delays).toEqual([SECRET_CLIPBOARD_CLEAR_MS]);
    expect(SECRET_CLIPBOARD_CLEAR_MS).toBe(45_000);

    timers.fireAll();
    expect(state.text).toBe("");
    expect(state.clears).toBe(1);
  });

  it("never clears what the user copied afterwards", () => {
    const { state, clipboard } = fakeClipboard();
    const timers = manualTimers();
    const guard = new SecretClipboardGuard(clipboard, { setTimer: timers.setTimer.bind(timers), clearTimer: timers.clearTimer });

    guard.writeSecret(SECRET);
    state.text = "notes for later";
    timers.fireAll();

    expect(state.text).toBe("notes for later");
    expect(state.clears).toBe(0);
  });

  it("hands the renderer nothing while the clipboard holds the secret, and the user's text after", () => {
    const { state, clipboard } = fakeClipboard("before");
    const guard = new SecretClipboardGuard(clipboard, { setTimer: () => 1, clearTimer: () => undefined });

    expect(guard.readText()).toBe("before");
    guard.writeSecret(SECRET);
    expect(guard.readText()).toBeUndefined();

    state.text = "user text";
    expect(guard.readText()).toBe("user text");
    // Copying the same secret by hand later is the user's business.
    state.text = SECRET;
    expect(guard.readText()).toBe(SECRET);
  });

  it("clears on quit and forgets the secret", () => {
    const { state, clipboard } = fakeClipboard();
    const timers = manualTimers();
    const guard = new SecretClipboardGuard(clipboard, { setTimer: timers.setTimer.bind(timers), clearTimer: timers.clearTimer });

    guard.writeSecret(SECRET);
    guard.clearIfStillHeld();
    expect(state.text).toBe("");
    expect(timers.timers.size).toBe(0);

    state.text = SECRET;
    guard.clearIfStillHeld();
    expect(state.text).toBe(SECRET);
  });

  it("restarts the timer for a second copy and keeps no plaintext", () => {
    const { clipboard } = fakeClipboard();
    const timers = manualTimers();
    const guard = new SecretClipboardGuard(clipboard, { setTimer: timers.setTimer.bind(timers), clearTimer: timers.clearTimer });

    guard.writeSecret(SECRET);
    guard.writeSecret("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n");
    expect(timers.timers.size).toBe(1);
    expect(JSON.stringify(Object.values(guard as unknown as Record<string, unknown>).filter((value) => typeof value === "string"))).not.toContain(
      "OPENSSH"
    );
  });
});
