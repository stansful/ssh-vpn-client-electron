import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import { SessionEndWatcher, type SessionEndWindow } from "../src/main/app/session-end-watcher.js";

class FakeWindow extends EventEmitter implements SessionEndWindow {
  destroyed = false;

  isDestroyed(): boolean {
    return this.destroyed;
  }

  destroy(): void {
    this.destroyed = true;
    this.emit("closed");
  }
}

function watcher(): { watcher: SessionEndWatcher; windows: FakeWindow[]; ended: string[][] } {
  const windows: FakeWindow[] = [];
  const ended: string[][] = [];
  return {
    watcher: new SessionEndWatcher({
      createWindow: () => {
        const window = new FakeWindow();
        windows.push(window);
        return window;
      },
      onSessionEnd: (reasons) => ended.push(reasons)
    }),
    windows,
    ended
  };
}

describe("session end without a window", () => {
  it("hears a Windows sign-out while the app lives in the tray", () => {
    const { watcher: subject, windows, ended } = watcher();
    subject.update({ windows: false, platform: "win32", quitting: false });
    expect(windows).toHaveLength(1);
    subject.update({ windows: false, platform: "win32", quitting: false });
    expect(windows).toHaveLength(1);

    windows[0].emit("session-end", { reasons: ["logoff"] });
    expect(ended).toEqual([["logoff"]]);
  });

  it("gives way to the real window and is never in the way of quitting", () => {
    const { watcher: subject, windows } = watcher();
    subject.update({ windows: false, platform: "win32", quitting: false });
    subject.update({ windows: true, platform: "win32", quitting: false });
    expect(windows[0].destroyed).toBe(true);
    expect(subject.watching).toBe(false);

    subject.update({ windows: false, platform: "win32", quitting: true });
    expect(windows).toHaveLength(1);
  });

  it("is only for Windows", () => {
    const { watcher: subject, windows } = watcher();
    for (const platform of ["darwin", "linux"] as const) {
      subject.update({ windows: false, platform, quitting: false });
    }
    expect(windows).toHaveLength(0);
  });

  it("notices a window that closed on its own", () => {
    const { watcher: subject, windows } = watcher();
    subject.update({ windows: false, platform: "win32", quitting: false });
    windows[0].emit("closed");
    expect(subject.watching).toBe(false);
    subject.update({ windows: false, platform: "win32", quitting: false });
    expect(windows).toHaveLength(2);
  });
});
