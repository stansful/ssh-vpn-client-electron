import { describe, expect, it } from "vitest";
import {
  buildTerminalDisplay,
  isPromptLine,
  lastShellMarker,
  stripAnsi,
  terminalState
} from "../src/renderer/components/pages/connect/terminal-view.js";
import type { ShellRecord } from "../src/renderer/components/pages/connect/terminal-view.js";
import { isOpenPending, nextShellRecord, shellNeedsClose, type ShellRecordEvent } from "../src/renderer/components/pages/connect/shell-record.js";
import type { TerminalLine } from "../src/shared/types.js";

let counter = 0;
function chunk(stream: TerminalLine["stream"], text: string): TerminalLine {
  counter += 1;
  return { id: `t${counter}`, at: "2026-10-06T12:00:00.000Z", stream, text };
}

describe("Terminal display", () => {
  it("splits chunks into rows and dims system lines", () => {
    const display = buildTerminalDisplay([
      chunk("system", "SSH shell channel opened.\n"),
      chunk("stdout", "root@fra-01:~# uptime\r\n 12:04:31 up 41 days\r\nroot@fra-01:~# ")
    ]);
    expect(display.lines).toEqual([
      { text: "SSH shell channel opened.", cls: "t-dim" },
      { text: "root@fra-01:~# uptime", cls: "" },
      { text: " 12:04:31 up 41 days", cls: "" },
      { text: "root@fra-01:~# ", cls: "" }
    ]);
    expect(display.truncated).toBe(false);
  });

  it("ends a partial prompt before a system line and marks a server close", () => {
    const display = buildTerminalDisplay([chunk("stdout", "root@fra-01:~# exit\r\nlogout\r\n"), chunk("system", "\nSSH shell channel closed by the server.\n")]);
    expect(display.lines.map((line) => line.text)).toEqual(["root@fra-01:~# exit", "logout", "", "SSH shell channel closed by the server."]);
    expect(display.lines.at(-1)?.cls).toBe("t-warn");
  });

  it("joins a line that arrives in several chunks", () => {
    const display = buildTerminalDisplay([chunk("stdout", "Filesystem   Size"), chunk("stdout", "  Used\n")]);
    expect(display.lines).toEqual([{ text: "Filesystem   Size  Used", cls: "" }]);
  });

  it("drops colour codes and applies carriage returns and backspaces", () => {
    expect(stripAnsi("\u001b[01;32mroot@fra-01\u001b[00m:~# ")).toBe("root@fra-01:~# ");
    const display = buildTerminalDisplay([chunk("stdout", "10%\r50%\r100%\nab\bc\u0007\n")]);
    expect(display.lines.map((line) => line.text)).toEqual(["100%", "ac"]);
  });

  it("keeps only the tail of long output", () => {
    const many = Array.from({ length: 30 }, (_, index) => chunk("stdout", `line ${index}\n`));
    const byLines = buildTerminalDisplay(many, 100_000, 10);
    expect(byLines.lines).toHaveLength(10);
    expect(byLines.lines[0].text).toBe("line 20");
    expect(byLines.truncated).toBe(true);

    const byChars = buildTerminalDisplay([chunk("stdout", "0123456789\nabcdef\n")], 9);
    expect(byChars.lines.map((line) => line.text)).toEqual(["9", "abcdef"]);
    expect(byChars.truncated).toBe(true);
  });

  it("recognises a waiting prompt", () => {
    expect(isPromptLine("root@fra-01:~# ")).toBe(true);
    expect(isPromptLine("pi@lab:~ $")).toBe(true);
    expect(isPromptLine("load average: 0.08")).toBe(false);
    expect(isPromptLine("#")).toBe(false);
  });
});

describe("Shell state", () => {
  const opened = chunk("system", "SSH shell channel opened.\n");
  const closedByServer = chunk("system", "\nSSH shell channel closed by the server.\n");
  const userClosed = chunk("system", "\nSSH shell channel closed.\n");

  it("finds the newest shell marker after the open request", () => {
    expect(lastShellMarker([opened, chunk("stdout", "ls\n")])).toBe("opened");
    expect(lastShellMarker([opened, closedByServer])).toBe("closed-by-server");
    expect(lastShellMarker([opened, userClosed])).toBe("closed");
    expect(lastShellMarker([opened, closedByServer], closedByServer.id)).toBeUndefined();
    expect(lastShellMarker([])).toBeUndefined();
  });

  it("walks offline → opening → live → closed → reopened", () => {
    const base = { expanded: true, session: "s1" };
    expect(terminalState({ ...base, live: false, history: [] })).toBe("offline");
    expect(terminalState({ ...base, live: true, history: [] })).toBe("opening");
    expect(terminalState({ ...base, expanded: false, live: true, history: [] })).toBe("idle");
    expect(terminalState({ ...base, live: true, history: [opened], record: { session: "s1", phase: "open" } })).toBe("live");
    expect(terminalState({ ...base, live: true, history: [opened, closedByServer], record: { session: "s1", phase: "open" } })).toBe("closed");
    expect(
      terminalState({ ...base, live: true, history: [opened, closedByServer], record: { session: "s1", phase: "open", afterId: closedByServer.id } })
    ).toBe("live");
  });

  it("reports a failed open and forgets records from an older session", () => {
    expect(terminalState({ live: true, expanded: true, session: "s1", history: [], record: { session: "s1", phase: "failed", error: "PTY allocation failed." } })).toBe(
      "failed"
    );
    expect(terminalState({ live: true, expanded: true, session: "s2", history: [], record: { session: "s1", phase: "open" } })).toBe("opening");
  });
});

describe("Shell record across open and collapse", () => {
  const replay = (events: ShellRecordEvent[], start?: ShellRecord): ShellRecord | undefined => events.reduce(nextShellRecord, start);
  const view = (record: ShellRecord | undefined, history: TerminalLine[] = []) =>
    terminalState({ live: true, expanded: true, session: "s1", record, history });

  it("opens again after a collapse and re-expand while the first open was still on its way", () => {
    // Expand (open #1), collapse (close), expand again (open #2), then the answers arrive in order.
    let record = replay([
      { type: "open", session: "s1", attempt: 1 },
      { type: "close" }
    ]);
    expect(record).toBeUndefined();
    // The panel isn't blocked by the first open: a new request goes out.
    expect(isOpenPending(record, "s1")).toBe(false);
    record = nextShellRecord(record, { type: "open", session: "s1", attempt: 2, afterId: "t-before" });
    expect(isOpenPending(record, "s1")).toBe(true);

    // Open #1 answers first; main has queued close and open #2 behind it, so it doesn't count.
    record = nextShellRecord(record, { type: "opened", session: "s1", attempt: 1 });
    expect(record).toMatchObject({ phase: "opening", attempt: 2 });
    expect(view(record)).toBe("opening");

    // Open #2 answers: the shell is live and input is enabled.
    record = nextShellRecord(record, { type: "opened", session: "s1", attempt: 2 });
    expect(record).toEqual({ session: "s1", phase: "open", attempt: 2, afterId: "t-before" });
    const opened = chunk("system", "SSH shell channel opened.\n");
    expect(view(record, [chunk("system", "\nSSH shell channel closed.\n"), opened])).toBe("live");
  });

  it("ignores a late failure from a replaced open and answers after a collapse", () => {
    const opening = replay([{ type: "open", session: "s1", attempt: 1 }, { type: "close" }, { type: "open", session: "s1", attempt: 2 }]);
    expect(nextShellRecord(opening, { type: "open-failed", session: "s1", attempt: 1, error: "late" })).toBe(opening);
    expect(nextShellRecord(opening, { type: "open-failed", session: "s1", attempt: 2, error: "PTY allocation failed." })).toMatchObject({
      phase: "failed",
      error: "PTY allocation failed."
    });
    // Collapsed for good: the answer of the open that was on its way changes nothing.
    const collapsed = replay([{ type: "open", session: "s1", attempt: 3 }, { type: "close" }, { type: "opened", session: "s1", attempt: 3 }]);
    expect(collapsed).toBeUndefined();
    expect(terminalState({ live: true, expanded: false, session: "s1", record: collapsed, history: [] })).toBe("idle");
  });

  it("ignores answers for another session and answers that arrive twice", () => {
    const opening = nextShellRecord(undefined, { type: "open", session: "s2", attempt: 4 });
    expect(nextShellRecord(opening, { type: "opened", session: "s1", attempt: 4 })).toBe(opening);
    const open = nextShellRecord(opening, { type: "opened", session: "s2", attempt: 4 });
    expect(nextShellRecord(open, { type: "open-failed", session: "s2", attempt: 4, error: "late" })).toBe(open);
  });

  it("dedupes a repeated open only while one is still pending for the session", () => {
    expect(isOpenPending(undefined, "s1")).toBe(false);
    expect(isOpenPending({ session: "s1", phase: "opening", attempt: 1 }, "s1")).toBe(true);
    expect(isOpenPending({ session: "s1", phase: "opening", attempt: 1 }, "s2")).toBe(false);
    expect(isOpenPending({ session: "s1", phase: "failed", attempt: 1 }, "s1")).toBe(false);
    expect(isOpenPending({ session: "s1", phase: "open", attempt: 1 }, "s1")).toBe(false);
  });

  it("closes a shell that is open or still opening, never after a failed open", () => {
    expect(shellNeedsClose({ session: "s1", phase: "opening", attempt: 1 }, "s1")).toBe(true);
    expect(shellNeedsClose({ session: "s1", phase: "open", attempt: 1 }, "s1")).toBe(true);
    expect(shellNeedsClose({ session: "s1", phase: "failed", attempt: 1 }, "s1")).toBe(false);
    expect(shellNeedsClose({ session: "s0", phase: "open", attempt: 1 }, "s1")).toBe(false);
    expect(shellNeedsClose(undefined, "s1")).toBe(false);
  });
});
