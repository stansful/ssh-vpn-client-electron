import { describe, expect, it } from "vitest";
import {
  buildTerminalDisplay,
  isPromptLine,
  lastShellMarker,
  stripAnsi,
  terminalState
} from "../src/renderer/components/pages/connect/terminal-view.js";
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
