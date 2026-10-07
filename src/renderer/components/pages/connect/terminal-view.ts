import type { TerminalLine } from "../../../../shared/types.js";

/** One rendered row of the server terminal. */
export interface TerminalDisplayLine {
  text: string;
  /** `.term` tone class: "t-dim" for system lines, "t-warn" when the server closed the shell. */
  cls: string;
}

export interface TerminalDisplay {
  lines: TerminalDisplayLine[];
  /** Older output was left out of the view (it is still in the main process history). */
  truncated: boolean;
}

/** Enough for any screen of output while keeping the DOM small. */
export const MAX_TERMINAL_VIEW_CHARACTERS = 200_000;
export const MAX_TERMINAL_VIEW_LINES = 1000;

// The shell runs as xterm-256color, so prompts and tools colour their output;
// the view is plain text, so escape sequences are dropped rather than shown raw.
// eslint-disable-next-line no-control-regex
const ANSI_SEQUENCE = /\u001b\[[0-?]*[ -/]*[@-~]|\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)|\u001b[@-Z\\-_]/gu;
// eslint-disable-next-line no-control-regex
const OTHER_CONTROL = /[\u0000-\u0007\u000b\u000c\u000e-\u001f\u007f]/gu;

export function stripAnsi(text: string): string {
  return text.replace(ANSI_SEQUENCE, "");
}

/** Applies carriage returns (a progress line overwrites itself) and backspaces to one line. */
function applyControls(existing: string, part: string): string {
  let text = existing;
  if (part.includes("\r")) {
    const segments = part.split("\r").filter((segment) => segment.length > 0);
    if (segments.length === 0) {
      return text;
    }
    text = part.startsWith("\r") || segments.length > 1 ? segments[segments.length - 1] : text + segments[0];
  } else {
    text += part;
  }
  if (text.includes("\b")) {
    let result = "";
    for (const char of text) {
      result = char === "\b" ? result.slice(0, -1) : result + char;
    }
    text = result;
  }
  return text.replace(OTHER_CONTROL, "");
}

function toneOf(line: Pick<TerminalLine, "stream" | "text">): string {
  if (line.stream !== "system") {
    return "";
  }
  return /closed by the server/iu.test(line.text) ? "t-warn" : "t-dim";
}

/**
 * Turns the main process's output chunks (≈50 ms of one stream each, or a
 * system line) into display rows. Only the tail is processed so long
 * sessions stay cheap to re-render.
 */
export function buildTerminalDisplay(
  history: readonly TerminalLine[],
  maxCharacters = MAX_TERMINAL_VIEW_CHARACTERS,
  maxLines = MAX_TERMINAL_VIEW_LINES
): TerminalDisplay {
  let budget = maxCharacters;
  let start = history.length;
  let firstText: string | undefined;
  while (start > 0 && budget > 0) {
    const text = history[start - 1].text;
    start -= 1;
    if (text.length > budget) {
      firstText = text.slice(-budget);
      budget = 0;
    } else {
      budget -= text.length;
    }
  }
  let truncated = start > 0 || firstText !== undefined;

  const rows: Array<{ text: string; stream: TerminalLine["stream"]; raw: string }> = [];
  let current: { text: string; stream: TerminalLine["stream"]; raw: string } | undefined;
  for (let index = start; index < history.length; index += 1) {
    const chunk = history[index];
    const source = index === start && firstText !== undefined ? firstText : chunk.text;
    const parts = stripAnsi(source).replace(/\r\n/gu, "\n").split("\n");
    parts.forEach((part, partIndex) => {
      if (partIndex > 0) {
        rows.push(current ?? { text: "", stream: chunk.stream, raw: "" });
        current = undefined;
      }
      if (part === "") {
        return;
      }
      current ??= { text: "", stream: chunk.stream, raw: "" };
      current.text = applyControls(current.text, part);
      current.raw += part;
    });
  }
  if (current && current.text !== "") {
    rows.push(current);
  }

  if (rows.length > maxLines) {
    rows.splice(0, rows.length - maxLines);
    truncated = true;
  }
  return {
    lines: rows.map((row) => ({ text: row.text, cls: toneOf({ stream: row.stream, text: row.raw }) })),
    truncated
  };
}

export type ShellMarker = "opened" | "closed-by-server" | "closed";

/**
 * The latest shell event the service wrote into the output, looking only at
 * lines after `afterId` (the last line present when the shell was asked to open).
 */
export function lastShellMarker(history: readonly TerminalLine[], afterId?: string): ShellMarker | undefined {
  for (let index = history.length - 1; index >= 0; index -= 1) {
    const line = history[index];
    if (afterId !== undefined && line.id === afterId) {
      return undefined;
    }
    if (line.stream !== "system") {
      continue;
    }
    if (/closed by the server/iu.test(line.text)) {
      return "closed-by-server";
    }
    if (/shell channel opened/iu.test(line.text)) {
      return "opened";
    }
    if (/shell channel closed/iu.test(line.text)) {
      return "closed";
    }
  }
  return undefined;
}

export type ShellPhase = "opening" | "open" | "failed";

/** What the page asked of the shell in one session (keyed by when the session connected). */
export interface ShellRecord {
  session: string;
  phase: ShellPhase;
  /** Last output line when the open was requested; markers before it belong to an older shell. */
  afterId?: string;
  error?: string;
}

/**
 * offline: no SSH session · idle: connected, panel collapsed · opening ·
 * live · closed: the server ended the shell · failed: the shell didn't open.
 */
export type TerminalState = "offline" | "idle" | "opening" | "live" | "closed" | "failed";

export function terminalState(input: {
  /** SSH is the active transport and connected. */
  live: boolean;
  expanded: boolean;
  session: string;
  record?: ShellRecord;
  history: readonly TerminalLine[];
}): TerminalState {
  if (!input.live) {
    return "offline";
  }
  const record = input.record && input.record.session === input.session ? input.record : undefined;
  if (!record) {
    return input.expanded ? "opening" : "idle";
  }
  if (record.phase === "opening") {
    return "opening";
  }
  if (record.phase === "failed") {
    return "failed";
  }
  return lastShellMarker(input.history, record.afterId) === "closed-by-server" ? "closed" : "live";
}

/** The last row looks like a shell prompt waiting for input ("root@fra-01:~# "). */
export function isPromptLine(text: string): boolean {
  return /[$#%>]\s?$/u.test(text) && text.trim().length > 1;
}
