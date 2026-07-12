import { describe, expect, it } from "vitest";
import {
  appendBoundedTerminalLine,
  appendBoundedTerminalLines,
  MAX_TERMINAL_HISTORY_BYTES,
  utf8ByteLength
} from "../src/shared/terminal-history.js";
import type { TerminalLine } from "../src/shared/types.js";

describe("bounded terminal history", () => {
  it("caps snapshot terminal payloads to a battery- and memory-friendly size", () => {
    expect(MAX_TERMINAL_HISTORY_BYTES).toBe(2 * 1024 * 1024);
  });

  it("keeps the newest lines within both count and UTF-8 byte limits", () => {
    let lines: TerminalLine[] = [];
    lines = appendBoundedTerminalLine(lines, line("one", "1234"), 3, 8);
    lines = appendBoundedTerminalLine(lines, line("two", "5678"), 3, 8);
    lines = appendBoundedTerminalLine(lines, line("three", "90"), 3, 8);

    expect(lines.map((entry) => entry.id)).toEqual(["two", "three"]);
    expect(lines.reduce((total, entry) => total + utf8ByteLength(entry.text), 0)).toBeLessThanOrEqual(8);
  });

  it("counts Unicode payload bytes without allocating an encoded copy", () => {
    expect(utf8ByteLength("Aé😀")).toBe(7);
  });

  it("drops an individual oversized chunk without discarding bounded history", () => {
    const previous = [line("old", "ok")];
    expect(appendBoundedTerminalLine(previous, line("huge", "12345"), 10, 4)).toEqual(previous);
  });

  it("appends a renderer burst in one bounded operation while preserving line order", () => {
    const previous = [line("old", "12")];
    const next = appendBoundedTerminalLines(
      previous,
      [line("one", "34"), line("oversized", "123456789"), line("two", "56")],
      3,
      6
    );

    expect(next.map((entry) => entry.id)).toEqual(["old", "one", "two"]);
    expect(next.map((entry) => entry.text).join("")).toBe("123456");
  });
});

function line(id: string, text: string): TerminalLine {
  return { id, text, at: "", stream: "stdout" };
}
