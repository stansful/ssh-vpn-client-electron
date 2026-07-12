import type { TerminalLine } from "../../shared/types.js";

export const MAX_TERMINAL_DISPLAY_CHARACTERS = 1024 * 1024;
export const TERMINAL_HISTORY_OMITTED_MARKER = "[... older terminal output omitted from the live view ...]\n";

/**
 * Keeps the DOM-facing terminal string much smaller than the authoritative
 * history. Appends are incremental and snapshot clones are matched by line ID,
 * while reconnects/clears rebuild only the bounded tail.
 */
export class TerminalDisplayBuffer {
  private text = "";
  private lastLineId: string | undefined;
  private firstHistoryLineId: string | undefined;
  private truncated = false;

  constructor(private readonly maxCharacters = MAX_TERMINAL_DISPLAY_CHARACTERS) {}

  update(lines: readonly TerminalLine[], visible = true): string {
    if (!visible) {
      this.reset();
      return "";
    }
    if (lines.length === 0 || this.maxCharacters <= 0) {
      this.reset();
      return "";
    }

    const currentFirstId = lines[0]?.id;
    const previousLineIndex = this.lastLineId ? findLineIndexFromEnd(lines, this.lastLineId) : -1;
    const historyLostDisplayedPrefix =
      !this.truncated &&
      this.firstHistoryLineId !== undefined &&
      this.firstHistoryLineId !== currentFirstId;

    if (previousLineIndex >= 0 && !historyLostDisplayedPrefix) {
      const appended = boundedLineText(lines, previousLineIndex + 1, this.maxCharacters);
      if (appended.text) {
        if (appended.omitted || appended.text.length >= this.maxCharacters) {
          const displacedPreviousText = this.text.length > 0;
          this.text = appended.text;
          this.truncated = this.truncated || displacedPreviousText || appended.omitted;
        } else {
          this.append(appended.text);
        }
      }
    } else {
      this.rebuild(lines);
    }

    this.lastLineId = lines.at(-1)?.id;
    this.firstHistoryLineId = currentFirstId;
    return this.truncated ? `${TERMINAL_HISTORY_OMITTED_MARKER}${this.text}` : this.text;
  }

  private append(value: string): void {
    const combined = `${this.text}${value}`;
    if (combined.length > this.maxCharacters) {
      this.text = combined.slice(-this.maxCharacters);
      this.truncated = true;
    } else {
      this.text = combined;
    }
  }

  private rebuild(lines: readonly TerminalLine[]): void {
    const rebuilt = boundedLineText(lines, 0, this.maxCharacters);
    this.text = rebuilt.text;
    this.truncated = rebuilt.omitted;
  }

  private reset(): void {
    this.text = "";
    this.lastLineId = undefined;
    this.firstHistoryLineId = undefined;
    this.truncated = false;
  }
}

function findLineIndexFromEnd(lines: readonly TerminalLine[], id: string): number {
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    if (lines[index]?.id === id) {
      return index;
    }
  }
  return -1;
}

function boundedLineText(
  lines: readonly TerminalLine[],
  start: number,
  maxCharacters: number
): { text: string; omitted: boolean } {
  let remaining = maxCharacters;
  let index = lines.length - 1;
  let omittedFromPartialLine = false;
  const reverseChunks: string[] = [];
  for (; index >= start && remaining > 0; index -= 1) {
    const value = lines[index]?.text ?? "";
    if (value.length > remaining) {
      reverseChunks.push(value.slice(-remaining));
      omittedFromPartialLine = true;
      remaining = 0;
    } else {
      reverseChunks.push(value);
      remaining -= value.length;
    }
  }
  return { text: reverseChunks.reverse().join(""), omitted: omittedFromPartialLine || index >= start };
}
