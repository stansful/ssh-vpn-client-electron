import type { TerminalLine } from "./types.js";

export const MAX_TERMINAL_HISTORY_LINES = 2000;
// Every snapshot crosses the Electron structured-clone boundary. Keeping this
// below a few MiB avoids transient multi-copy RAM spikes during settings edits
// while still retaining substantial recent terminal output.
export const MAX_TERMINAL_HISTORY_BYTES = 2 * 1024 * 1024;

const byteLengthCache = new WeakMap<readonly TerminalLine[], number>();

/** Appends terminal output while bounding both chunk count and UTF-8 payload bytes. */
export function appendBoundedTerminalLine(
  lines: readonly TerminalLine[],
  line: TerminalLine,
  maxLines = MAX_TERMINAL_HISTORY_LINES,
  maxBytes = MAX_TERMINAL_HISTORY_BYTES
): TerminalLine[] {
  return appendBoundedTerminalLines(lines, [line], maxLines, maxBytes);
}

/**
 * Appends a renderer frame of terminal output with one history allocation.
 * This avoids cloning a multi-MiB tail once per IPC event in a burst.
 */
export function appendBoundedTerminalLines(
  lines: readonly TerminalLine[],
  appendedLines: readonly TerminalLine[],
  maxLines = MAX_TERMINAL_HISTORY_LINES,
  maxBytes = MAX_TERMINAL_HISTORY_BYTES
): TerminalLine[] {
  if (maxLines <= 0 || maxBytes <= 0) {
    const empty: TerminalLine[] = [];
    byteLengthCache.set(empty, 0);
    return empty;
  }
  if (appendedLines.length === 0) {
    return lines.slice();
  }

  const acceptedLines: TerminalLine[] = [];
  let appendedBytes = 0;
  for (const line of appendedLines) {
    const lineBytes = utf8ByteLength(line.text);
    if (lineBytes <= maxBytes) {
      acceptedLines.push(line);
      appendedBytes += lineBytes;
    }
  }
  if (acceptedLines.length === 0) {
    return trimExistingHistory(lines, maxLines, maxBytes);
  }

  let totalBytes = byteLengthCache.get(lines);
  if (totalBytes === undefined) {
    totalBytes = lines.reduce((total, candidate) => total + utf8ByteLength(candidate.text), 0);
  }
  totalBytes += appendedBytes;
  const next = [...lines, ...acceptedLines];
  let start = 0;
  while (next.length - start > maxLines || totalBytes > maxBytes) {
    totalBytes -= utf8ByteLength(next[start]?.text ?? "");
    start += 1;
  }
  const bounded = start === 0 ? next : next.slice(start);
  byteLengthCache.set(bounded, totalBytes);
  return bounded;
}

function trimExistingHistory(lines: readonly TerminalLine[], maxLines: number, maxBytes: number): TerminalLine[] {
  let start = lines.length;
  let bytes = 0;
  while (start > 0 && lines.length - start < maxLines) {
    const nextBytes = utf8ByteLength(lines[start - 1]?.text ?? "");
    if (bytes + nextBytes > maxBytes) {
      break;
    }
    bytes += nextBytes;
    start -= 1;
  }
  const bounded = lines.slice(start);
  byteLengthCache.set(bounded, bytes);
  return bounded;
}

export function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x80) {
      bytes += 1;
    } else if (code < 0x800) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
  }
  return bytes;
}
