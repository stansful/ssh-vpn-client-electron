import type { TerminalLine } from "../../shared/types.js";
import { utf8ByteLength } from "../../shared/terminal-history.js";

export interface TerminalOutputBatch<Source extends string> {
  source: Source;
  lines: TerminalLine[];
  droppedBytes: number;
}

export interface TerminalOutputBatcherOptions {
  flushDelayMs?: number;
  maxPendingBytes?: number;
  maxSegments?: number;
}

const DEFAULT_FLUSH_DELAY_MS = 50;
const DEFAULT_MAX_PENDING_BYTES = 256 * 1024;
const DEFAULT_MAX_SEGMENTS = 4;

interface PendingTerminalSegment {
  line: TerminalLine;
  chunks: string[];
}

/**
 * Bounds renderer IPC pressure from commands that produce terminal output much
 * faster than Chromium can render it. Adjacent chunks are coalesced and excess
 * output is reported as dropped instead of growing an unbounded event queue.
 */
export class TerminalOutputBatcher<Source extends string> {
  private readonly flushDelayMs: number;
  private readonly maxPendingBytes: number;
  private readonly maxSegments: number;
  private source: Source | undefined;
  private segments: PendingTerminalSegment[] = [];
  private pendingBytes = 0;
  private droppedBytes = 0;
  private timer: NodeJS.Timeout | undefined;

  constructor(
    private readonly onFlush: (batch: TerminalOutputBatch<Source>) => void,
    options: TerminalOutputBatcherOptions = {}
  ) {
    this.flushDelayMs = positiveInteger(options.flushDelayMs, DEFAULT_FLUSH_DELAY_MS);
    this.maxPendingBytes = positiveInteger(options.maxPendingBytes, DEFAULT_MAX_PENDING_BYTES);
    this.maxSegments = positiveInteger(options.maxSegments, DEFAULT_MAX_SEGMENTS);
  }

  enqueue(source: Source, line: TerminalLine): void {
    if (line.text.length === 0) {
      return;
    }
    if (this.source !== undefined && this.source !== source) {
      this.flush();
    }
    // System lifecycle messages are rare and should preserve their ordering
    // relative to already buffered stdout/stderr without an artificial delay.
    if (line.stream === "system" && (this.segments.length > 0 || this.droppedBytes > 0)) {
      this.flush();
    }
    this.source = source;

    const bytes = utf8ByteLength(line.text);
    const previous = this.segments.at(-1);
    const needsSegment = !previous || previous.line.stream !== line.stream;
    if (this.pendingBytes + bytes > this.maxPendingBytes || (needsSegment && this.segments.length >= this.maxSegments)) {
      this.droppedBytes = Math.min(Number.MAX_SAFE_INTEGER, this.droppedBytes + bytes);
    } else if (previous && previous.line.stream === line.stream) {
      // Joining on every chunk repeatedly copies the complete accumulated
      // string. Keep chunk references and materialize each segment once at
      // flush time so high-volume terminal output remains linear-time.
      previous.chunks.push(line.text);
      this.pendingBytes += bytes;
    } else {
      this.segments.push({ line, chunks: [line.text] });
      this.pendingBytes += bytes;
    }

    if (line.stream === "system") {
      this.flush();
    } else {
      this.scheduleFlush();
    }
  }

  flush(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
    const source = this.source;
    if (source === undefined) {
      return;
    }
    const batch: TerminalOutputBatch<Source> = {
      source,
      lines: this.segments.map(({ line, chunks }) => ({
        ...line,
        text: chunks.length === 1 ? chunks[0] : chunks.join("")
      })),
      droppedBytes: this.droppedBytes
    };
    this.reset();
    if (batch.lines.length > 0 || batch.droppedBytes > 0) {
      this.onFlush(batch);
    }
  }

  clear(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
    this.reset();
  }

  private scheduleFlush(): void {
    if (this.timer) {
      return;
    }
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.flush();
    }, this.flushDelayMs);
    this.timer.unref();
  }

  private reset(): void {
    this.source = undefined;
    this.segments = [];
    this.pendingBytes = 0;
    this.droppedBytes = 0;
  }
}

function positiveInteger(value: number | undefined, fallback: number): number {
  return Number.isInteger(value) && Number(value) > 0 ? Number(value) : fallback;
}
