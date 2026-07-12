import type { RendererEvent } from "../../shared/ipc.js";
import {
  diagnosticEntryByteLength,
  MAX_DIAGNOSTICS_HISTORY_BYTES,
  normalizeDiagnosticEntry
} from "../../shared/diagnostics-history.js";
import { utf8ByteLength } from "../../shared/terminal-history.js";

interface RendererEventQueueOptions {
  maxEvents: number;
  maxTerminalBytes: number;
  maxDiagnosticBytes?: number;
}

/**
 * Bounds events received while the initial or post-background snapshot is in
 * flight. The oldest data is dropped first because the authoritative snapshot
 * already contains everything emitted before it was captured.
 */
export class BoundedRendererEventQueue {
  private readonly events: RendererEvent[] = [];
  private terminalBytes = 0;
  private diagnosticBytes = 0;
  private readonly maxDiagnosticBytes: number;

  constructor(private readonly options: RendererEventQueueOptions) {
    this.maxDiagnosticBytes = options.maxDiagnosticBytes ?? MAX_DIAGNOSTICS_HISTORY_BYTES;
  }

  enqueue(event: RendererEvent): void {
    let queuedEvent = event;
    if (isReplaceableStateEvent(event)) {
      const previous = this.events.findIndex((candidate) => candidate.type === event.type);
      if (previous >= 0) {
        this.events.splice(previous, 1);
      }
    }
    if (event.type === "terminal-output") {
      const bytes = utf8ByteLength(event.line.text);
      if (bytes > this.options.maxTerminalBytes) {
        return;
      }
      this.terminalBytes += bytes;
    }
    if (event.type === "diagnostics-appended") {
      const entry = normalizeDiagnosticEntry(event.entry);
      const bytes = diagnosticEntryByteLength(entry);
      if (bytes > this.maxDiagnosticBytes) {
        return;
      }
      queuedEvent = entry === event.entry ? event : { ...event, entry };
      this.diagnosticBytes += bytes;
    }
    this.events.push(queuedEvent);
    this.trim();
  }

  drain(): RendererEvent[] {
    const drained = this.events.splice(0);
    this.terminalBytes = 0;
    this.diagnosticBytes = 0;
    return drained;
  }

  clear(): void {
    this.events.length = 0;
    this.terminalBytes = 0;
    this.diagnosticBytes = 0;
  }

  get size(): number {
    return this.events.length;
  }

  private trim(): void {
    while (this.terminalBytes > this.options.maxTerminalBytes) {
      const terminalIndex = this.events.findIndex((event) => event.type === "terminal-output");
      if (terminalIndex < 0) {
        this.terminalBytes = 0;
        break;
      }
      this.removeAt(terminalIndex);
    }
    while (this.diagnosticBytes > this.maxDiagnosticBytes) {
      const diagnosticIndex = this.events.findIndex((event) => event.type === "diagnostics-appended");
      if (diagnosticIndex < 0) {
        this.diagnosticBytes = 0;
        break;
      }
      this.removeAt(diagnosticIndex);
    }
    while (this.events.length > this.options.maxEvents) {
      const droppableIndex = this.events.findIndex(
        (event) => event.type === "terminal-output" || event.type === "diagnostics-appended" || event.type === "error"
      );
      this.removeAt(droppableIndex >= 0 ? droppableIndex : 0);
    }
  }

  private removeAt(index: number): void {
    const removed = this.events.splice(index, 1)[0];
    if (removed?.type === "terminal-output") {
      this.terminalBytes -= utf8ByteLength(removed.line.text);
    }
    if (removed?.type === "diagnostics-appended") {
      this.diagnosticBytes -= diagnosticEntryByteLength(removed.entry);
    }
  }
}

function isReplaceableStateEvent(
  event: RendererEvent
): event is Extract<RendererEvent, { type: "status-changed" | "tunnel-check-result" | "update-download-changed" }> {
  return event.type === "status-changed" || event.type === "tunnel-check-result" || event.type === "update-download-changed";
}
