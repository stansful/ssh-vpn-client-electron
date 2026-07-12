import type { RendererEvent } from "../../shared/ipc.js";
import type { AppSnapshot } from "../../shared/types.js";
import {
  appendBoundedDiagnosticEntries,
  MAX_DIAGNOSTICS_HISTORY_BYTES
} from "../../shared/diagnostics-history.js";
import { appendBoundedTerminalLines } from "../../shared/terminal-history.js";
import { MAX_RENDERER_DIAGNOSTICS } from "../types.js";

export function formatRuntimeDiagnostics(snapshot: AppSnapshot | undefined): string {
  return (snapshot?.diagnostics ?? [])
    .map((entry) => `[${entry.at}] ${entry.level.toUpperCase()} ${entry.message}`)
    .join("\n");
}

export function applyServiceEventToSnapshot(snapshot: AppSnapshot | undefined, event: RendererEvent): AppSnapshot | undefined {
  return applyLiveServiceEventsToSnapshot(snapshot, [event]);
}

export function applyLiveServiceEventsToSnapshot(
  snapshot: AppSnapshot | undefined,
  events: readonly RendererEvent[]
): AppSnapshot | undefined {
  if (!snapshot) {
    return snapshot;
  }
  let runtime = snapshot.runtime;
  let diagnostics = snapshot.diagnostics;
  let terminal = snapshot.terminal;
  let lastTunnelCheck = snapshot.lastTunnelCheck;
  let updateDownload = snapshot.updateDownload;
  let changed = false;
  const appendedDiagnostics: AppSnapshot["diagnostics"] = [];
  const appendedTerminal: AppSnapshot["terminal"] = [];

  for (const event of events) {
    if (event.type === "status-changed") {
      runtime = event.status;
      changed = true;
    } else if (event.type === "diagnostics-appended") {
      appendedDiagnostics.push(event.entry);
      changed = true;
    } else if (event.type === "terminal-output") {
      if (event.line.text.length === 0) {
        continue;
      }
      appendedTerminal.push(event.line);
      changed = true;
    } else if (event.type === "tunnel-check-result") {
      lastTunnelCheck = event.result;
      changed = true;
    } else if (event.type === "update-download-changed") {
      updateDownload = event.download;
      changed = true;
    }
  }

  if (!changed) {
    return snapshot;
  }
  if (appendedDiagnostics.length > 0) {
    diagnostics = appendBoundedDiagnosticEntries(
      diagnostics,
      appendedDiagnostics,
      MAX_RENDERER_DIAGNOSTICS,
      MAX_DIAGNOSTICS_HISTORY_BYTES
    );
  }
  if (appendedTerminal.length > 0) {
    terminal = appendBoundedTerminalLines(terminal, appendedTerminal);
  }
  return { ...snapshot, runtime, diagnostics, terminal, lastTunnelCheck, updateDownload };
}

export function applyServiceEventsToSnapshot(snapshot: AppSnapshot, events: readonly RendererEvent[]): AppSnapshot {
  const diagnosticIds = new Set(snapshot.diagnostics.map((entry) => entry.id));
  const terminalLineIds = new Set(snapshot.terminal.map((line) => line.id));
  const uniqueEvents: RendererEvent[] = [];
  for (const event of events) {
    if (event.type === "diagnostics-appended") {
      if (diagnosticIds.has(event.entry.id)) {
        continue;
      }
      diagnosticIds.add(event.entry.id);
    }
    if (event.type === "terminal-output") {
      if (terminalLineIds.has(event.line.id)) {
        continue;
      }
      terminalLineIds.add(event.line.id);
    }
    uniqueEvents.push(event);
  }
  return applyLiveServiceEventsToSnapshot(snapshot, uniqueEvents) ?? snapshot;
}
