import type { RendererEvent } from "../../shared/ipc.js";
import type { AppSnapshot, DiagnosticsEntry, DiagnosticsSource } from "../../shared/types.js";
import {
  appendBoundedDiagnosticEntries,
  MAX_DIAGNOSTICS_HISTORY_BYTES
} from "../../shared/diagnostics-history.js";
import { appendBoundedTerminalLines } from "../../shared/terminal-history.js";
import { MAX_RENDERER_DIAGNOSTICS } from "../types.js";

/**
 * Source of a diagnostics entry: the stamped `source`, else a guess from the
 * wording (older entries and services that do not stamp it yet).
 */
export function diagnosticSource(entry: Pick<DiagnosticsEntry, "source" | "message">): DiagnosticsSource {
  if (entry.source) {
    return entry.source;
  }
  const message = entry.message;
  if (/\bupdate\b|portable update|GitHub release/iu.test(message)) {
    return "update";
  }
  if (/\bxray\b|vless|vmess|trojan|hysteria|\bhy2\b/iu.test(message)) {
    return "xray";
  }
  if (/routing|split tunnel|full tunnel|proxy list|direct list|domain list|\bTUN\b|wintun|system proxy|PAC\b|process-name|rule/iu.test(message)) {
    return "routing";
  }
  if (/\bSSH\b|host key|keepalive|reconnect|tunnel check|SOCKS|HTTP tunnel|local proxy|shell/iu.test(message)) {
    return "ssh";
  }
  return "app";
}

/**
 * Folds a burst of live events into the snapshot. `snapshot-invalidated` is
 * not handled here: the snapshot hook reloads the whole snapshot for it.
 */
export function applyLiveServiceEventsToSnapshot(
  snapshot: AppSnapshot | undefined,
  events: readonly RendererEvent[]
): AppSnapshot | undefined {
  if (!snapshot) {
    return snapshot;
  }
  let runtime = snapshot.runtime;
  let activeTransport = snapshot.activeTransport;
  let diagnostics = snapshot.diagnostics;
  let terminal = snapshot.terminal;
  let lastTunnelCheck = snapshot.lastTunnelCheck;
  let tunnelCheckRunning = snapshot.tunnelCheckRunning;
  let updateDownload = snapshot.updateDownload;
  let attention = snapshot.attention;
  let changed = false;
  const appendedDiagnostics: AppSnapshot["diagnostics"] = [];
  const appendedTerminal: AppSnapshot["terminal"] = [];

  for (const event of events) {
    if (event.type === "status-changed") {
      // The main process clears the check result when a tunnel stops or a
      // new connect starts; mirror it so an old result never lingers.
      if (
        lastTunnelCheck &&
        event.status.state !== runtime.state &&
        (event.status.state === "Disconnected" || event.status.state === "Connecting")
      ) {
        lastTunnelCheck = undefined;
      }
      runtime = event.status;
      changed = true;
    } else if (event.type === "active-transport-changed") {
      if (activeTransport !== event.transport) {
        lastTunnelCheck = undefined;
      }
      activeTransport = event.transport;
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
    } else if (event.type === "tunnel-check-changed") {
      tunnelCheckRunning = event.running;
      changed = true;
    } else if (event.type === "update-download-changed") {
      updateDownload = event.download;
      changed = true;
    } else if (event.type === "attention-changed") {
      attention = event.attention;
      changed = true;
    }
  }

  if (!changed) {
    return snapshot;
  }
  // An IPC reply can carry a snapshot that already holds entries whose events
  // are still queued for the next frame; append each entry only once.
  const newDiagnostics = withoutKnownIds(appendedDiagnostics, diagnostics, diagnostics.length);
  if (newDiagnostics.length > 0) {
    diagnostics = appendBoundedDiagnosticEntries(
      diagnostics,
      newDiagnostics,
      MAX_RENDERER_DIAGNOSTICS,
      MAX_DIAGNOSTICS_HISTORY_BYTES
    );
  }
  const newTerminal = withoutKnownIds(appendedTerminal, terminal, appendedTerminal.length + RECENT_TERMINAL_LINES_CHECKED);
  if (newTerminal.length > 0) {
    terminal = appendBoundedTerminalLines(terminal, newTerminal);
  }
  return { ...snapshot, runtime, activeTransport, diagnostics, terminal, lastTunnelCheck, tunnelCheckRunning, updateDownload, attention };
}

/** Terminal output only repeats at the tail, so only that much is compared. */
const RECENT_TERMINAL_LINES_CHECKED = 256;

function withoutKnownIds<T extends { id: string }>(appended: T[], existing: readonly T[], tail: number): T[] {
  if (appended.length === 0 || existing.length === 0) {
    return appended;
  }
  const known = new Set(existing.slice(-tail).map((item) => item.id));
  return appended.filter((item) => {
    if (known.has(item.id)) {
      return false;
    }
    known.add(item.id);
    return true;
  });
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
