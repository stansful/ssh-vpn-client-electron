import type { ServiceEvent } from "../../shared/ipc.js";
import type { AppSnapshot } from "../../shared/types.js";
import { MAX_RENDERER_DIAGNOSTICS, MAX_RENDERER_TERMINAL_LINES } from "../types.js";

export function formatRuntimeDiagnostics(snapshot: AppSnapshot | undefined): string {
  return (snapshot?.diagnostics ?? [])
    .map((entry) => `[${entry.at}] ${entry.level.toUpperCase()} ${entry.message}`)
    .join("\n");
}

export function applyServiceEventToSnapshot(snapshot: AppSnapshot | undefined, event: ServiceEvent): AppSnapshot | undefined {
  if (!snapshot) {
    return snapshot;
  }
  if (event.type === "status-changed") {
    return { ...snapshot, runtime: event.status };
  }
  if (event.type === "diagnostics-appended") {
    return {
      ...snapshot,
      diagnostics: [...snapshot.diagnostics, event.entry].slice(-MAX_RENDERER_DIAGNOSTICS)
    };
  }
  if (event.type === "terminal-output") {
    return {
      ...snapshot,
      terminal: [...snapshot.terminal, event.line].slice(-MAX_RENDERER_TERMINAL_LINES)
    };
  }
  if (event.type === "tunnel-check-result") {
    return { ...snapshot, lastTunnelCheck: event.result };
  }
  return snapshot;
}
