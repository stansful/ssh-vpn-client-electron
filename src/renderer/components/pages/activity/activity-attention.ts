import type { AttentionEvent, ConnectionState, DiagnosticsEntry } from "../../../../shared/types.js";
import { formatRelative } from "../../../lib/format.js";
import type { NavigationIntent, View } from "../../../types.js";

export type AttentionTone = "danger" | "warn" | "info";

export function attentionTone(level: AttentionEvent["level"]): AttentionTone {
  return level === "error" ? "danger" : level === "warning" ? "warn" : "info";
}

export type AttentionAction =
  | { type: "navigate"; label: string; view: View; intent?: NavigationIntent }
  /** Expandable "How to enable" steps for the TUN adapter. */
  | { type: "tun-steps" };

const OPEN_ROUTING: AttentionAction = { type: "navigate", label: "Open routing", view: "routing" };
const OPEN_SERVERS: AttentionAction = { type: "navigate", label: "Open SSH servers", view: "servers" };
const OPEN_PROFILES: AttentionAction = { type: "navigate", label: "Open Xray profiles", view: "profiles" };
const OPEN_CONNECT: AttentionAction = { type: "navigate", label: "Open Connect", view: "connect" };

/** Where the advice in the message points (the main process words it that way). */
function actionFromAdvice(message: string): AttentionAction | undefined {
  if (/\bin Routing\b/u.test(message)) {
    return OPEN_ROUTING;
  }
  if (/\bin SSH servers\b/u.test(message)) {
    return OPEN_SERVERS;
  }
  if (/\bin Xray profiles\b/u.test(message)) {
    return OPEN_PROFILES;
  }
  return undefined;
}

/** The one action an attention item offers, if any. */
export function attentionAction(event: Pick<AttentionEvent, "kind" | "level" | "message">): AttentionAction | undefined {
  switch (event.kind) {
    case "split-tunnel-no-targets":
      return OPEN_ROUTING;
    case "tun-unavailable":
      // A warning means TUN never started (setup steps help); an error means it stopped mid-session.
      return event.level === "error" ? OPEN_CONNECT : { type: "tun-steps" };
    case "reconnect-stopped":
    case "auto-connect-failed":
      return actionFromAdvice(event.message) ?? OPEN_CONNECT;
    case "auto-connect-skipped":
      return actionFromAdvice(event.message);
    case "system-proxy-restore-failed":
      return OPEN_CONNECT;
    default:
      return undefined;
  }
}

const LIVE_STATES: readonly ConnectionState[] = ["Connecting", "Connected", "Reconnecting", "Disconnecting"];

/**
 * When the current session began. Live diagnostics are cleared on every
 * connect, so the oldest one marks the start; `connectedAt` covers a trimmed list.
 */
export function sessionStartedAt(
  state: ConnectionState,
  connectedAt: string | undefined,
  diagnostics: readonly Pick<DiagnosticsEntry, "at">[]
): string | undefined {
  if (!LIVE_STATES.includes(state)) {
    return undefined;
  }
  const candidates = [diagnostics[0]?.at, connectedAt].filter((value): value is string => Boolean(value) && !Number.isNaN(Date.parse(value as string)));
  if (candidates.length === 0) {
    return undefined;
  }
  return candidates.reduce((earliest, value) => (Date.parse(value) < Date.parse(earliest) ? value : earliest));
}

/** "This connection", "Previous connection", or a relative time when no session runs. */
export function attentionWhen(at: string, sessionStart: string | undefined, now: Date = new Date()): string {
  const time = Date.parse(at);
  if (sessionStart && !Number.isNaN(time)) {
    return time >= Date.parse(sessionStart) ? "This connection" : "Previous connection";
  }
  const relative = formatRelative(at, now);
  return relative ? relative.charAt(0).toUpperCase() + relative.slice(1) : "";
}
