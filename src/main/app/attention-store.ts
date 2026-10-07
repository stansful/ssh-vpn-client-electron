import { randomUUID } from "node:crypto";
import type { AttentionEvent, AttentionKind, DiagnosticsEntry, DiagnosticsSource, GlobalTab } from "../../shared/types.js";

export const MAX_ATTENTION_EVENTS = 20;
const MAX_ATTENTION_TEXT_CHARACTERS = 600;

export interface AttentionInput {
  kind: AttentionKind;
  level: AttentionEvent["level"];
  source: DiagnosticsSource;
  title: string;
  message: string;
  at?: string;
}

export interface AttentionStoreOptions {
  maxEvents?: number;
  now?: () => Date;
  createId?: () => string;
}

/**
 * Events that changed how traffic flows. Live diagnostics are cleared on every
 * connect; these stay in main-process memory until the user dismisses them, so
 * a reason that otherwise only reached the log is not lost.
 */
export class AttentionStore {
  private events: AttentionEvent[] = [];
  private readonly maxEvents: number;
  private readonly now: () => Date;
  private readonly createId: () => string;

  constructor(options: AttentionStoreOptions = {}) {
    this.maxEvents = Math.max(1, options.maxEvents ?? MAX_ATTENTION_EVENTS);
    this.now = options.now ?? (() => new Date());
    this.createId = options.createId ?? randomUUID;
  }

  /** Newest first. */
  list(): AttentionEvent[] {
    return this.events.map((event) => ({ ...event }));
  }

  get size(): number {
    return this.events.length;
  }

  has(kind: AttentionKind): boolean {
    return this.events.some((event) => event.kind === kind);
  }

  /** Adds an event, replacing an older one about the same thing. */
  add(input: AttentionInput): AttentionEvent {
    const event: AttentionEvent = {
      id: this.createId(),
      at: input.at ?? this.now().toISOString(),
      kind: input.kind,
      level: input.level,
      source: input.source,
      title: boundText(input.title),
      message: boundText(input.message)
    };
    const key = dedupeKey(event);
    this.events = [event, ...this.events.filter((candidate) => dedupeKey(candidate) !== key)].slice(0, this.maxEvents);
    return { ...event };
  }

  /** Dismisses one event, or every event when `id` is omitted. Returns whether anything changed. */
  dismiss(id?: string): boolean {
    const before = this.events.length;
    this.events = id === undefined ? [] : this.events.filter((event) => event.id !== id);
    return this.events.length !== before;
  }

  dismissKind(kind: AttentionKind): boolean {
    const before = this.events.length;
    this.events = this.events.filter((event) => event.kind !== kind);
    return this.events.length !== before;
  }
}

function dedupeKey(event: Pick<AttentionEvent, "kind" | "title">): string {
  // "other" collects unrelated events, so only identical ones replace each other.
  return event.kind === "other" ? `other:${event.title}` : event.kind;
}

function boundText(value: string): string {
  const trimmed = value.trim();
  return trimmed.length > MAX_ATTENTION_TEXT_CHARACTERS ? `${trimmed.slice(0, MAX_ATTENTION_TEXT_CHARACTERS - 1)}…` : trimmed;
}

export interface DiagnosticAttentionContext {
  /** Server or profile the transport was running. */
  targetName?: string;
  /** Failure text the transport status carries at that moment. */
  statusMessage?: string;
  /** What is known about TUN prerequisites on this machine. */
  tun?: { elevated: boolean; wintunFound: boolean };
  /** The app was started by the sign-in launch (hidden in the tray). */
  launchedAtSignIn?: boolean;
}

/**
 * Turns the transport diagnostics that change how traffic flows into attention
 * events. Everything else stays a plain diagnostic. The context is only built
 * for a match, since most diagnostics are routine proxy traffic.
 */
export function attentionFromDiagnostic(
  entry: Pick<DiagnosticsEntry, "level" | "message">,
  origin: GlobalTab,
  context: DiagnosticAttentionContext | (() => DiagnosticAttentionContext) = {}
): AttentionInput | undefined {
  const message = entry.message;
  const resolveContext = (): DiagnosticAttentionContext => (typeof context === "function" ? context() : context);
  if (/^Reconnect stopped\b/u.test(message)) {
    return reconnectStoppedAttention(message, origin, resolveContext());
  }
  if (/^Selected-rules routing no longer has any enabled rules/u.test(message)) {
    return splitTunnelNoTargetsAttention(resolveContext().targetName);
  }
  if (/^TUN routing (is unavailable|could not start)/u.test(message)) {
    return tunUnavailableAttention(resolveContext());
  }
  if (/^TUN dataplane stopped unexpectedly/u.test(message)) {
    return {
      kind: "tun-unavailable",
      level: "error",
      source: "routing",
      title: "TUN adapter stopped",
      message: "The TUN adapter stopped during the session, so apps that ignore the Windows proxy setting may now connect directly. Reconnect to bring it back."
    };
  }
  if (/^TUN (routing teardown failed|dataplane did not stop cleanly)/u.test(message)) {
    return {
      kind: "other",
      level: "error",
      source: "routing",
      title: "TUN adapter didn’t stop cleanly",
      message: "Windows may still route traffic through a stale Shadow SSH adapter. If sites don’t load, connect and disconnect once, or restart Windows."
    };
  }
  if (/^Windows proxy restore( after enabling TUN routing)? failed/u.test(message)) {
    return {
      kind: "system-proxy-restore-failed",
      level: "warning",
      source: "routing",
      title: "Couldn’t restore network settings",
      message: "Windows may still point at the Shadow SSH proxy, so some apps may be offline. Connect once, or turn the proxy off in Windows settings."
    };
  }
  if (/^The tunnel has been down for \d+ s; returning the machine to direct routing/u.test(message)) {
    const seconds = /down for (\d+) s/u.exec(message)?.[1] ?? "30";
    return {
      kind: "other",
      level: "warning",
      source: "routing",
      title: "Traffic went direct while the tunnel was down",
      message: `${resolveContext().targetName ?? "The tunnel"} was down for ${seconds} s, so your traffic went back to the direct network until the session returned.`
    };
  }
  return undefined;
}

export function splitTunnelNoTargetsAttention(targetName?: string): AttentionInput {
  return {
    kind: "split-tunnel-no-targets",
    level: "error",
    source: "routing",
    title: "Split tunnel lost its last target, so the tunnel was closed to avoid routing everything direct",
    message: `A routing change left nothing to send through the tunnel, so ${
      targetName ?? "the tunnel"
    } was disconnected. Turn on a rule or a domain list, then connect again.`
  };
}

function reconnectStoppedAttention(message: string, origin: GlobalTab, context: DiagnosticAttentionContext): AttentionInput {
  let advice: string;
  if (message.includes("routing configuration")) {
    advice = "Split tunnel has nothing it can route. Turn on a rule or a domain list in Routing, then connect again.";
  } else if (message.includes("host trust or credentials")) {
    advice = "The server’s host key or sign-in needs you. Check it in SSH servers, then connect again.";
  } else if (message.includes("SSH configuration or key")) {
    advice = "Retrying won’t fix this. Check the server and its key in SSH servers, then connect again.";
  } else {
    advice = message;
  }
  const reason = context.statusMessage?.trim();
  return {
    kind: "reconnect-stopped",
    level: "error",
    source: origin,
    title: context.targetName ? `Reconnect stopped · ${context.targetName}` : "Reconnect stopped",
    message: reason ? `${withFinalStop(reason)} ${advice}` : advice
  };
}

function tunUnavailableAttention(context: DiagnosticAttentionContext): AttentionInput {
  const tun = context.tun;
  if (tun && !tun.elevated && context.launchedAtSignIn) {
    return {
      kind: "tun-unavailable",
      level: "warning",
      source: "routing",
      title: "TUN is off this session",
      message: "Started at sign-in without admin rights, so apps use the Windows system proxy instead."
    };
  }
  let title = "TUN adapter not used";
  if (tun && !tun.elevated) {
    title = "TUN adapter not used: not running as administrator";
  } else if (tun && !tun.wintunFound) {
    title = "TUN adapter not used: wintun.dll wasn’t found";
  }
  return {
    kind: "tun-unavailable",
    level: "warning",
    source: "routing",
    title,
    message: "Apps that ignore the Windows proxy setting, like Telegram or Discord, can connect directly instead of through the tunnel."
  };
}

export type AutoConnectSkipReason = "no-targets" | "no-server" | "no-profile";

export function autoConnectSkippedAttention(reason: AutoConnectSkipReason): AttentionInput {
  const message =
    reason === "no-targets"
      ? "Split tunnel has nothing to route yet. Add a target in Routing, then connect."
      : reason === "no-server"
        ? "No SSH server is picked for Connect. Pick one in SSH servers, then connect."
        : "No Xray profile is picked for Connect. Pick one in Xray profiles, then connect.";
  return { kind: "auto-connect-skipped", level: "warning", source: "app", title: "Auto-connect skipped", message };
}

export interface AutoConnectFailure {
  transport: GlobalTab;
  targetName: string;
  /** The error text, without a stack. */
  reason: string;
  /** For SSH: what the saved secret is. */
  secretKind?: "password" | "key";
  platform: NodeJS.Platform;
}

const SECRET_FAILURE_PATTERN = /secret record is missing|secure storage is unavailable|decrypt|encrypted secret/iu;

export function autoConnectFailedAttention(failure: AutoConnectFailure): AttentionInput {
  let message: string;
  if (SECRET_FAILURE_PATTERN.test(failure.reason)) {
    const elsewhere = failure.platform === "win32" ? "another PC or Windows account" : "another computer or user account";
    message =
      failure.transport === "xray"
        ? `Couldn’t read the saved link for ${failure.targetName}. It was saved on ${elsewhere}. Add the profile again in Xray profiles.`
        : `Couldn’t read the saved ${failure.secretKind === "key" ? "key" : "password"} for ${failure.targetName}. It was saved on ${elsewhere}. Enter it again in SSH servers.`;
  } else {
    message = `Couldn’t connect to ${failure.targetName} at start: ${withFinalStop(failure.reason)}`;
  }
  return { kind: "auto-connect-failed", level: "error", source: "app", title: "Auto-connect failed", message };
}

export function systemProxyRecoveredAttention(): AttentionInput {
  return {
    kind: "system-proxy-recovered",
    level: "info",
    source: "app",
    title: "Network settings repaired",
    message: "Shadow SSH didn’t close cleanly last time, so Windows still pointed at its proxy. Direct settings are back."
  };
}

export function systemProxyRecoveryFailedAttention(): AttentionInput {
  return {
    kind: "system-proxy-restore-failed",
    level: "warning",
    source: "app",
    title: "Couldn’t repair network settings",
    message: "Windows still points at an old Shadow SSH proxy, so some apps may be offline. Connect once, or turn the proxy off in Windows settings."
  };
}

export function storageWriteFailedAttention(reason: string): AttentionInput {
  return {
    kind: "other",
    level: "warning",
    source: "app",
    title: "Couldn’t update your saved data",
    message: `Your servers, keys and rules loaded fine, but writing them back failed. ${withFinalStop(reason)} Shadow SSH tries again on your next change.`
  };
}

export function storageUnreadableAttention(reason: string): AttentionInput {
  return {
    kind: "storage-unreadable",
    level: "error",
    source: "app",
    title: "Your saved data couldn’t be read",
    message: `Shadow SSH stopped before changing anything. ${withFinalStop(reason)}`
  };
}

function withFinalStop(value: string): string {
  const trimmed = value.trim();
  return /[.!?…]$/u.test(trimmed) ? trimmed : `${trimmed}.`;
}
