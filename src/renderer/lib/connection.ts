import type { ConnectionState, DesktopPlatform, GlobalTab, ProxyProtocol, RoutingMode, RuntimeStatus, TunnelCheckResult } from "../../shared/types.js";
import { platformLabel } from "./format.js";
import { classifyReconnectReason, extractAttempt, isGenericStateMessage, isStartupFailure, type ReconnectReason } from "./runtime-message.js";

/** Visual state of the orb (and of `.hero[data-state]`, minus "blocked"). */
export type OrbState = "off" | "connecting" | "connected" | "reconnecting" | "disconnecting" | "error" | "preview" | "blocked";

/** Status tones, one meaning each (Foundations → Status tones). */
export type StatusTone = "neutral" | "busy" | "ok" | "danger" | "warn" | "info";

/** Phase of one transport as the user should read it. */
export type ConnectionPhase = "off" | "connecting" | "connected" | "reconnecting" | "disconnecting" | "error" | "preview";

/** What tapping the orb (the one action on Connect) does. */
export type PrimaryAction = "connect" | "disconnect" | "retry" | "stop-reconnecting" | "switch" | "none";

export interface ConnectionInput {
  /** The transport this presentation describes (the Connect tab being viewed). */
  transport: GlobalTab;
  /** The transport that owns `runtime`. */
  activeTransport: GlobalTab;
  runtime: RuntimeStatus;
  platform: DesktopPlatform;
  routingMode?: RoutingMode;
  /** Name of the selected (or, while a session runs, the active) server or profile. */
  targetName?: string;
  /** host:port of the selected server or profile. */
  targetAddress?: string;
  /** "VLESS", "Hysteria 2" etc., for Xray copy. */
  protocolLabel?: string;
  /** Name of the session running on the other transport, for "Off here · Xray is on". */
  otherTargetName?: string;
  /** Split tunnel has nothing to route, so connecting is paused. */
  routingBlocked?: boolean;
  /** No server/profile is saved or selected yet. */
  noTarget?: boolean;
  /** The selected Xray profile has an unknown security mode or transport. */
  unsupportedTarget?: boolean;
  /** How the running Hysteria 2 session's tunnel check went (`hysteria2CheckState`); undefined for other sessions. */
  hysteria2Check?: Hysteria2CheckState;
}

/**
 * Where a connected Hysteria 2 session stands with its tunnel check. Xray
 * reports Connected as soon as its local proxy listens, before (and whether
 * or not) the server answers over UDP, so only a passed check confirms it.
 * "unverified": the check passed with a note (the endpoint stayed silent),
 * which a blocked server passes too.
 */
export type Hysteria2CheckState = "pending" | "passed" | "unverified" | "failed";

/**
 * The tunnel check state of the active Xray session when it runs a Hysteria 2
 * profile, judged from the latest check made since it connected. Undefined
 * for SSH and other protocols, which keep their copy.
 */
export function hysteria2CheckState(input: {
  runtime: Pick<RuntimeStatus, "state" | "connectedAt">;
  activeTransport: GlobalTab;
  /** Protocol of the profile the session runs. */
  protocol?: ProxyProtocol;
  lastTunnelCheck?: TunnelCheckResult;
}): Hysteria2CheckState | undefined {
  if (input.activeTransport !== "xray" || input.protocol !== "hysteria2" || input.runtime.state !== "Connected") {
    return undefined;
  }
  const check = input.lastTunnelCheck;
  if (!check || (check.transport ?? "xray") !== "xray") {
    return "pending";
  }
  // A check from before a restart describes the old Xray process.
  const since = input.runtime.connectedAt ? Date.parse(input.runtime.connectedAt) : Number.NaN;
  const at = Date.parse(check.at);
  if (!Number.isNaN(since) && (Number.isNaN(at) || at < since)) {
    return "pending";
  }
  if (!check.ok) {
    return "failed";
  }
  return check.note ? "unverified" : "passed";
}

const HYSTERIA2_CHECK_COPY: Record<Exclude<Hysteria2CheckState, "passed">, string> = {
  pending: "Xray is up. Hysteria 2 can’t confirm the server until the tunnel check passes.",
  unverified: "Xray is up, but the check endpoint sent nothing back, so the Hysteria 2 server isn’t confirmed. Use a TLS or HTTP check endpoint to confirm it.",
  failed: "Xray is up, but the tunnel check failed. Hysteria 2 needs UDP to reach the server; the tunnel check lists what to try."
};

export interface ConnectionPresentation {
  phase: ConnectionPhase;
  /** For `.hero[data-state]`; "preview" (warn colours) also marks a Hysteria 2 session whose tunnel check failed. */
  heroState: ConnectionPhase;
  orbState: OrbState;
  tone: StatusTone;
  /** Big word on the hero: Off, Connecting, Protected, Proxy ready, Check failed, Reconnecting, Disconnecting, Needs attention, Preview only. */
  stateWord: string;
  /** Hero badge; busy badges end in an ellipsis and carry a spinner. */
  badge: { text: string; tone: StatusTone; spinner: boolean };
  description: string;
  /** Small caps label under the orb, e.g. "Tap to connect". */
  orbLabel: string;
  /** Accessible name of the orb button. */
  orbAriaLabel: string;
  orbDisabled: boolean;
  primaryAction: PrimaryAction;
  /** A session runs or is starting on this transport. */
  session: boolean;
  /** Connecting / reconnecting / disconnecting. */
  busy: boolean;
  /** The picker cannot change selection right now. */
  pickerLocked: boolean;
  /** Hint under a locked picker. */
  lockHint?: string;
  /** This transport is off while the other one runs. */
  otherTransportActive: boolean;
  /** Reconnect cause, while reconnecting. */
  reconnectReason?: ReconnectReason;
  attempt?: number;
  /** Failure text worth showing (Error state), without generic restatements. */
  errorDetail?: string;
}

const TRANSPORT_LABEL: Record<GlobalTab, string> = { ssh: "SSH", xray: "Xray" };

export function transportLabel(transport: GlobalTab): string {
  return TRANSPORT_LABEL[transport];
}

/** Windows redirects traffic itself; macOS and Linux only open a local proxy. */
export function redirectsSystemTraffic(platform: DesktopPlatform): boolean {
  return platform === "windows";
}

/** The session is a simulator (core failed to start) or cannot route anything. */
export function isPreviewSession(runtime: Pick<RuntimeStatus, "state" | "transport" | "realTunnelAvailable">): boolean {
  return runtime.state === "Connected" && (runtime.transport === "simulator" || !runtime.realTunnelAvailable);
}

export function phaseOf(runtime: RuntimeStatus): ConnectionPhase {
  switch (runtime.state) {
    case "Connecting":
      return "connecting";
    case "Connected":
      return isPreviewSession(runtime) ? "preview" : "connected";
    case "Reconnecting":
      return "reconnecting";
    case "Disconnecting":
      return "disconnecting";
    case "Error":
      return "error";
    default:
      return "off";
  }
}

/** Server/profile selection is locked for every in-flight or active session. */
export function isConnectionSelectionLocked(state: ConnectionState): boolean {
  return state !== "Disconnected" && state !== "Error";
}

/**
 * Everything the Connect hero shows for one transport. The inactive transport
 * always reads Off; a session on the other transport is reported through
 * `otherTransportActive`.
 */
export function presentConnection(input: ConnectionInput): ConnectionPresentation {
  const { runtime, transport } = input;
  const isActive = input.transport === input.activeTransport;
  const phase: ConnectionPhase = isActive ? phaseOf(runtime) : "off";
  const otherTransportActive = !isActive && runtime.state !== "Disconnected" && runtime.state !== "Error";
  const name = input.targetName?.trim() || (transport === "ssh" ? "your server" : "this profile");
  const address = input.targetAddress?.trim() || name;
  const ssh = transport === "ssh";
  const nounLock = ssh ? "Disconnect to switch server." : "Disconnect to switch profile.";
  const split = (input.routingMode ?? "selected-rules") === "selected-rules";

  const base = {
    phase,
    heroState: phase,
    session: phase !== "off" && phase !== "error",
    busy: phase === "connecting" || phase === "reconnecting" || phase === "disconnecting",
    otherTransportActive
  };

  if (phase === "connecting") {
    return {
      ...base,
      orbState: "connecting",
      tone: "busy",
      stateWord: "Connecting",
      badge: { text: "Connecting…", tone: "busy", spinner: true },
      description: ssh
        ? `Opening an encrypted SSH session to ${address} and preparing routing…`
        : `Starting the Xray engine with ${input.protocolLabel ? `${input.protocolLabel} profile` : "profile"} ${name}…`,
      orbLabel: "Connecting…",
      orbAriaLabel: "Connecting",
      orbDisabled: true,
      primaryAction: "none",
      pickerLocked: true,
      lockHint: "Locked until this attempt finishes — up to a minute."
    };
  }

  if (phase === "disconnecting") {
    return {
      ...base,
      orbState: "disconnecting",
      tone: "busy",
      stateWord: "Disconnecting",
      badge: { text: "Stopping…", tone: "busy", spinner: true },
      description: ssh
        ? "Closing the session and restoring your direct network settings…"
        : "Stopping Xray and restoring your direct network settings…",
      orbLabel: "Stopping…",
      orbAriaLabel: "Disconnecting",
      orbDisabled: true,
      primaryAction: "none",
      pickerLocked: true,
      lockHint: nounLock
    };
  }

  if (phase === "reconnecting") {
    const reason = classifyReconnectReason(runtime.message, input.targetName);
    const attempt = extractAttempt(runtime.message, runtime.reconnectAttempt);
    let description: string;
    if (reason?.likelyStuck) {
      description = `Still trying ${address}. Retries keep going until you stop them.`;
    } else if (ssh) {
      description = `Restoring the session to ${address}. Routing holds for 30 s, then traffic goes direct until the tunnel is back.`;
    } else {
      description = `Xray stopped unexpectedly. Restarting ${name}${attempt ? ` — attempt ${attempt}` : ""}.`;
    }
    return {
      ...base,
      orbState: "reconnecting",
      tone: "busy",
      stateWord: "Reconnecting",
      badge: { text: attempt ? `Attempt ${attempt}…` : "Reconnecting…", tone: "busy", spinner: true },
      description,
      orbLabel: "Tap to stop",
      orbAriaLabel: "Stop reconnecting",
      orbDisabled: false,
      primaryAction: "stop-reconnecting",
      pickerLocked: true,
      lockHint: nounLock,
      reconnectReason: reason,
      attempt
    };
  }

  if (phase === "preview") {
    return {
      ...base,
      orbState: "preview",
      tone: "warn",
      stateWord: "Preview only",
      badge: { text: "Not routing", tone: "warn", spinner: false },
      description: "Shadow couldn't start its connection core, so Connect shows a preview only. No tunnel is open and your traffic goes direct.",
      orbLabel: "Tap to stop",
      orbAriaLabel: "Stop this session",
      orbDisabled: false,
      primaryAction: "disconnect",
      pickerLocked: true,
      lockHint: nounLock
    };
  }

  if (phase === "connected") {
    const proxyOnly = !redirectsSystemTraffic(input.platform);
    const check = ssh ? undefined : input.hysteria2Check;
    const connected = {
      ...base,
      orbLabel: "Tap to disconnect",
      orbAriaLabel: "Disconnect",
      orbDisabled: false,
      primaryAction: "disconnect" as const,
      pickerLocked: true,
      lockHint: nounLock
    };
    if (check === "failed") {
      // Xray runs, but nothing reached the server: don't call it Protected.
      return {
        ...connected,
        heroState: "preview",
        orbState: "preview",
        tone: "warn",
        stateWord: "Check failed",
        badge: { text: "Connected", tone: "warn", spinner: false },
        description: HYSTERIA2_CHECK_COPY.failed
      };
    }
    let description: string;
    if (check && check !== "passed") {
      description = HYSTERIA2_CHECK_COPY[check];
    } else if (proxyOnly) {
      description = `The tunnel is up, but ${platformLabel(input.platform)} won't send app traffic into it on its own. Apps use it once they point at the local proxy.`;
    } else if (!split) {
      description = ssh
        ? `All your traffic now reaches the internet through ${name}.`
        : `All your traffic now goes through ${name}.`;
    } else {
      description = ssh
        ? `The apps, sites and IPs you picked now reach the internet through ${name}. Everything else stays direct.`
        : `The apps, sites and IPs you picked now go through ${name}. Everything else stays direct.`;
    }
    return {
      ...connected,
      orbState: "connected",
      tone: "ok",
      stateWord: proxyOnly ? "Proxy ready" : "Protected",
      badge: { text: "Connected", tone: "ok", spinner: false },
      description
    };
  }

  if (phase === "error") {
    const detail = isGenericStateMessage(runtime.message) || isStartupFailure(runtime.message) ? undefined : runtime.message.trim();
    let description: string;
    if (isStartupFailure(runtime.message)) {
      description = "Shadow couldn't start its connection core. Try again runs a preview only; quit and reopen Shadow to connect for real.";
    } else if (ssh) {
      description = detail ?? `The connection to ${name} stopped and won't retry on its own. Try again, or edit the server.`;
    } else {
      description = `Xray stopped while starting ${name} and won't retry on its own. Try again, or choose another profile if it keeps failing.`;
    }
    return {
      ...base,
      orbState: "error",
      tone: "danger",
      stateWord: "Needs attention",
      badge: { text: "Error", tone: "danger", spinner: false },
      description,
      orbLabel: "Tap to retry",
      orbAriaLabel: "Try again",
      orbDisabled: Boolean(input.routingBlocked || input.noTarget || input.unsupportedTarget),
      primaryAction: "retry",
      pickerLocked: false,
      errorDetail: detail
    };
  }

  // Off: no target, unsupported profile, blocked by routing, the other transport on, or ready.
  if (input.noTarget) {
    return {
      ...base,
      orbState: "blocked",
      tone: "neutral",
      stateWord: "Off",
      badge: { text: "Not connected", tone: "neutral", spinner: false },
      description: ssh
        ? "Add the SSH server that will carry your traffic. You need its address, a user name, and a password or key."
        : "Add or import an Xray profile to carry your traffic. A VLESS, VMess, Trojan or Hysteria 2 link is all you need.",
      orbLabel: ssh ? "Add a server first" : "Add a profile first",
      orbAriaLabel: ssh ? "Connect (add a server first)" : "Connect (add a profile first)",
      orbDisabled: true,
      primaryAction: "none",
      pickerLocked: false
    };
  }
  if (input.unsupportedTarget) {
    return {
      ...base,
      orbState: "blocked",
      tone: "warn",
      stateWord: "Off",
      badge: { text: "Can't connect", tone: "warn", spinner: false },
      description: `Your traffic goes direct. ${name} can't be started, so Connect is off for this profile.`,
      orbLabel: "Pick another profile",
      orbAriaLabel: "Connect (choose a supported profile first)",
      orbDisabled: true,
      primaryAction: "none",
      pickerLocked: false
    };
  }
  if (input.routingBlocked) {
    return {
      ...base,
      orbState: "blocked",
      tone: "warn",
      stateWord: "Off",
      badge: { text: "Blocked by routing", tone: "warn", spinner: false },
      description: "Split tunnel has nothing to route yet, so connecting is paused until you add a target.",
      orbLabel: "Add a target first",
      orbAriaLabel: "Connect (add a routing target first)",
      orbDisabled: true,
      primaryAction: "none",
      pickerLocked: false
    };
  }
  if (otherTransportActive) {
    const other = transportLabel(input.activeTransport);
    return {
      ...base,
      orbState: "off",
      tone: "neutral",
      stateWord: "Off",
      badge: { text: "Not connected", tone: "neutral", spinner: false },
      description: `${transportLabel(transport)} isn't running. Your traffic is going through ${other} right now.`,
      orbLabel: `Tap to switch to ${transportLabel(transport)}`,
      orbAriaLabel: `Switch to ${transportLabel(transport)} and connect`,
      orbDisabled: false,
      primaryAction: "switch",
      pickerLocked: false
    };
  }
  return {
    ...base,
    orbState: "off",
    tone: "neutral",
    stateWord: "Off",
    badge: { text: "Not connected", tone: "neutral", spinner: false },
    description: ssh
      ? `Your traffic goes direct. Tap the button to route ${split ? "the apps and sites you picked" : "your traffic"} through ${name}.`
      : `Your traffic goes direct. Tap the button to start the ${name} profile.`,
    orbLabel: "Tap to connect",
    orbAriaLabel: "Connect",
    orbDisabled: false,
    primaryAction: "connect",
    pickerLocked: false
  };
}

export interface GlobalStatusPresentation {
  tone: StatusTone;
  /** "Protected", "Proxy ready", "Check failed", "Connecting…", "Needs attention", "Preview only", "Not connected". */
  title: string;
  /** "SSH · Frankfurt-01" or "Tap Connect to start". */
  subtitle: string;
  /** Glyph family for the status tile. */
  icon: "off" | "busy" | "ok" | "danger" | "warn";
  /** Accessible summary, e.g. "Protected, SSH · Frankfurt-01. Open Connect." */
  ariaLabel: string;
}

/**
 * Sidebar card / window-level status for the ACTIVE transport. Reads
 * "Proxy ready" instead of "Protected" where traffic is not redirected.
 */
export function presentGlobalStatus(input: {
  runtime: RuntimeStatus;
  activeTransport: GlobalTab;
  platform: DesktopPlatform;
  targetName?: string;
  /** See `ConnectionInput.hysteria2Check`: a failed check reads "Check failed", like the hero. */
  hysteria2Check?: Hysteria2CheckState;
}): GlobalStatusPresentation {
  const phase = phaseOf(input.runtime);
  const route = `${transportLabel(input.activeTransport)}${input.targetName ? ` · ${input.targetName}` : ""}`;
  const make = (tone: StatusTone, title: string, subtitle: string, icon: GlobalStatusPresentation["icon"]): GlobalStatusPresentation => ({
    tone,
    title,
    subtitle,
    icon,
    ariaLabel: `${title}, ${subtitle}. Open Connect.`
  });
  switch (phase) {
    case "connecting":
      return make("busy", "Connecting…", route, "busy");
    case "reconnecting":
      return make("busy", "Reconnecting…", route, "busy");
    case "disconnecting":
      return make("busy", "Disconnecting…", route, "busy");
    case "connected":
      if (input.activeTransport === "xray" && input.hysteria2Check === "failed") {
        return make("warn", "Check failed", route, "warn");
      }
      return make("ok", redirectsSystemTraffic(input.platform) ? "Protected" : "Proxy ready", route, "ok");
    case "preview":
      return make("warn", "Preview only", route, "warn");
    case "error":
      return make("danger", "Needs attention", route, "danger");
    default:
      return make("neutral", "Not connected", "Tap Connect to start", "off");
  }
}

/** CSS tone class for badges, dots, tiles and callouts ("" for neutral). */
export function toneClass(tone: StatusTone): string {
  return tone === "neutral" ? "" : `t-${tone}`;
}
