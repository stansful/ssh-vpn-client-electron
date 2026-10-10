import type { LocalProxyEndpoint, RuntimeStatus } from "../../shared/types.js";

export type ReconnectReasonKind = "network-change" | "wake" | "clock-jump" | "watchdog" | "session-lost" | "stuck";

export interface ReconnectReason {
  kind: ReconnectReasonKind;
  /** Callout title, e.g. "Your network changed". */
  title: string;
  /** One calm sentence about what happens; mentions `targetName` when given. */
  detail: string;
  /** Routine reasons read as info; errors that never clear on their own as warn. */
  tone: "info" | "warn";
  /** The retry loop is unlikely to succeed without the user fixing something. */
  likelyStuck: boolean;
  /** The service's own words for the failure, when there are any. */
  technical?: string;
}

/**
 * Errors that do not clear by retrying: the name does not resolve, nothing
 * listens on the port, or the server shares no algorithm with the client.
 */
const STUCK_PATTERNS: Array<{ pattern: RegExp; detail: string }> = [
  { pattern: /\bENOTFOUND\b|getaddrinfo .*not found|name (?:or service )?not (?:known|found)/iu, detail: "The server name can't be found." },
  { pattern: /\bECONNREFUSED\b|connection refused/iu, detail: "The server refuses connections on this port." },
  {
    pattern: /no (?:compatible|matching|common) (?:algorithm|cipher|key exchange|host key|mac)|handshake failed: no/iu,
    detail: "The server and Shadow have no encryption method in common."
  },
  { pattern: /host key (?:does not|doesn't) match|host key mismatch|fingerprint mismatch/iu, detail: "The server's host key doesn't match the pinned one." },
  { pattern: /authentication (?:failed|rejected)|permission denied/iu, detail: "The server rejected the sign-in." }
];

/** The part of a status message after the "Reconnecting after …:" envelope. */
export function reconnectReasonText(message: string): string {
  const trimmed = message.trim();
  const patterns = [
    /^Reconnecting after SSH failure:\s*/iu,
    /^Restarting Xray transport after failure:\s*/iu,
    /^Reconnect attempt \d+ failed:\s*/iu,
    /^Reconnect attempt \d+ scheduled in \d+ s:\s*/iu
  ];
  for (const pattern of patterns) {
    if (pattern.test(trimmed)) {
      return trimmed.replace(pattern, "").trim();
    }
  }
  const lost = /^SSH session lost \((.*)\); reconnecting\.?$/isu.exec(trimmed);
  if (lost) {
    return lost[1].trim();
  }
  return trimmed;
}

/**
 * Classifies why a session is reconnecting. Routine causes (network change,
 * wake from sleep, clock jump, the watchdog) are info; failures that will not
 * fix themselves are flagged as likely stuck.
 */
export function classifyReconnectReason(message: string | undefined, targetName?: string): ReconnectReason | undefined {
  if (!message?.trim()) {
    return undefined;
  }
  const reason = reconnectReasonText(message);
  const subject = targetName ? `nothing is wrong with ${targetName}` : "nothing is wrong with the server";

  for (const { pattern, detail } of STUCK_PATTERNS) {
    if (pattern.test(reason)) {
      return {
        kind: "stuck",
        title: "This probably won't fix itself",
        detail: `${detail} Stop, fix it, then connect again. Edits don't reach a retry in progress.`,
        tone: "warn",
        likelyStuck: true,
        technical: reason
      };
    }
  }
  if (/network[- ]changed|network interfaces changed|network changed/iu.test(reason)) {
    return {
      kind: "network-change",
      title: "Your network changed",
      detail: `A quick reconnect is normal after switching networks, so ${subject}.`,
      tone: "info",
      likelyStuck: false,
      technical: reason
    };
  }
  if (/\bresume\b|woke|wake|sleep/iu.test(reason)) {
    return {
      kind: "wake",
      title: "Your computer woke from sleep",
      detail: `A quick reconnect is normal after sleep, so ${subject}.`,
      tone: "info",
      likelyStuck: false,
      technical: reason
    };
  }
  if (/clock[- ]jump|did not run for about|clock changed/iu.test(reason)) {
    return {
      kind: "clock-jump",
      title: "Shadow was paused for a while",
      detail: "The system clock jumped, so the session is checked again from scratch.",
      tone: "info",
      likelyStuck: false,
      technical: reason
    };
  }
  if (/watchdog|supervisor/iu.test(reason)) {
    return {
      kind: "watchdog",
      title: "The connection watchdog restarted the session",
      detail: "It noticed the tunnel had stopped without a retry planned, so it started one.",
      tone: "info",
      likelyStuck: false,
      technical: reason
    };
  }
  return {
    kind: "session-lost",
    title: "The session dropped",
    detail: "Shadow is reconnecting on its own.",
    tone: "info",
    likelyStuck: false,
    technical: reason || undefined
  };
}

/** Attempt number from "… (attempt 3)." / "Reconnect attempt 3 failed: …", else `fallback`. */
export function extractAttempt(message: string | undefined, fallback?: number): number | undefined {
  const match = message ? /\battempt\s+(\d+)/iu.exec(message) : null;
  if (match) {
    return Number(match[1]);
  }
  return fallback && fallback > 0 ? fallback : undefined;
}

const ENDPOINT = String.raw`((?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:]+\]|localhost):(\d{1,5})`;

/**
 * Local proxy from a status or diagnostics message, for services that do
 * not report `runtime.localProxy` yet:
 * "HTTP/SOCKS proxy 127.0.0.1:50817", "Xray HTTP proxy 127.0.0.1:10809 and
 * SOCKS proxy 127.0.0.1:10808", "Local proxy 127.0.0.1:50817".
 */
export function parseLocalProxy(message: string | undefined): LocalProxyEndpoint | undefined {
  if (!message) {
    return undefined;
  }
  const http = new RegExp(String.raw`HTTP(?:\/SOCKS5?)?\s+proxy(?:\s+is listening on)?\s+${ENDPOINT}`, "iu").exec(message);
  const socks = new RegExp(String.raw`(?<!HTTP\/)SOCKS5?\s+proxy\s+${ENDPOINT}`, "iu").exec(message);
  const generic = new RegExp(String.raw`(?:local|routing)\s+(?:\w+\s+)?proxy(?:\s+is listening on)?\s+${ENDPOINT}`, "iu").exec(message);
  const primary = http ?? generic;
  if (!primary) {
    return undefined;
  }
  const host = primary[1].replace(/^\[|\]$/gu, "");
  const httpPort = Number(primary[2]);
  if (!Number.isInteger(httpPort) || httpPort < 1 || httpPort > 65535) {
    return undefined;
  }
  const socksPort = socks ? Number(socks[2]) : undefined;
  return socksPort && socksPort !== httpPort ? { host, httpPort, socksPort } : { host, httpPort };
}

/** `runtime.localProxy`, falling back to parsing the connected message. */
export function runtimeLocalProxy(runtime: Pick<RuntimeStatus, "localProxy" | "message" | "state">): LocalProxyEndpoint | undefined {
  if (runtime.localProxy) {
    return runtime.localProxy;
  }
  return runtime.state === "Connected" ? parseLocalProxy(runtime.message) : undefined;
}

/** "127.0.0.1:50817" for display and copying. */
export function formatLocalProxy(proxy: LocalProxyEndpoint): string {
  return proxy.host.includes(":") ? `[${proxy.host}]:${proxy.httpPort}` : `${proxy.host}:${proxy.httpPort}`;
}

/** The core failed to start ("Startup failed: …"); Connect then runs a simulator. */
export function isStartupFailure(message: string | undefined): boolean {
  return Boolean(message?.trimStart().startsWith("Startup failed:"));
}

/** Messages that only restate the state and add nothing for the user. */
export function isGenericStateMessage(message: string | undefined): boolean {
  const trimmed = message?.trim() ?? "";
  return (
    trimmed === "" ||
    trimmed === "Disconnected." ||
    trimmed === "Connected." ||
    trimmed === "Application services are starting." ||
    trimmed === "Native service is not connected." ||
    trimmed === "Live SSH service is active." ||
    /^Connected to .+\. (?:HTTP\/SOCKS proxy|Xray HTTP proxy) /u.test(trimmed)
  );
}
