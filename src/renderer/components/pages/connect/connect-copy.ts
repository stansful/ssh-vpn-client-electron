import type { AttentionEvent } from "../../../../shared/types.js";
import { formatClock } from "../../../lib/format.js";

export interface FailureCopy {
  /** Plain sentence for the hero: what went wrong and what to do. */
  description: string;
  /** The service's own words, kept for support; omitted when it adds nothing. */
  technical?: string;
}

interface SshFailureContext {
  /** Server name ("Frankfurt-01"). */
  name: string;
  /** Sign-in user, when known. */
  username?: string;
}

const RECONNECT_PREFIX = /^Reconnect attempt \d+ failed:\s*/iu;

/**
 * Turns an SSH failure that stopped retries into a sentence that names the
 * cause and the fix. Unknown messages get a calm generic sentence; the raw
 * text always stays available as `technical`.
 */
export function describeSshFailure(message: string, context: SshFailureContext): FailureCopy {
  const raw = message.trim();
  const reason = raw.replace(RECONNECT_PREFIX, "");
  const { name } = context;
  const user = context.username?.trim();
  const technical = raw || undefined;

  const rules: Array<[RegExp, () => string]> = [
    [/password auth rejected|rejected the password/iu, () => `${name} rejected the password${user ? ` for ${user}` : ""}. Update the server credentials, then try again.`],
    [/private-key auth rejected|rejected the (?:private )?key/iu, () => `${name} rejected the key${user ? ` for ${user}` : ""}. Check which key the server expects, then try again.`],
    [/no auth method available/iu, () => `${name} offered no sign-in method Shadow SSH can use. Check the server's SSH settings, then try again.`],
    [/SSH password is unavailable|no password is saved/iu, () => `No password is saved for ${name}. Add it in the server settings, then try again.`],
    [/SSH private key is unavailable/iu, () => `No key is attached to ${name}. Pick a key in the server settings, then try again.`],
    [/Encrypted OpenSSH private keys are not supported/iu, () => `The key for ${name} is a passphrase-protected OpenSSH key, which Shadow SSH can't load yet. Use an unencrypted key or convert it to PKCS8 or PEM.`],
    [/Unable to load SSH private key/iu, () => `The key for ${name} couldn't be read. Check the key format and its passphrase, then try again.`],
    [/Unsupported public key type/iu, () => `The key for ${name} uses a type Shadow SSH doesn't support yet. Use an Ed25519 or RSA key.`],
    [/fingerprint mismatch|host key changed during rekey|host key (?:does not|doesn't) match/iu, () => `${name} presented a host key that doesn't match the pinned one. If the server was reinstalled, update the pinned key; otherwise don't connect.`],
    [/host key signature verification failed/iu, () => `${name} sent an invalid host key signature, so Shadow SSH stopped. Check the server before connecting again.`],
    [/Unsupported SSH host key algorithm|No compatible SSH server host key algorithm/iu, () => `${name} uses a host key type Shadow SSH can't verify, so it won't connect.`],
    [/No compatible SSH .* algorithm/iu, () => `${name} and Shadow SSH have no encryption method in common. Check the server's SSH settings.`],
    [/\bENOTFOUND\b/iu, () => `The server name of ${name} can't be found. Check the host in the server settings.`],
    [/\bECONNREFUSED\b/iu, () => `${name} refuses connections on this port. Check the port in the server settings.`],
    [/timed? ?out|timeout/iu, () => `${name} didn't answer in time. Check that the server is online, then try again.`]
  ];
  for (const [pattern, sentence] of rules) {
    if (pattern.test(reason)) {
      return { description: sentence(), technical };
    }
  }
  return {
    description: `The connection to ${name} stopped and won't retry on its own. Try again, or edit the server.`,
    technical
  };
}

/**
 * "Wi-Fi → Ethernet" from the wake detector's
 * "network interfaces changed (lost Wi-Fi=192.168.1.24; gained Ethernet=10.0.0.12)".
 */
export function networkChangeSummary(reason: string | undefined): string | undefined {
  const match = reason ? /network interfaces changed \(([^)]*)\)/iu.exec(reason) : null;
  if (!match) {
    return undefined;
  }
  const lost: string[] = [];
  const gained: string[] = [];
  for (const part of match[1].split(";")) {
    const trimmed = part.trim();
    const side = /^lost\s+/iu.test(trimmed) ? lost : /^gained\s+/iu.test(trimmed) ? gained : undefined;
    if (!side) {
      continue;
    }
    const entries = trimmed.replace(/^(?:lost|gained)\s+/iu, "").replace(/\s+and \d+ more$/iu, "").split(",");
    for (const entry of entries) {
      const nameOnly = interfaceName(entry);
      if (nameOnly && !side.includes(nameOnly)) {
        side.push(nameOnly);
      }
    }
  }
  const lostOnly = lost.filter((item) => !gained.includes(item));
  const gainedOnly = gained.filter((item) => !lost.includes(item));
  if (lostOnly.length > 0 && gainedOnly.length > 0) {
    return `${lostOnly.join(", ")} → ${gainedOnly.join(", ")}`;
  }
  if (lostOnly.length > 0) {
    return `${lostOnly.join(", ")} went away`;
  }
  if (gainedOnly.length > 0) {
    return `${gainedOnly.join(", ")} came up`;
  }
  const same = lost.find((item) => gained.includes(item));
  return same ? `${same} got a new address` : undefined;
}

/** "Wi-Fi=192.168.1.24" or "Wi-Fi 192.168.1.24" → "Wi-Fi". */
function interfaceName(entry: string): string | undefined {
  const trimmed = entry.trim();
  if (!trimmed) {
    return undefined;
  }
  const equals = trimmed.indexOf("=");
  if (equals > 0) {
    return trimmed.slice(0, equals).trim();
  }
  return trimmed.replace(/\s+(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:]+)$/iu, "").trim() || undefined;
}

/**
 * Splits "The server name can't be found. Stop, fix it, …" into the cause
 * and the advice, so the raw error can sit between them.
 */
export function splitLead(detail: string): { lead: string; rest: string } {
  const match = /^(.+?[.!?])\s+(.*)$/su.exec(detail.trim());
  if (!match) {
    return { lead: detail.trim().replace(/[.!?]$/u, ""), rest: "" };
  }
  return { lead: match[1].replace(/[.!?]$/u, ""), rest: match[2] };
}

/**
 * Hint under "Off · blocked by routing", shown only when a running tunnel
 * was closed because its last target was turned off.
 */
export function closedForRoutingHint(attention: readonly AttentionEvent[]): string | undefined {
  const event = attention.find((candidate) => candidate.kind === "split-tunnel-no-targets");
  if (!event) {
    return undefined;
  }
  const named = /\bso (.+?) was disconnected\b/u.exec(event.message)?.[1]?.trim();
  const subject = named && named !== "the tunnel" ? `The ${named} tunnel` : "The tunnel";
  const clock = formatClock(event.at);
  return `${subject} closed${clock ? ` at ${clock}` : ""} because its last target was turned off.`;
}

/** Callout copy when the server refused or never answered the terminal request. */
export function shellFailureCopy(error: string, context: SshFailureContext): string {
  const user = context.username?.trim();
  if (/timed out|timeout/iu.test(error)) {
    return `${context.name} didn't answer the terminal request in time. The tunnel is fine; try again.`;
  }
  if (/PTY allocation failed|Shell request failed|open failed|refused|prohibited|denied/iu.test(error)) {
    return `${context.name} refused the terminal request. The tunnel is fine; the server may not allow terminals${user ? ` for ${user}` : ""}.`;
  }
  return "The shell couldn't start. The tunnel is fine; try again.";
}
