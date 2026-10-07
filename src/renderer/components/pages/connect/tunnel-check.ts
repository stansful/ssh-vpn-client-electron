import { validateCheckEndpoint } from "../../../../shared/validation.js";
import type { GlobalTab, ProxyProtocol, TunnelCheckResult } from "../../../../shared/types.js";
import { stripIpcPrefix } from "../../../lib/errors.js";
import { formatClock, formatDay, formatLatency } from "../../../lib/format.js";

/** A run of check copy; `mono` for the endpoint, `code` for a command to type. */
export interface TextSegment {
  text: string;
  kind?: "mono" | "code";
}

export type TunnelCheckKind = "waiting" | "idle" | "checking" | "passed" | "note" | "failed";

export interface TunnelCheckView {
  kind: TunnelCheckKind;
  /** Badge word; a latency follows "Passed" when known. */
  badge: string;
  text: TextSegment[];
  /** Line above the steps ("Traffic reaches Frankfurt-01 but not the site. Try this:"). */
  stepsIntro?: string;
  steps?: TextSegment[][];
  /** "SSH · Frankfurt-01 · today 12:04:18": which tunnel the one shared result describes. */
  meta?: string;
}

export interface TunnelCheckInput {
  result?: TunnelCheckResult;
  /** The saved check endpoint (what the next run uses). */
  endpoint: string;
  activeTransport: GlobalTab;
  /** The active transport is connected, so a check can run. */
  connected: boolean;
  /** A manual check is in flight. */
  checking: boolean;
  /** Server/profile the active session runs. */
  activeName?: string;
  /** Protocol of the Xray profile the active session runs. */
  activeProtocol?: ProxyProtocol;
  /** That profile's Hysteria 2 link has insecure=1 without a pinSHA256. */
  activeInsecureWithoutPin?: boolean;
  now?: Date;
}

const TRANSPORT_LABEL: Record<GlobalTab, string> = { ssh: "SSH", xray: "Xray" };
const TLS_PORTS = [443, 8443, 993, 995];
const HTTP_PORTS = [80, 8080, 8000];
/** The probe's overall limit (open + first answer). */
export const CHECK_TIMEOUT_SECONDS = 12;
export const DEFAULT_CHECK_ENDPOINT = "youtube.com:443";

export interface EndpointParts {
  host: string;
  port: number;
}

/** host and port of "youtube.com:443" or "[2001:db8::1]:443"; undefined when there is no usable port. */
export function parseEndpoint(endpoint: string): EndpointParts | undefined {
  const trimmed = endpoint.trim();
  const bracketed = /^\[([^\]]+)\]:(\d{1,5})$/u.exec(trimmed);
  const plain = bracketed ? undefined : /^([^:]+):(\d{1,5})$/u.exec(trimmed);
  const match = bracketed ?? plain;
  if (!match) {
    return undefined;
  }
  const port = Number(match[2]);
  return port >= 1 && port <= 65535 ? { host: match[1], port } : undefined;
}

export type ProbeMethod = "tls" | "http" | "wait";

/** How the probe talks to a port: TLS handshake, HTTP HEAD /, or wait for the server to speak. */
export function probeMethodFor(endpoint: string): { method: ProbeMethod; port: number } | undefined {
  const parts = parseEndpoint(endpoint);
  if (!parts) {
    return undefined;
  }
  if (TLS_PORTS.includes(parts.port)) {
    return { method: "tls", port: parts.port };
  }
  if (HTTP_PORTS.includes(parts.port)) {
    return { method: "http", port: parts.port };
  }
  return { method: "wait", port: parts.port };
}

/** Copy for the "How it's checked" box in the endpoint dialog. */
export function probeMethodCopy(method: ProbeMethod, port: number): { label: string; text: string } {
  switch (method) {
    case "tls":
      return { label: "TLS handshake", text: `${port} is a TLS port, so the check opens a TLS session through the tunnel and waits for the reply.` };
    case "http":
      return { label: "HTTP HEAD /", text: `${port} is an HTTP port, so the check sends HEAD / and reads the status line that comes back.` };
    default:
      return {
        label: "Server speaks first",
        text: `Port ${port} gets no probe. The check waits up to ${CHECK_TIMEOUT_SECONDS} s for the server to say something; silence still passes, but the route is not verified end to end.`
      };
  }
}

const WEB_ADDRESS_MESSAGE = "That is a web address, not an endpoint. Enter host:port without https:// or a path, for example youtube.com:443.";

/** Why an endpoint can't be saved, or undefined when it can. */
export function endpointError(value: string): string | undefined {
  const trimmed = value.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//iu.test(trimmed)) {
    return WEB_ADDRESS_MESSAGE;
  }
  const result = validateCheckEndpoint(trimmed);
  return result.ok ? undefined : result.message;
}

/** The value obviously isn't host:port (a pasted link or path), so say so while typing. */
export function looksLikeWebAddress(value: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//iu.test(value.trim()) || /[/?#@\\]/u.test(value.trim());
}

function latencyOf(result: TunnelCheckResult): number | undefined {
  if (result.latencyMs !== undefined) {
    return result.latencyMs;
  }
  const match = /\bin (\d+) ms\b/u.exec(result.message);
  return match ? Number(match[1]) : undefined;
}

function passedText(result: TunnelCheckResult): TextSegment[] {
  const endpoint: TextSegment = { text: result.endpoint, kind: "mono" };
  const message = result.message;
  if (/^Direct endpoint check succeeded/iu.test(message)) {
    return [endpoint, { text: " answered directly. A preview session can't check the tunnel itself." }];
  }
  if (/answered the TLS handshake/iu.test(message)) {
    return [endpoint, { text: " answered the TLS handshake through the tunnel." }];
  }
  if (/answered with a TLS alert/iu.test(message)) {
    return [endpoint, { text: " answered with a TLS alert through the tunnel. Data flows, but the endpoint refused the test handshake." }];
  }
  const http = /answered (HTTP\/[\d.]+ \d{3}[^.:;]*)/u.exec(message);
  if (http) {
    return [endpoint, { text: ` answered ${http[1].trim()} through the tunnel.` }];
  }
  if (/not a TLS record/iu.test(message)) {
    return [endpoint, { text: " answered through the tunnel, but not with TLS. Something other than the endpoint may be answering." }];
  }
  return [endpoint, { text: " answered through the tunnel." }];
}

/** A command the server terminal can run to see whether the server itself reaches the endpoint. */
export function reachCommand(endpoint: string): string | undefined {
  const parts = parseEndpoint(endpoint);
  if (!parts) {
    return undefined;
  }
  const host = parts.host.includes(":") ? `[${parts.host}]` : parts.host;
  if (TLS_PORTS.includes(parts.port) && parts.port !== 993 && parts.port !== 995) {
    return parts.port === 443 ? `curl -I https://${host}` : `curl -I https://${host}:${parts.port}`;
  }
  if (HTTP_PORTS.includes(parts.port)) {
    return parts.port === 80 ? `curl -I http://${host}` : `curl -I http://${host}:${parts.port}`;
  }
  return `nc -vz ${parts.host} ${parts.port}`;
}

/**
 * Hysteria 2 rides QUIC: Xray reports Connected once its local proxy is up,
 * even when the network drops UDP to the server, so a failed check is the
 * only sign of it.
 */
const HYSTERIA2_UDP_STEP: TextSegment[] = [
  { text: "Hysteria 2 needs UDP to reach the server, and Xray shows Connected even when this network blocks it. Try a VLESS, VMess or Trojan profile to rule that out." }
];
/**
 * Xray logs why a Hysteria 2 dial failed (auth, certificate, timeout) only at
 * info level, below the level the app runs it at, so there is no reason to
 * point at: name the likely ones instead.
 */
const HYSTERIA2_LINK_STEP: TextSegment[] = [
  { text: "If the link’s password (auth), pinSHA256 or obfs password is wrong, it fails the same way." }
];
/**
 * Xray checks the certificate even though the link says insecure=1, so this is
 * the likeliest cause. Profiles can't be edited, so the fix is a new profile.
 */
const HYSTERIA2_INSECURE_STEP: TextSegment[] = [
  {
    text: "This link asks to skip certificate checks (insecure=1), which the bundled Xray can’t do, so a server with a self-signed certificate fails this way. Add the server’s pinSHA256 to the link, add the link again and remove this profile."
  }
];
/**
 * The service appends this hint to every failed Hysteria 2 check ("Hysteria 2
 * runs over UDP (QUIC): the network may block UDP …, or the link’s password
 * (auth), certificate pin (pinSHA256) or obfs password may be wrong."); the
 * card says the same in its steps instead.
 */
const HYSTERIA2_SERVICE_HINT = /\s*Hysteria 2 runs over UDP \(QUIC\):.*$/su;

function failureSteps(endpoint: string, transport: GlobalTab, protocol?: ProxyProtocol, insecureWithoutPin?: boolean): TextSegment[][] {
  const steps: TextSegment[][] = [[{ text: "Run the check again in a minute. The site may be briefly down." }]];
  if (transport === "xray" && protocol === "hysteria2") {
    if (insecureWithoutPin) {
      steps.push(HYSTERIA2_INSECURE_STEP);
    }
    steps.push(HYSTERIA2_UDP_STEP, HYSTERIA2_LINK_STEP);
  }
  const command = transport === "ssh" ? reachCommand(endpoint) : undefined;
  if (command) {
    steps.push([{ text: "In the server terminal, run " }, { text: command, kind: "code" }, { text: " to see whether the server itself can reach it." }]);
  } else {
    steps.push([{ text: "Change the endpoint to a site you know is up, to rule out the site itself." }]);
  }
  steps.push([{ text: transport === "ssh" ? "Connect through another server or an Xray profile." : "Connect through another profile or an SSH server." }]);
  return steps;
}

function ensureSentence(text: string): string {
  const trimmed = text.trim();
  return /[.!?]$/u.test(trimmed) ? trimmed : `${trimmed}.`;
}

function failedView(
  result: TunnelCheckResult,
  transport: GlobalTab,
  name: string | undefined,
  protocol: ProxyProtocol | undefined,
  insecureWithoutPin: boolean | undefined
): Pick<TunnelCheckView, "text" | "stepsIntro" | "steps"> {
  const endpoint: TextSegment = { text: result.endpoint, kind: "mono" };
  const message = stripIpcPrefix(result.message) || result.message;
  const raw = transport === "xray" && protocol === "hysteria2" ? message.replace(HYSTERIA2_SERVICE_HINT, "") || message : message;
  const timeout = /nothing came back within (\d+)\s*s/iu.exec(raw);
  if (timeout) {
    return {
      text: [{ text: "The tunnel opened a connection to " }, endpoint, { text: ` but nothing came back within ${timeout[1]} s.` }],
      stepsIntro:
        transport === "ssh" && name ? `Traffic reaches ${name} but not the site. Try this:` : "Traffic enters the tunnel but doesn't reach the site. Try this:",
      steps: failureSteps(result.endpoint, transport, protocol, insecureWithoutPin)
    };
  }
  if (/is not connected/iu.test(raw)) {
    return { text: [{ text: "The tunnel wasn't connected when the check ran. Connect, then run it again." }] };
  }
  if (/must be host:port|must use host:port/iu.test(raw)) {
    return { text: [{ text: "The endpoint " }, endpoint, { text: " isn't a host:port address. Change it, then run the check again." }] };
  }
  return {
    text: [{ text: "The check to " }, endpoint, { text: ` failed: ${ensureSentence(raw.replace(/^Tunnel check failed for \S+:\s*/iu, ""))}` }],
    stepsIntro: "Try this:",
    steps: failureSteps(result.endpoint, transport, protocol, insecureWithoutPin)
  };
}

/** "SSH · Frankfurt-01 · today 12:04:18". */
export function checkMeta(result: TunnelCheckResult, fallbackTransport: GlobalTab, fallbackName?: string, now: Date = new Date()): string {
  const transport = TRANSPORT_LABEL[result.transport ?? fallbackTransport];
  const name = result.targetName ?? fallbackName;
  const day = formatDay(result.at, now);
  const when = day ? `${day} ${formatClock(result.at)}` : "";
  return [transport, name, when].filter(Boolean).join(" · ");
}

/**
 * The one tunnel check card both transports share. A result only shows while
 * the transport it checked is connected, so an old colour never lingers.
 */
export function presentTunnelCheck(input: TunnelCheckInput): TunnelCheckView {
  const { result, endpoint, activeTransport, connected, checking } = input;
  if (checking) {
    return {
      kind: "checking",
      badge: "Checking…",
      text: [
        { text: "Sending a test request to " },
        { text: endpoint, kind: "mono" },
        { text: ` through the tunnel. This takes up to ${CHECK_TIMEOUT_SECONDS} s.` }
      ]
    };
  }
  if (!connected) {
    return { kind: "waiting", badge: "Waiting", text: [{ text: "Runs by itself 1.5 s after you connect. After that, run it whenever you like." }] };
  }
  const usable = result && (result.transport ?? activeTransport) === activeTransport;
  if (!result || !usable) {
    return { kind: "idle", badge: "Not run yet", text: [{ text: "Run a check to confirm data really flows." }] };
  }
  const meta = checkMeta(result, activeTransport, input.activeName, input.now);
  if (result.ok && result.note) {
    return {
      kind: "note",
      badge: "Passed",
      text: [
        { text: "The tunnel opened a connection to " },
        { text: result.endpoint, kind: "mono" },
        { text: ". The server sent nothing back, which is normal for this port, so the route couldn't be verified end to end." }
      ],
      meta
    };
  }
  if (result.ok) {
    const latency = latencyOf(result);
    return { kind: "passed", badge: latency !== undefined ? `Passed · ${formatLatency(latency)}` : "Passed", text: passedText(result), meta };
  }
  return {
    kind: "failed",
    badge: "Failed",
    ...failedView(result, activeTransport, result.targetName ?? input.activeName, input.activeProtocol, input.activeInsecureWithoutPin),
    meta
  };
}
