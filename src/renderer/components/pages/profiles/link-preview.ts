import {
  HYSTERIA2_ECH_MESSAGE,
  HYSTERIA2_FINALMASK_MESSAGE,
  HYSTERIA2_HOST_MESSAGE,
  HYSTERIA2_OBFS_PASSWORD_MESSAGE,
  HYSTERIA2_PIN_MESSAGE,
  HYSTERIA2_PORTS_MESSAGE,
  INVALID_HYSTERIA2_URI_MESSAGE,
  isHysteria2Scheme,
  parseHysteria2Link
} from "../../../../core/proxy/hysteria2-link.js";
import type { ProxyProtocol, ProxySecurity, ProxyTransport } from "../../../../shared/types.js";

// Browser-safe mirror of src/core/proxy/share-link-parser.ts (that module needs
// node:crypto and Buffer, which the renderer doesn't have). Same rules, same
// error texts and the same canonical form, so the preview and the duplicate
// check agree with what the main process will save. tests/profiles-link-preview
// keeps the two in step. Hysteria 2 links go through the core's own pure
// reader, so they match by construction.

export const MAX_LINK_LENGTH = 64 * 1024;
export const MAX_IMPORT_LINES = 10_000;
export const MAX_IMPORT_TEXT_LENGTH = 2 * 1024 * 1024;
export const MAX_STORED_PROFILES = 10_000;

/** Typo targets. hy2 is left out on purpose: three letters are too close to h2c and friends. */
export const SUPPORTED_SCHEMES = ["vless", "vmess", "trojan", "hysteria2"] as const;
export const UNSUPPORTED_SCHEME_MESSAGE = "Only vless://, vmess://, trojan://, and hysteria2:// links are supported.";

/**
 * Shown under a previewed Hysteria 2 link that asks to skip certificate
 * checks without a pin: the bundled Xray dropped allowInsecure, so it checks
 * the certificate anyway.
 */
export const HYSTERIA2_INSECURE_WARNING =
  "This link asks to skip certificate checks (insecure=1), which the bundled Xray can’t do, so the server’s certificate is checked as usual. If the server uses a self-signed certificate, add its pinSHA256 to the link.";

/**
 * The same for a saved profile (card, Connect picker and hero). Profiles
 * can't be edited and the pinned link is a new profile, so the advice says to
 * add it again and remove the tagged one.
 */
export const HYSTERIA2_INSECURE_PROFILE_WARNING =
  "This profile’s link asks to skip certificate checks (insecure=1), which the bundled Xray can’t do, so the server’s certificate is checked as usual. If the server uses a self-signed certificate, add the link again with its pinSHA256 and remove this one.";

/**
 * Short mark for a saved profile with `insecureWithoutPin`, on its card and in
 * the Connect picker; `HYSTERIA2_INSECURE_PROFILE_WARNING` explains it. Not "unpinned":
 * Pin already means "keep when removing unpinned profiles" there. Shared with the tray.
 */
export { HYSTERIA2_INSECURE_TAG } from "../../../../shared/proxy-protocols.js";

/** The schemes people can paste, for copy: "vless://, vmess://, trojan:// or hysteria2://". */
const LINK_SCHEMES_TEXT = "vless://, vmess://, trojan:// or hysteria2://";

export interface LinkPreview {
  name: string;
  protocol: ProxyProtocol;
  host: string;
  port: number;
  /** Hysteria 2 port hopping: every port the link hops across ("443,20000-30000"), as the profile stores it. */
  hopPorts?: string;
  /** insecure=1 without a pinSHA256, as the profile stores it (only ever `true`). */
  insecureWithoutPin?: boolean;
  /** Hysteria 2 link with a pinSHA256 (only ever `true`); not stored, it tells a fixed link from a tagged one. */
  certificatePinned?: boolean;
  transport: ProxyTransport;
  security: ProxySecurity;
  /** Things to know before saving, such as `HYSTERIA2_INSECURE_WARNING`. Absent when there are none. */
  warnings?: string[];
  /** The text the core hashes into the profile fingerprint. */
  canonical: string;
}

export type LinkPreviewResult =
  | { status: "empty" }
  | { status: "ok"; link: LinkPreview }
  /** `message` is the core parser's own text; show `describeLinkProblem` to people. */
  | { status: "error"; message: string };

interface VmessPayload {
  ps?: string;
  add?: string;
  port?: string | number;
  net?: string;
  tls?: string;
  flow?: string;
}

/** Reads one share link the way the main process will. Never throws. */
export function previewShareLink(raw: string): LinkPreviewResult {
  const link = raw.trim();
  if (!link) {
    return { status: "empty" };
  }
  try {
    return { status: "ok", link: parseShareLink(link) };
  } catch (error) {
    return { status: "error", message: error instanceof Error ? error.message : String(error) };
  }
}

/** Throws the core parser's messages for links it would reject. */
export function parseShareLink(rawUri: string): LinkPreview {
  if (rawUri.length > MAX_LINK_LENGTH) {
    throw new Error(`Proxy link is longer than ${MAX_LINK_LENGTH} characters.`);
  }
  const protocol = detectProtocol(rawUri);
  if (protocol === "vmess") {
    return parseVmess(rawUri);
  }
  return protocol === "hysteria2" ? parseHysteria2(rawUri) : parseUriProtocol(rawUri, protocol);
}

/** `sha256:<hex>`, equal to the stored `ProxyProfile.fingerprint`; undefined without WebCrypto. */
export async function linkFingerprint(link: Pick<LinkPreview, "canonical">): Promise<string | undefined> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    return undefined;
  }
  try {
    const digest = await subtle.digest("SHA-256", new TextEncoder().encode(link.canonical));
    return `sha256:${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  } catch {
    return undefined;
  }
}

/** The scheme before `://`, lower-cased, or undefined when the text has none. */
export function linkScheme(raw: string): string | undefined {
  return raw.trim().match(/^([a-z][a-z0-9+.-]*):\/\//iu)?.[1]?.toLowerCase();
}

/** Other proxy schemes people paste. They're never typos of a supported one. */
const SCHEME_NAMES: Record<string, string> = {
  ss: "Shadowsocks",
  ssr: "ShadowsocksR",
  hysteria: "Hysteria v1",
  "hysteria2+realm": "Hysteria 2 Realm",
  tuic: "TUIC",
  wireguard: "WireGuard",
  wg: "WireGuard",
  socks: "SOCKS",
  socks5: "SOCKS5"
};

/** Hysteria v1 is the one close miss with a working sibling; say so instead of only "can't run". */
const HYSTERIA_V1_HINT = "Hysteria v1 links can’t run in Shadow SSH. Hysteria 2 links (hysteria2:// or hy2://) work.";

/** A likely typo of a supported scheme ("vles" → "vless"), when there is exactly one close match. */
export function suggestScheme(raw: string): { from: string; to: (typeof SUPPORTED_SCHEMES)[number] } | undefined {
  const scheme = linkScheme(raw);
  if (!scheme || scheme.length < 3 || (SUPPORTED_SCHEMES as readonly string[]).includes(scheme) || isHysteria2Scheme(scheme) || SCHEME_NAMES[scheme]) {
    return undefined;
  }
  let best: (typeof SUPPORTED_SCHEMES)[number] | undefined;
  let bestDistance = Number.POSITIVE_INFINITY;
  let tie = false;
  for (const candidate of SUPPORTED_SCHEMES) {
    const distance = editDistance(scheme, candidate);
    if (distance < bestDistance) {
      best = candidate;
      bestDistance = distance;
      tie = false;
    } else if (distance === bestDistance) {
      tie = true;
    }
  }
  return best && !tie && bestDistance <= 2 ? { from: scheme, to: best } : undefined;
}

/** Replaces a mistyped scheme at the start of the link, keeping everything after `://`. */
export function applySchemeFix(raw: string, to: string): string {
  return raw.replace(/^(\s*)[a-z][a-z0-9+.-]*:\/\//iu, `$1${to}://`);
}

/**
 * Plain-words explanation of why a link can't be saved, for the Add profile
 * field. `message` is the parser's text from `previewShareLink`.
 */
export function describeLinkProblem(raw: string, message: string): string {
  const scheme = linkScheme(raw);
  if (message === UNSUPPORTED_SCHEME_MESSAGE) {
    if (!scheme) {
      return `This isn’t a share link. Paste one that starts with ${LINK_SCHEMES_TEXT}.`;
    }
    const typo = suggestScheme(raw);
    if (typo) {
      return `Looks like a typo: ${typo.from}:// instead of ${typo.to}://.`;
    }
    if (scheme === "http" || scheme === "https") {
      return `That’s a web address, not a share link. Subscription URLs aren’t supported, so paste the ${LINK_SCHEMES_TEXT} links themselves.`;
    }
    if (scheme === "hysteria") {
      return "This is a hysteria:// (Hysteria v1) link, which Shadow SSH can’t run. Hysteria 2 links work, so paste a hysteria2:// or hy2:// link instead.";
    }
    const name = SCHEME_NAMES[scheme];
    return name
      ? `This is ${/^(ss|[aeiou])/u.test(scheme) ? "an" : "a"} ${scheme}:// (${name}) link, which Shadow SSH can’t run. Paste a ${LINK_SCHEMES_TEXT} link instead.`
      : `${scheme}:// links can’t run in Shadow SSH. Paste a ${LINK_SCHEMES_TEXT} link instead.`;
  }
  if (/^Invalid VMess base64 JSON payload\.$/u.test(message)) {
    return "This vmess:// link is damaged: its encoded part can’t be read. Copy it again from your provider.";
  }
  if (message === HYSTERIA2_HOST_MESSAGE) {
    return `This ${scheme ?? "hysteria2"}:// link has no server address. Copy it again from your provider.`;
  }
  if (message === HYSTERIA2_PORTS_MESSAGE) {
    // The authority, mport or the fm JSON.
    return `This ${scheme ?? "hysteria2"}:// link’s ports can’t be read. Ports look like 443 or 443,20000-30000, with at most 64 ranges. Copy it again from your provider.`;
  }
  if (message === INVALID_HYSTERIA2_URI_MESSAGE) {
    return `This ${scheme ?? "hysteria2"}:// link is damaged, so it can’t be read. Copy it again from your provider.`;
  }
  if (message === HYSTERIA2_ECH_MESSAGE) {
    return "The ech value in this link isn’t an ECH config list, so it can’t be used. Copy the link again from your provider.";
  }
  if (/must contain (host and valid port|add and valid port)\.$/u.test(message)) {
    return `This ${scheme ?? "share"}:// link has no server address or a wrong port. Copy it again from your provider.`;
  }
  if (/^Invalid (VLESS|TROJAN) URI\.$/u.test(message)) {
    return `This ${scheme ?? "share"}:// link is damaged, so it can’t be read. Copy it again from your provider.`;
  }
  const obfs = /^Unsupported Hysteria 2 obfuscation: (.+)\. Only salamander works\.$/u.exec(message);
  if (obfs) {
    return `This link hides its traffic with ${obfs[1]} obfuscation, which the bundled Xray can’t run. Only salamander works, so ask your provider for a link that uses it.`;
  }
  if (message === HYSTERIA2_OBFS_PASSWORD_MESSAGE) {
    return "This link turns on salamander obfuscation but has no obfs-password, so it can’t connect. Copy it again from your provider.";
  }
  if (message === HYSTERIA2_PIN_MESSAGE) {
    return "The pinSHA256 in this link isn’t a certificate hash (64 hex characters), so the server can’t be checked. Copy it again from your provider.";
  }
  const mask = /^Unsupported Hysteria 2 finalmask type: (.+)\.$/u.exec(message);
  if (mask) {
    // A choice of Shadow SSH, not a limit of the bundled Xray: it reads only these two from fm.
    const what = mask[1] === "salamander with packetSize" ? "a salamander packetSize" : mask[1];
    return `The fm settings in this link use ${what}, which Shadow SSH doesn’t support with Hysteria 2 (only salamander and port hopping). Remove the fm part or ask your provider for another link.`;
  }
  if (message === HYSTERIA2_FINALMASK_MESSAGE) {
    return "The fm settings in this link (Xray finalmask JSON) can’t be read. Remove the fm part or copy the link again from your provider.";
  }
  if (/is longer than \d+ (characters|bytes)\.$/u.test(message)) {
    return "This is longer than 65,536 characters, so it can’t be a single share link.";
  }
  return message;
}

/** The import list shows the parser's text; this one reads better with the board's punctuation. */
export function importFailureMessage(message: string): string {
  return message === UNSUPPORTED_SCHEME_MESSAGE ? "Only vless://, vmess://, trojan:// and hysteria2:// links are supported." : message;
}

/**
 * Extra line under a failed import line: a typo fix, or what kind of link it
 * is. Judged from the line itself, so it holds whatever the error text says.
 */
export function importFailureHint(line: string): { hint: string; fix?: { from: string; to: string } } | undefined {
  const own = previewShareLink(line);
  if (own.status !== "error" || own.message !== UNSUPPORTED_SCHEME_MESSAGE) {
    return undefined;
  }
  const typo = suggestScheme(line);
  if (typo) {
    return { hint: `Looks like a typo: ${typo.from}:// instead of ${typo.to}://`, fix: typo };
  }
  const scheme = linkScheme(line);
  if (scheme === "http" || scheme === "https") {
    return { hint: "This is a web address. Subscription URLs aren’t supported." };
  }
  if (scheme === "hysteria") {
    return { hint: HYSTERIA_V1_HINT };
  }
  const name = scheme ? SCHEME_NAMES[scheme] : undefined;
  return name ? { hint: `${name} links can’t run in Shadow SSH.` } : undefined;
}

// ---------- mirrored parser ----------

function detectProtocol(rawUri: string): ProxyProtocol {
  const protocol = rawUri.match(/^([a-z][a-z0-9+.-]*):\/\//iu)?.[1]?.toLowerCase();
  if (protocol === "vless" || protocol === "vmess" || protocol === "trojan") {
    return protocol;
  }
  if (isHysteria2Scheme(protocol)) {
    return "hysteria2";
  }
  throw new Error(UNSUPPORTED_SCHEME_MESSAGE);
}

/** hysteria2:// and hy2://: always QUIC + TLS, read by the same module the core uses. */
function parseHysteria2(rawUri: string): LinkPreview {
  const link = parseHysteria2Link(rawUri);
  // With a pin, insecure=1 is fine: the pin is what gets checked.
  const insecureWithoutPin = link.insecure && link.pinnedCertSha256.length === 0;
  return {
    name: link.name,
    protocol: "hysteria2",
    host: link.host,
    port: link.port,
    ...(link.hopPorts ? { hopPorts: link.hopPorts } : {}),
    ...(insecureWithoutPin ? { insecureWithoutPin: true } : {}),
    ...(link.pinnedCertSha256.length > 0 ? { certificatePinned: true } : {}),
    transport: "hysteria",
    security: "tls",
    ...(insecureWithoutPin ? { warnings: [HYSTERIA2_INSECURE_WARNING] } : {}),
    canonical: link.canonical
  };
}

function parseUriProtocol(rawUri: string, protocol: Exclude<ProxyProtocol, "vmess" | "hysteria2">): LinkPreview {
  let url: URL;
  try {
    url = new URL(rawUri);
  } catch {
    throw new Error(`Invalid ${protocol.toUpperCase()} URI.`);
  }
  const host = normalizeHost(url.hostname);
  const port = Number(url.port);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${protocol.toUpperCase()} URI must contain host and valid port.`);
  }
  const params = url.searchParams;
  const canonicalParams = [...params.entries()]
    .map(([key, value]) => [key.toLowerCase(), value] as const)
    .sort(([left], [right]) => left.localeCompare(right));
  return {
    name: decodeName(url.hash, `${protocol}-${host}:${port}`),
    protocol,
    host,
    port,
    transport: normalizeTransport(params.get("type") ?? params.get("net") ?? "tcp"),
    security: normalizeSecurity(params.get("security") ?? (params.get("tls") === "1" ? "tls" : "none")),
    canonical: JSON.stringify({
      protocol,
      username: url.username,
      host,
      port,
      params: canonicalParams,
      hash: decodeName(url.hash, "")
    })
  };
}

function parseVmess(rawUri: string): LinkPreview {
  const encoded = rawUri.replace(/^vmess:\/\//iu, "").trim();
  let payload: VmessPayload;
  try {
    payload = JSON.parse(decodeBase64Utf8(encoded)) as VmessPayload;
  } catch {
    throw new Error("Invalid VMess base64 JSON payload.");
  }
  if (payload === null || typeof payload !== "object") {
    // JSON.parse("1") etc.: the core then fails reading `add`.
    throw new Error("VMess payload must contain add and valid port.");
  }
  const host = normalizeHost(String(payload.add ?? ""));
  const port = Number(payload.port);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("VMess payload must contain add and valid port.");
  }
  const transport = normalizeTransport(payload.net ?? "tcp");
  const security = normalizeSecurity(payload.tls || "none");
  const name = String(payload.ps ?? `vmess-${host}:${port}`).trim() || `vmess-${host}:${port}`;
  const sorted = Object.fromEntries(
    Object.entries({ ...payload, add: host, port, net: transport, tls: security }).sort(([left], [right]) => left.localeCompare(right))
  );
  return { name, protocol: "vmess", host, port, transport, security, canonical: `vmess:${JSON.stringify(sorted)}` };
}

/** Decodes like Node's Buffer: skips characters outside the alphabet and stops at the first "=". */
function decodeBase64Utf8(value: string): string {
  const normalized = value.replace(/\s+/gu, "").replace(/-/gu, "+").replace(/_/gu, "/");
  let data = normalized.replace(/[^A-Za-z0-9+/=]/gu, "");
  const padding = data.indexOf("=");
  if (padding >= 0) {
    data = data.slice(0, padding);
  }
  if (data.length % 4 === 1) {
    data = data.slice(0, -1);
  }
  const binary = atob(data.padEnd(Math.ceil(data.length / 4) * 4, "="));
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder("utf-8").decode(bytes);
}

function normalizeHost(value: string): string {
  return value.trim().replace(/^\[/u, "").replace(/\]$/u, "").toLowerCase();
}

function decodeName(hash: string, fallback: string): string {
  if (!hash) {
    return fallback;
  }
  try {
    return decodeURIComponent(hash.replace(/^#/u, "")).trim() || fallback;
  } catch {
    return hash.replace(/^#/u, "").trim() || fallback;
  }
}

function normalizeTransport(value: string): ProxyTransport {
  const normalized = value.trim().toLowerCase();
  if (normalized === "raw") {
    return "tcp";
  }
  if (normalized === "kcp") {
    return "mkcp";
  }
  // HTTP/2 (h2, http) is gone from Xray 26, like QUIC.
  if (["tcp", "ws", "grpc", "xhttp", "mkcp", "hysteria"].includes(normalized)) {
    return normalized as ProxyTransport;
  }
  if (normalized === "httpupgrade" || normalized === "http-upgrade" || normalized === "http_upgrade") {
    return "httpupgrade";
  }
  return "unknown";
}

function normalizeSecurity(value: string): ProxySecurity {
  const normalized = value.trim().toLowerCase();
  if (!normalized || normalized === "0" || normalized === "false" || normalized === "none") {
    return "none";
  }
  if (normalized === "tls" || normalized === "reality") {
    return normalized;
  }
  return "unknown";
}

/** Optimal string alignment distance (adjacent swaps count as one edit). */
function editDistance(a: string, b: string): number {
  const rows = a.length + 1;
  const cols = b.length + 1;
  const d: number[][] = Array.from({ length: rows }, (_, i) => Array.from({ length: cols }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
  for (let i = 1; i < rows; i += 1) {
    for (let j = 1; j < cols; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[a.length][b.length];
}
