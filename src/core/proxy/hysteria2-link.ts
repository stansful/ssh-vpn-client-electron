// Hysteria 2 share links: hysteria2://[auth@]host[:ports]/?params#name, with
// hy2:// as an alias. No Node APIs here: the main-process parser, the Xray
// config builder and the renderer's Add-profile preview all read links through
// this one module, so the stored fingerprint and the preview's duplicate check
// can't drift apart.
//
// Format: https://v2.hysteria.network/docs/developers/URI-Scheme/, plus the
// non-standard keys real clients and panels emit (mport, up/down, pcs, fm ...).
// WHATWG URL can't parse these links on its own: it rejects port lists such as
// "host:443,20000-30000", so the authority is split by hand.

export const HYSTERIA2_DEFAULT_PORT = 443;
/** Seconds between port hops when the link doesn't say; Hysteria's own default. */
export const HYSTERIA2_DEFAULT_HOP_INTERVAL = 30;

export const INVALID_HYSTERIA2_URI_MESSAGE = "Invalid Hysteria 2 link.";
export const HYSTERIA2_HOST_MESSAGE = "Hysteria 2 link must contain a server host.";
export const HYSTERIA2_PORTS_MESSAGE = "Hysteria 2 link has an invalid port list.";
export const HYSTERIA2_OBFS_PASSWORD_MESSAGE = "Hysteria 2 salamander obfuscation needs obfs-password.";
export const HYSTERIA2_PIN_MESSAGE = "Invalid Hysteria 2 pinSHA256: expected a SHA-256 certificate hash.";
export const HYSTERIA2_FINALMASK_MESSAGE = "Invalid Hysteria 2 fm parameter: expected finalmask JSON.";
export const HYSTERIA2_ECH_MESSAGE = "Invalid Hysteria 2 ech: expected a base64 ECHConfigList.";

/** Xray refuses shorter hop intervals. */
const MIN_HOP_INTERVAL = 5;
/** A DNS name is at most 253 characters; anything longer is not a server. */
const MAX_HOST_LENGTH = 253;
/**
 * Distinct port ranges a hop list may keep after merging. Xray expands every
 * range port by port, so an unbounded list of repeated "1-65535" ranges in a
 * 64 KB link would cost it gigabytes.
 */
const MAX_HOP_RANGES = 64;
/**
 * Longest scalar value (a rate, an interval, one pin) worth reading. Values
 * come from untrusted links; a bound keeps every pattern below linear-time.
 */
const MAX_SCALAR_LENGTH = 128;
/** Xray rejects brutal rates under 65536 bytes per second. */
const MIN_BRUTAL_BITS_PER_SECOND = 65_536 * 8;
const CONGESTION_CONTROLS = ["reno", "bbr", "brutal", "force-brutal"] as const;

export type Hysteria2Congestion = (typeof CONGESTION_CONTROLS)[number];

/** QUIC tuning a panel's `fm` parameter may carry; values Xray would refuse are dropped. */
export interface Hysteria2QuicParams {
  initStreamReceiveWindow?: number;
  maxStreamReceiveWindow?: number;
  initConnectionReceiveWindow?: number;
  maxConnectionReceiveWindow?: number;
  maxIdleTimeout?: number;
  keepAlivePeriod?: number;
  disablePathMTUDiscovery?: boolean;
}

export interface Hysteria2Link {
  name: string;
  /** Hysteria auth: the whole userinfo, decoded ("user:pass" for userpass auth). May be empty. */
  auth: string;
  /** Bare host: lower case, punycode, IPv6 without brackets. */
  host: string;
  /**
   * First port of the authority. Without hopping Xray dials it; with hopping
   * Xray starts on a random port of hopPorts and never uses this one.
   */
  port: number;
  /** Sorted, merged port list ("443,20000-30000") when the link hops across more than one port. */
  hopPorts?: string;
  /** Seconds between hops: a number or an Xray "min-max" range. Set whenever hopPorts is. */
  hopInterval?: number | string;
  /** TLS server name: sni, else the host. */
  sni: string;
  /** Salamander obfuscation password. */
  obfsPassword?: string;
  /** Lower-case hex SHA-256 certificate pins. */
  pinnedCertSha256: string[];
  /** The link asks to skip certificate checks (insecure=1); only a pin can stand in for that. */
  insecure: boolean;
  verifyPeerCertByName?: string;
  echConfigList?: string;
  congestion?: Hysteria2Congestion;
  /** Brutal rates as Xray bandwidth strings ("50000000 bps"). */
  brutalUp?: string;
  brutalDown?: string;
  quic: Hysteria2QuicParams;
  /** The text the profile fingerprint hashes. */
  canonical: string;
}

interface PortRange {
  from: number;
  to: number;
}

/** What a panel's `fm` (Xray finalmask JSON) parameter adds to the link. */
interface FinalMaskHints {
  obfsPassword?: string;
  hopPorts?: PortRange[];
  hopInterval?: number | string;
  congestion?: Hysteria2Congestion;
  brutalUp?: string;
  brutalDown?: string;
  quic: Hysteria2QuicParams;
}

export function isHysteria2Scheme(scheme: string | undefined): boolean {
  const normalized = scheme?.toLowerCase();
  return normalized === "hysteria2" || normalized === "hy2";
}

/** Reads a hysteria2:// or hy2:// link. Throws with the messages exported above. */
export function parseHysteria2Link(rawUri: string): Hysteria2Link {
  const match = /^([a-z][a-z0-9+.-]*):\/\/([^?#]*)(\?[^#]*)?(#.*)?$/isu.exec(rawUri);
  if (!match || !isHysteria2Scheme(match[1])) {
    throw new Error(INVALID_HYSTERIA2_URI_MESSAGE);
  }
  const head = match[2] ?? "";
  const query = match[3] ?? "";
  const fragment = (match[4] ?? "").split("?serverDescription=")[0] ?? "";

  // The auth may hold "/" or "@" when a panel didn't escape it, so the
  // userinfo ends at the last "@" and the authority at the first "/" after it.
  const at = head.lastIndexOf("@");
  const userinfo = at >= 0 ? head.slice(0, at) : "";
  const afterUserinfo = at >= 0 ? head.slice(at + 1) : head;
  const slash = afterUserinfo.indexOf("/");
  const authority = slash >= 0 ? afterUserinfo.slice(0, slash) : afterUserinfo;

  const { rawHost, portSpec } = splitAuthority(authority);
  if (!rawHost) {
    throw new Error(HYSTERIA2_HOST_MESSAGE);
  }
  const host = normalizeHost(rawHost);
  const writtenPorts = portSpec ? readPortList(portSpec) : [{ from: HYSTERIA2_DEFAULT_PORT, to: HYSTERIA2_DEFAULT_PORT }];
  const port = writtenPorts[0].from;
  const authorityPorts = mergePortRanges(writtenPorts);

  const entries = [...new URLSearchParams(query)];
  const param = firstParam(entries);
  const fm = parseFinalMask(param("fm"));

  // Explicit link keys win over the panel's fm JSON.
  const mport = param("mport", "mports")?.trim();
  const hopRanges = mport
    ? mergePortRanges(readPortList(mport.replace(/(\d)\s*:\s*(\d)/gu, "$1-$2")))
    : coversSeveralPorts(authorityPorts) ? authorityPorts : fm.hopPorts ?? authorityPorts;
  const hopPorts = coversSeveralPorts(hopRanges) ? formatPortList(hopRanges) : undefined;
  const hopInterval = hopPorts
    ? parseHopInterval(param("hopinterval", "hop-interval", "hop_interval", "mporthopint"), param("hop_interval_max"))
      ?? fm.hopInterval
      ?? HYSTERIA2_DEFAULT_HOP_INTERVAL
    : undefined;

  const brutalUp = parseHysteriaBandwidth(param("up", "upmbps")) ?? fm.brutalUp;
  const brutalDown = parseHysteriaBandwidth(param("down", "downmbps")) ?? fm.brutalDown;
  // force-brutal without an upload rate makes Xray refuse the whole config.
  const congestion = fm.congestion === "force-brutal" && !brutalUp ? undefined : fm.congestion;

  const name = decodeName(fragment, "");
  return {
    name: name || `hysteria2-${host}:${port}`,
    auth: decodeComponent(userinfo),
    host,
    port,
    hopPorts,
    hopInterval,
    sni: param("sni", "peer")?.trim() || host,
    obfsPassword: readObfsPassword(param("obfs"), param("obfs-password", "obfspassword", "obfs_password"), fm.obfsPassword),
    pinnedCertSha256: readPins([param("pinsha256"), param("pcs")]),
    insecure: parseFlag(param("insecure", "allowinsecure", "allow_insecure")),
    verifyPeerCertByName: param("vcn")?.trim() || undefined,
    echConfigList: readEchConfigList(param("ech")),
    congestion,
    brutalUp,
    brutalDown,
    quic: fm.quic,
    canonical: JSON.stringify({
      protocol: "hysteria2",
      auth: decodeComponent(userinfo),
      host,
      ports: formatPortList(authorityPorts),
      params: entries
        .map(([key, value]) => [key.toLowerCase(), value] as const)
        .sort(([left], [right]) => left.localeCompare(right)),
      hash: name
    })
  };
}

/**
 * Hysteria's bandwidth notation: a bare number is Mbps and units are decimal
 * ("100", "30 Mbps", "1gbps"). Returns an exact Xray bandwidth string
 * ("100000000 bps"), or undefined for empty, unreadable or too-small rates,
 * which leaves congestion control to BBR.
 */
export function parseHysteriaBandwidth(value: string | undefined): string | undefined {
  const match = /^(\d+(?:\.\d+)?)\s*([a-z]*)$/iu.exec(boundedTrim(value));
  if (!match) {
    return undefined;
  }
  const multiplier = DECIMAL_BANDWIDTH_UNITS[match[2].toLowerCase()];
  if (multiplier === undefined) {
    return undefined;
  }
  const bitsPerSecond = Math.round(Number(match[1]) * multiplier);
  return bitsPerSecond >= MIN_BRUTAL_BITS_PER_SECOND ? `${bitsPerSecond} bps` : undefined;
}

const DECIMAL_BANDWIDTH_UNITS: Record<string, number> = {
  "": 1e6,
  b: 1,
  bps: 1,
  k: 1e3,
  kb: 1e3,
  kbps: 1e3,
  m: 1e6,
  mb: 1e6,
  mbps: 1e6,
  g: 1e9,
  gb: 1e9,
  gbps: 1e9,
  t: 1e12,
  tb: 1e12,
  tbps: 1e12
};

/** Xray's own bandwidth notation (binary units, "60 mbps"), as an `fm` JSON value carries it. */
function readXrayBandwidth(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const match = /^(\d+(?:\.\d+)?)\s*([a-z]*)$/iu.exec(boundedTrim(value).toLowerCase());
  if (!match) {
    return undefined;
  }
  const multiplier = BINARY_BANDWIDTH_UNITS[match[2]];
  if (multiplier === undefined) {
    return undefined;
  }
  return Number(match[1]) * multiplier >= MIN_BRUTAL_BITS_PER_SECOND ? value.trim() : undefined;
}

const BINARY_BANDWIDTH_UNITS: Record<string, number> = {
  "": 1,
  b: 1,
  bps: 1,
  k: 1024,
  kb: 1024,
  kbps: 1024,
  m: 1024 ** 2,
  mb: 1024 ** 2,
  mbps: 1024 ** 2,
  g: 1024 ** 3,
  gb: 1024 ** 3,
  gbps: 1024 ** 3,
  t: 1024 ** 4,
  tb: 1024 ** 4,
  tbps: 1024 ** 4
};

function splitAuthority(authority: string): { rawHost: string; portSpec?: string } {
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    const rest = end >= 0 ? authority.slice(end + 1) : "";
    if (end < 0 || (rest && !rest.startsWith(":"))) {
      throw new Error(INVALID_HYSTERIA2_URI_MESSAGE);
    }
    return { rawHost: authority.slice(1, end), portSpec: rest.slice(1) };
  }
  const colon = authority.indexOf(":");
  return colon >= 0 ? { rawHost: authority.slice(0, colon), portSpec: authority.slice(colon + 1) } : { rawHost: authority };
}

/** Lower case, punycode for IDNs, IPv6 without brackets; the host Xray and the TUN exclusion use. */
function normalizeHost(rawHost: string): string {
  if (rawHost.length > MAX_HOST_LENGTH) {
    throw new Error(INVALID_HYSTERIA2_URI_MESSAGE);
  }
  try {
    const hostname = new URL(rawHost.includes(":") ? `https://[${rawHost}]/` : `https://${rawHost}/`).hostname;
    return hostname.replace(/^\[/u, "").replace(/\]$/u, "").toLowerCase();
  } catch {
    throw new Error(INVALID_HYSTERIA2_URI_MESSAGE);
  }
}

/** "443", "20000-30000" or "443,20000-30000", in the order written; reversed ranges are put in order. */
function readPortList(spec: string): PortRange[] {
  const items = spec.split(",");
  // Generous for a written list, and it bounds the work before merging.
  if (items.length > MAX_HOP_RANGES * 4) {
    throw new Error(HYSTERIA2_PORTS_MESSAGE);
  }
  return items.map((item) => {
    const match = /^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/u.exec(item.trim());
    if (!match) {
      throw new Error(HYSTERIA2_PORTS_MESSAGE);
    }
    const first = Number(match[1]);
    const last = match[2] === undefined ? first : Number(match[2]);
    const from = Math.min(first, last);
    const to = Math.max(first, last);
    if (from < 1 || to > 65_535) {
      throw new Error(HYSTERIA2_PORTS_MESSAGE);
    }
    return { from, to };
  });
}

/** Sorted, with overlapping and adjacent ranges joined, so no port is listed twice. */
function mergePortRanges(ranges: PortRange[]): PortRange[] {
  const merged: PortRange[] = [];
  for (const range of [...ranges].sort((left, right) => left.from - right.from)) {
    const last = merged.at(-1);
    if (last && range.from <= last.to + 1) {
      last.to = Math.max(last.to, range.to);
    } else {
      merged.push({ ...range });
    }
  }
  if (merged.length > MAX_HOP_RANGES) {
    throw new Error(HYSTERIA2_PORTS_MESSAGE);
  }
  return merged;
}

function formatPortList(ranges: PortRange[]): string {
  return ranges.map(({ from, to }) => (from === to ? String(from) : `${from}-${to}`)).join(",");
}

/** Takes merged ranges. */
function coversSeveralPorts(ranges: PortRange[]): boolean {
  return ranges.length > 1 || ranges[0].from !== ranges[0].to;
}

/** Seconds as a number or "min-max"; "30s" is read as 30. At least 5, as Xray requires. */
function parseHopInterval(value: string | number | undefined, maxValue?: string): number | string | undefined {
  const compact = (raw: string | number | undefined): string => boundedTrim(raw === undefined ? undefined : String(raw)).replace(/\s+/gu, "");
  const seconds = (raw: string | number | undefined): number | undefined => {
    const text = compact(raw).replace(/s$/iu, "");
    return /^\d{1,6}$/u.test(text) ? Math.max(MIN_HOP_INTERVAL, Number(text)) : undefined;
  };
  const range = /^(\d{1,6})s?-(\d{1,6})s?$/iu.exec(compact(value));
  const min = range ? seconds(range[1]) : seconds(value);
  const max = range ? seconds(range[2]) : seconds(maxValue);
  if (min === undefined) {
    return undefined;
  }
  if (max === undefined || max === min) {
    return min;
  }
  return `${Math.min(min, max)}-${Math.max(min, max)}`;
}

function readObfsPassword(obfs: string | undefined, password: string | undefined, maskPassword: string | undefined): string | undefined {
  const type = obfs?.trim().toLowerCase() ?? "";
  if (type === "none" || type === "plain" || (!type && !password && maskPassword === undefined)) {
    return undefined;
  }
  if (type && type !== "salamander") {
    throw new Error(`Unsupported Hysteria 2 obfuscation: ${echoed(type)}. Only salamander works.`);
  }
  // NekoBox and v2rayN treat obfs-password without obfs as salamander.
  const chosen = password || maskPassword;
  if (!chosen) {
    throw new Error(HYSTERIA2_OBFS_PASSWORD_MESSAGE);
  }
  return chosen;
}

function readPins(values: Array<string | undefined>): string[] {
  const pins = new Set<string>();
  for (const item of values.flatMap((value) => value?.split(",") ?? [])) {
    if (item.trim()) {
      pins.add(normalizePin(item.trim()));
    }
  }
  return [...pins];
}

/** Hex with or without ":"/"-" separators (the openssl form), or base64 as some panels store it. */
function normalizePin(value: string): string {
  if (value.length > MAX_SCALAR_LENGTH) {
    throw new Error(HYSTERIA2_PIN_MESSAGE);
  }
  const hex = value.replace(/[\s:-]/gu, "");
  if (/^[0-9a-f]{64}$/iu.test(hex)) {
    return hex.toLowerCase();
  }
  const bytes = decodeBase64(value);
  if (bytes?.length === 32) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  throw new Error(HYSTERIA2_PIN_MESSAGE);
}

function decodeBase64(value: string): Uint8Array | undefined {
  let end = value.length;
  while (end > 0 && value[end - 1] === "=") {
    end -= 1;
  }
  const data = value.slice(0, end).replace(/-/gu, "+").replace(/_/gu, "/");
  if (!/^[A-Za-z0-9+/]*$/u.test(data) || data.length % 4 === 1) {
    return undefined;
  }
  try {
    return Uint8Array.from(atob(data.padEnd(Math.ceil(data.length / 4) * 4, "=")), (char) => char.charCodeAt(0));
  } catch {
    return undefined;
  }
}

/**
 * Only the base64 ECHConfigList form. Xray also reads a DNS server spec here
 * ("udp://…", "https://…") and queries it directly, outside the tunnel; a
 * share link must not choose extra hosts for the client to contact.
 */
function readEchConfigList(value: string | undefined): string | undefined {
  const text = value?.trim();
  if (!text) {
    return undefined;
  }
  const bytes = decodeBase64(text);
  // ECHConfigList: a 2-byte length, then that many bytes of configs.
  if (!bytes || bytes.length < 4 || ((bytes[0] << 8) | bytes[1]) !== bytes.length - 2) {
    throw new Error(HYSTERIA2_ECH_MESSAGE);
  }
  return text;
}

function parseFinalMask(value: string | undefined): FinalMaskHints {
  const hints: FinalMaskHints = { quic: {} };
  if (!value?.trim()) {
    return hints;
  }
  let json: unknown;
  try {
    json = JSON.parse(value);
  } catch {
    throw new Error(HYSTERIA2_FINALMASK_MESSAGE);
  }
  if (!isRecord(json)) {
    throw new Error(HYSTERIA2_FINALMASK_MESSAGE);
  }

  for (const mask of readArray(json.udp)) {
    if (!isRecord(mask) || typeof mask.type !== "string") {
      throw new Error(HYSTERIA2_FINALMASK_MESSAGE);
    }
    const type = mask.type.toLowerCase();
    const settings = isRecord(mask.settings) ? mask.settings : {};
    if (type === "salamander" && settings.packetSize === undefined) {
      hints.obfsPassword ??= typeof settings.password === "string" ? settings.password : undefined;
    } else if (type === "udphop") {
      // Newer Xray carries port hopping as a UDP mask; read it the same way.
      hints.hopPorts ??= readMaskPorts(settings.remotePorts);
      hints.hopInterval ??= parseHopInterval(readIntervalValue(settings.interval));
    } else {
      throw new Error(`Unsupported Hysteria 2 finalmask type: ${type === "salamander" ? "salamander with packetSize" : echoed(type)}.`);
    }
  }

  if (json.quicParams !== undefined) {
    const quic = json.quicParams;
    if (!isRecord(quic)) {
      throw new Error(HYSTERIA2_FINALMASK_MESSAGE);
    }
    const congestion = typeof quic.congestion === "string" ? quic.congestion.trim().toLowerCase() : "";
    hints.congestion = (CONGESTION_CONTROLS as readonly string[]).includes(congestion) ? (congestion as Hysteria2Congestion) : undefined;
    hints.brutalUp = readXrayBandwidth(quic.brutalUp);
    hints.brutalDown = readXrayBandwidth(quic.brutalDown);
    if (isRecord(quic.udpHop)) {
      hints.hopPorts ??= readMaskPorts(quic.udpHop.ports);
      hints.hopInterval ??= parseHopInterval(readIntervalValue(quic.udpHop.interval));
    }
    hints.quic = stripUndefined({
      initStreamReceiveWindow: readInteger(quic.initStreamReceiveWindow, 16_384),
      maxStreamReceiveWindow: readInteger(quic.maxStreamReceiveWindow, 16_384),
      initConnectionReceiveWindow: readInteger(quic.initConnectionReceiveWindow, 16_384),
      maxConnectionReceiveWindow: readInteger(quic.maxConnectionReceiveWindow, 16_384),
      maxIdleTimeout: readInteger(quic.maxIdleTimeout, 4, 120),
      keepAlivePeriod: readInteger(quic.keepAlivePeriod, 2, 60),
      disablePathMTUDiscovery: quic.disablePathMTUDiscovery === true ? true : undefined
    });
  }
  return hints;
}

function readMaskPorts(value: unknown): PortRange[] | undefined {
  if (typeof value !== "string" && typeof value !== "number") {
    return undefined;
  }
  const spec = String(value).trim().replace(/(\d)\s*:\s*(\d)/gu, "$1-$2");
  return spec ? mergePortRanges(readPortList(spec)) : undefined;
}

function readIntervalValue(value: unknown): string | number | undefined {
  return typeof value === "string" || typeof value === "number" ? value : undefined;
}

function readInteger(value: unknown, min: number, max = Number.MAX_SAFE_INTEGER): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value >= min && value <= max ? value : undefined;
}

function readArray(value: unknown): unknown[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error(HYSTERIA2_FINALMASK_MESSAGE);
  }
  return value;
}

/** First value for any of the keys, matched case-insensitively. */
function firstParam(entries: Array<[string, string]>): (...keys: string[]) => string | undefined {
  const values = new Map<string, string>();
  for (const [key, value] of entries) {
    const normalized = key.toLowerCase();
    if (!values.has(normalized)) {
      values.set(normalized, value);
    }
  }
  return (...keys) => {
    for (const key of keys) {
      const value = values.get(key);
      if (value !== undefined) {
        return value;
      }
    }
    return undefined;
  };
}

/** A value from the link, shortened for an error message that repeats it. */
function echoed(value: string): string {
  return value.length > 40 ? `${value.slice(0, 40)}…` : value;
}

/** Trimmed text, or "" when it is too long to be a real value. */
function boundedTrim(value: string | undefined): string {
  return value === undefined || value.length > MAX_SCALAR_LENGTH ? "" : value.trim();
}

/** Go's strconv.ParseBool truths, as the official client reads `insecure`, plus yes/on. */
function parseFlag(value: string | undefined): boolean {
  return ["1", "t", "true", "yes", "on"].includes(value?.trim().toLowerCase() ?? "");
}

function decodeComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function decodeName(hash: string, fallback: string): string {
  const raw = hash.replace(/^#/u, "");
  return decodeComponent(raw).trim() || fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stripUndefined<T extends Record<string, unknown>>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined)) as T;
}
