import { proxyProtocolLabel } from "../../shared/proxy-protocols.js";
import type { DesktopPlatform, ProxyProfile, ProxyProtocol, RuntimeArch, SshConfig } from "../../shared/types.js";

const pad = (value: number): string => String(value).padStart(2, "0");

function toDate(value: string | number | Date): Date | undefined {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

/** Local wall-clock time with seconds, e.g. "12:04:18". */
export function formatClock(value: string | number | Date): string {
  const date = toDate(value);
  return date ? `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}` : "";
}

/** Local time without seconds, e.g. "12:04". */
export function formatTime(value: string | number | Date): string {
  const date = toDate(value);
  return date ? `${pad(date.getHours())}:${pad(date.getMinutes())}` : "";
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function sameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

/** Day label: "today", "yesterday", "6 Oct" or "6 Oct 2025". */
export function formatDay(value: string | number | Date, now: Date = new Date()): string {
  const date = toDate(value);
  if (!date) {
    return "";
  }
  if (sameDay(date, now)) {
    return "today";
  }
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (sameDay(date, yesterday)) {
    return "yesterday";
  }
  const base = `${date.getDate()} ${MONTHS[date.getMonth()]}`;
  return date.getFullYear() === now.getFullYear() ? base : `${base} ${date.getFullYear()}`;
}

/** "today at 12:04", "yesterday at 09:10", "6 Oct at 12:04". */
export function formatWhen(value: string | number | Date, now: Date = new Date()): string {
  const day = formatDay(value, now);
  return day ? `${day} at ${formatTime(value)}` : "";
}

/** "just now", "5 min ago", "3 h ago", then falls back to formatWhen. */
export function formatRelative(value: string | number | Date, now: Date = new Date()): string {
  const date = toDate(value);
  if (!date) {
    return "";
  }
  const seconds = Math.round((now.getTime() - date.getTime()) / 1000);
  if (seconds < 45 && seconds > -45) {
    return "just now";
  }
  if (seconds > 0 && seconds < 3600) {
    return `${Math.round(seconds / 60)} min ago`;
  }
  if (seconds > 0 && seconds < 6 * 3600 && sameDay(date, now)) {
    return `${Math.round(seconds / 3600)} h ago`;
  }
  return formatWhen(date, now);
}

/** Decimal byte sizes as people read them in file managers: "92 MB", "1.4 GB". */
export function formatBytes(bytes: number | undefined): string {
  if (bytes === undefined || !Number.isFinite(bytes) || bytes < 0) {
    return "";
  }
  if (bytes < 1000) {
    return `${Math.round(bytes)} B`;
  }
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1000;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const rounded = value >= 100 || Number.isInteger(Number(value.toFixed(1))) ? Math.round(value).toString() : value.toFixed(1);
  return `${rounded} ${units[unit]}`;
}

/** Thousands separators: 1982 → "1,982". */
export function formatCount(value: number): string {
  return Math.round(value).toLocaleString("en-US");
}

/** "1 domain", "9 domains", "1,982 domains". */
export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${formatCount(count)} ${count === 1 ? singular : pluralForm}`;
}

/** "184 ms", or "1.2 s" for slow answers. */
export function formatLatency(ms: number | undefined): string {
  if (ms === undefined || !Number.isFinite(ms)) {
    return "";
  }
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;
}

/** Elapsed time for "Connected for 2 h 14 min". */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) {
    return "";
  }
  const totalMinutes = Math.floor(ms / 60000);
  if (totalMinutes < 1) {
    return `${Math.max(0, Math.floor(ms / 1000))} s`;
  }
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours === 0) {
    return `${minutes} min`;
  }
  const days = Math.floor(hours / 24);
  if (days > 0) {
    return `${days} d ${hours % 24} h`;
  }
  return minutes === 0 ? `${hours} h` : `${hours} h ${minutes} min`;
}

/**
 * Two-letter avatar text: first letters of the first two words, or the first
 * two letters of a single word ("Frankfurt-01" → "FR", "Lab Raspberry" → "LR").
 */
export function initials(name: string): string {
  const words = name.trim().split(/\s+/u).filter(Boolean);
  if (words.length === 0) {
    return "?";
  }
  if (words.length > 1) {
    return `${firstLetter(words[0])}${firstLetter(words[1])}`.toUpperCase();
  }
  const letters = Array.from(words[0].replace(/[^\p{L}\p{N}]/gu, ""));
  return (letters.slice(0, 2).join("") || words[0].slice(0, 2)).toUpperCase();
}

function firstLetter(word: string): string {
  return Array.from(word.replace(/[^\p{L}\p{N}]/gu, ""))[0] ?? word.charAt(0);
}

/** host:port with IPv6 literals in brackets: "[2001:db8::1]:443". */
export function formatHostPort(host: string, port: number | string): string {
  const bare = host.replace(/^\[|\]$/gu, "");
  return bare.includes(":") ? `[${bare}]:${port}` : `${bare}:${port}`;
}

/** "root@203.0.113.10:22". */
export function formatSshTarget(config: Pick<SshConfig, "username" | "host" | "port">): string {
  const target = formatHostPort(config.host, config.port);
  return config.username ? `${config.username}@${target}` : target;
}

/** "VLESS", "VMess", "Trojan", "Hysteria 2": the names the tray and the service use too. */
export const protocolLabel: (protocol: ProxyProtocol) => string = proxyProtocolLabel;

/** Extra words search should find a protocol by: "hysteria2 hy2" for Hysteria 2 (its label reads "Hysteria 2"). */
export function protocolKeywords(protocol: ProxyProtocol): string {
  return protocol === "hysteria2" ? "hysteria2 hy2" : protocol;
}

/**
 * Transport tag as people read it, with "?" when the app could not recognise
 * it. Hysteria 2 always runs over QUIC, so it reads "quic" (the stored
 * transport is "hysteria"); a VLESS link with type=hysteria keeps "hysteria".
 */
export function profileTransportLabel(profile: Pick<ProxyProfile, "protocol" | "transport">): string {
  if (profile.protocol === "hysteria2" && profile.transport === "hysteria") {
    return "quic";
  }
  return profile.transport === "unknown" ? "?" : profile.transport;
}

/** "185.244.30.9:443", or every hop port for Hysteria 2 port hopping: "example.com:443,20000-30000". */
export function formatProfileAddress(profile: Pick<ProxyProfile, "host" | "port" | "hopPorts">): string {
  return formatHostPort(profile.host, profile.hopPorts || profile.port);
}

/** "tcp · reality" or "quic · tls", with "?" for parts the app could not recognise. */
export function formatTransportSecurity(profile: Pick<ProxyProfile, "protocol" | "transport" | "security">): string {
  const security = profile.security === "unknown" ? "?" : profile.security;
  return `${profileTransportLabel(profile)} · ${security}`;
}

/** "VLESS · 185.244.30.9:443 · tcp · reality", "Hysteria 2 · example.com:443,20000-30000 · quic · tls". */
export function formatProfileSummary(profile: Pick<ProxyProfile, "protocol" | "host" | "port" | "hopPorts" | "transport" | "security">): string {
  return `${protocolLabel(profile.protocol)} · ${formatProfileAddress(profile)} · ${formatTransportSecurity(profile)}`;
}

const PLATFORM_LABELS: Record<DesktopPlatform, string> = {
  windows: "Windows",
  macos: "macOS",
  linux: "Linux",
  unknown: "this system"
};

export function platformLabel(platform: DesktopPlatform): string {
  return PLATFORM_LABELS[platform] ?? platform;
}

/** "Windows x64". */
export function platformArchLabel(platform: DesktopPlatform, arch: RuntimeArch): string {
  return arch === "unknown" ? platformLabel(platform) : `${platformLabel(platform)} ${arch}`;
}

/** Shortens long fingerprints or IDs for display: "sha256:4f1c9e…a92e". */
export function shortenMiddle(value: string, head = 13, tail = 4): string {
  return value.length <= head + tail + 1 ? value : `${value.slice(0, head)}…${value.slice(-tail)}`;
}
