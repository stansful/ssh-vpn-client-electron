import { createHash } from "node:crypto";
import type { ParsedProxyProfile, ProxyProtocol, ProxySecurity, ProxyTransport } from "../../shared/types.js";

const MAX_LINK_LENGTH = 64 * 1024;
const MAX_IMPORT_LINES = 10_000;

interface VmessPayload {
  ps?: string;
  add?: string;
  port?: string | number;
  net?: string;
  tls?: string;
  flow?: string;
}

export interface ProxyImportParseResult {
  profiles: ParsedProxyProfile[];
  errors: string[];
  skipped: number;
}

export function parseProxyShareLinks(text: string): ProxyImportParseResult {
  const lines = text.split(/\r?\n/u);
  const errors: string[] = [];
  const profiles: ParsedProxyProfile[] = [];
  let skipped = 0;

  if (lines.length > MAX_IMPORT_LINES) {
    errors.push(`Import contains ${lines.length} lines; maximum is ${MAX_IMPORT_LINES}. Extra lines were ignored.`);
  }

  for (const [index, rawLine] of lines.slice(0, MAX_IMPORT_LINES).entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      skipped += 1;
      continue;
    }
    if (line.length > MAX_LINK_LENGTH) {
      errors.push(`Line ${index + 1}: proxy link is longer than ${MAX_LINK_LENGTH} bytes.`);
      continue;
    }
    try {
      profiles.push(parseProxyShareLink(line));
    } catch (error) {
      errors.push(`Line ${index + 1}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return { profiles, errors, skipped };
}

export function parseProxyShareLink(rawUri: string): ParsedProxyProfile {
  const protocol = detectProtocol(rawUri);
  if (protocol === "vmess") {
    return parseVmess(rawUri);
  }
  return parseUriProtocol(rawUri, protocol);
}

function detectProtocol(rawUri: string): ProxyProtocol {
  const match = rawUri.match(/^([a-z][a-z0-9+.-]*):\/\//iu);
  const protocol = match?.[1]?.toLowerCase();
  if (protocol === "vless" || protocol === "vmess" || protocol === "trojan") {
    return protocol;
  }
  throw new Error("Only vless://, vmess://, and trojan:// links are supported.");
}

function parseUriProtocol(rawUri: string, protocol: Exclude<ProxyProtocol, "vmess">): ParsedProxyProfile {
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

  const name = decodeName(url.hash, `${protocol}-${host}:${port}`);
  const transport = normalizeTransport(url.searchParams.get("type") ?? url.searchParams.get("net") ?? "tcp");
  const security = normalizeSecurity(url.searchParams.get("security") ?? (url.searchParams.get("tls") === "1" ? "tls" : "none"));
  const flow = (url.searchParams.get("flow") ?? "").trim();
  const normalized = canonicalizeUri(url, protocol);

  return {
    name,
    protocol,
    host,
    port,
    transport,
    security,
    flow,
    rawUri,
    fingerprint: fingerprint(normalized)
  };
}

function parseVmess(rawUri: string): ParsedProxyProfile {
  const encoded = rawUri.replace(/^vmess:\/\//iu, "").trim();
  let payload: VmessPayload;
  try {
    payload = JSON.parse(Buffer.from(normalizeBase64(encoded), "base64").toString("utf8")) as VmessPayload;
  } catch {
    throw new Error("Invalid VMess base64 JSON payload.");
  }

  const host = normalizeHost(String(payload.add ?? ""));
  const port = Number(payload.port);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("VMess payload must contain add and valid port.");
  }

  const protocol = "vmess";
  const name = String(payload.ps ?? `vmess-${host}:${port}`).trim() || `vmess-${host}:${port}`;
  const transport = normalizeTransport(payload.net ?? "tcp");
  const security = normalizeSecurity(payload.tls || "none");
  const flow = String(payload.flow ?? "").trim();
  const normalized = JSON.stringify(sortObject({
    ...payload,
    add: host,
    port,
    net: transport,
    tls: security
  }));

  return {
    name,
    protocol,
    host,
    port,
    transport,
    security,
    flow,
    rawUri,
    fingerprint: fingerprint(`vmess:${normalized}`)
  };
}

function canonicalizeUri(url: URL, protocol: ProxyProtocol): string {
  const params = [...url.searchParams.entries()]
    .map(([key, value]) => [key.toLowerCase(), value] as const)
    .sort(([left], [right]) => left.localeCompare(right));
  return JSON.stringify({
    protocol,
    username: url.username,
    host: normalizeHost(url.hostname),
    port: Number(url.port),
    params,
    hash: decodeName(url.hash, "")
  });
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
  if (normalized === "h2" || normalized === "http2") {
    return "http";
  }
  if (normalized === "tcp" || normalized === "ws" || normalized === "grpc" || normalized === "xhttp" || normalized === "mkcp" || normalized === "http" || normalized === "hysteria") {
    return normalized;
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
  if (normalized === "tls") {
    return "tls";
  }
  if (normalized === "reality") {
    return "reality";
  }
  return "unknown";
}

function normalizeBase64(value: string): string {
  const normalized = value.replace(/\s+/gu, "").replace(/-/gu, "+").replace(/_/gu, "/");
  return normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
}

function sortObject(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)));
}

function fingerprint(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
