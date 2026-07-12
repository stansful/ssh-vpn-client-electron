import type { ProxyProtocol, ProxySecurity, ProxyTransport } from "../../shared/types.js";

export interface XrayConfigInput {
  rawUri: string;
  socksHost: string;
  socksPort: number;
  httpHost?: string;
  httpPort?: number;
}

interface VmessPayload {
  id?: string;
  aid?: string | number;
  scy?: string;
  add?: string;
  port?: string | number;
  net?: string;
  type?: string;
  host?: string;
  path?: string;
  tls?: string;
  sni?: string;
  alpn?: string;
  ps?: string;
  mode?: string;
  seed?: string;
  headerType?: string;
}

export function buildXrayConfig(input: XrayConfigInput): string {
  const outbound = buildOutbound(input.rawUri);
  // SOCKS/HTTP already supplies the destination and this client has a single
  // outbound. Omitting Xray sniffing avoids redundant HTTP/TLS/QUIC DPI work.
  return JSON.stringify({
    log: { loglevel: "warning" },
    inbounds: [
      {
        tag: "socks-in",
        protocol: "socks",
        listen: input.socksHost,
        port: input.socksPort,
        settings: {
          // The supported desktop interception path is TCP-only. Do not keep
          // an unused UDP association path alive inside Xray.
          udp: false,
          auth: "noauth"
        }
      },
      ...(input.httpHost && input.httpPort
        ? [
            {
              tag: "http-in",
              protocol: "http",
              listen: input.httpHost,
              port: input.httpPort,
              settings: {}
            }
          ]
        : [])
    ],
    outbounds: [outbound]
  });
}

export function buildOutbound(rawUri: string): Record<string, unknown> {
  const protocol = detectProtocol(rawUri);
  if (protocol === "vmess") {
    return buildVmessOutbound(rawUri);
  }
  return buildUriOutbound(rawUri, protocol);
}

function buildUriOutbound(rawUri: string, protocol: "vless" | "trojan"): Record<string, unknown> {
  const url = new URL(rawUri);
  const host = normalizeHost(url.hostname);
  const port = Number(url.port);
  const security = normalizeSecurity(url.searchParams.get("security") ?? (url.searchParams.get("tls") === "1" ? "tls" : "none"));
  const transport = normalizeTransport(url.searchParams.get("type") ?? url.searchParams.get("net") ?? "tcp");
  assertSupported(security, transport);

  const server = protocol === "vless"
    ? {
        address: host,
        port,
        users: [
          {
            id: decodeURIComponent(url.username),
            encryption: url.searchParams.get("encryption") ?? "none",
            flow: url.searchParams.get("flow") ?? undefined
          }
        ]
      }
    : {
        address: host,
        port,
        password: decodeURIComponent(url.username)
      };

  return stripUndefined({
    protocol,
    tag: "proxy",
    settings: {
      vnext: protocol === "vless" ? [server] : undefined,
      servers: protocol === "trojan" ? [server] : undefined
    },
    streamSettings: buildStreamSettings(url, security, transport)
  });
}

function buildVmessOutbound(rawUri: string): Record<string, unknown> {
  const payload = JSON.parse(Buffer.from(normalizeBase64(rawUri.replace(/^vmess:\/\//iu, "").trim()), "base64").toString("utf8")) as VmessPayload;
  const host = normalizeHost(String(payload.add ?? ""));
  const port = Number(payload.port);
  const security = normalizeSecurity(payload.tls || "none");
  const transport = normalizeTransport(payload.net ?? "tcp");
  assertSupported(security, transport);

  return stripUndefined({
    protocol: "vmess",
    tag: "proxy",
    settings: {
      vnext: [
        {
          address: host,
          port,
          users: [
            {
              id: payload.id,
              alterId: Number(payload.aid ?? 0),
              security: payload.scy ?? "auto"
            }
          ]
        }
      ]
    },
    streamSettings: buildStreamSettingsFromParts({
      security,
      transport,
      host: payload.host,
      path: payload.path,
      type: payload.headerType ?? payload.type,
      sni: payload.sni,
      alpn: payload.alpn,
      mode: payload.mode,
      seed: payload.seed
    })
  });
}

function buildStreamSettings(url: URL, security: ProxySecurity, transport: ProxyTransport): Record<string, unknown> {
  return buildStreamSettingsFromParts({
    security,
    transport,
    host: url.searchParams.get("host") ?? undefined,
    path: url.searchParams.get("path") ?? undefined,
    type: url.searchParams.get("headerType") ?? url.searchParams.get("header") ?? undefined,
    serviceName: url.searchParams.get("serviceName") ?? undefined,
    sni: url.searchParams.get("sni") ?? url.searchParams.get("servername") ?? undefined,
    publicKey: url.searchParams.get("pbk") ?? undefined,
    shortId: url.searchParams.get("sid") ?? undefined,
    fingerprint: url.searchParams.get("fp") ?? undefined,
    mode: url.searchParams.get("mode") ?? undefined,
    seed: url.searchParams.get("seed") ?? undefined,
    congestion: url.searchParams.get("congestion") ?? undefined,
    upMbps: url.searchParams.get("upMbps") ?? url.searchParams.get("up") ?? undefined,
    downMbps: url.searchParams.get("downMbps") ?? url.searchParams.get("down") ?? undefined
  });
}

function buildStreamSettingsFromParts(parts: {
  security: ProxySecurity;
  transport: ProxyTransport;
  host?: string;
  path?: string;
  type?: string;
  serviceName?: string;
  sni?: string;
  alpn?: string;
  publicKey?: string;
  shortId?: string;
  fingerprint?: string;
  mode?: string;
  seed?: string;
  congestion?: string;
  upMbps?: string;
  downMbps?: string;
}): Record<string, unknown> {
  return stripUndefined({
    network: xrayNetwork(parts.transport),
    security: parts.security === "none" ? undefined : parts.security,
    tlsSettings: parts.security === "tls" ? stripUndefined({ serverName: parts.sni, alpn: parseCsv(parts.alpn) }) : undefined,
    realitySettings: parts.security === "reality"
      ? stripUndefined({ serverName: parts.sni, publicKey: parts.publicKey, shortId: parts.shortId, fingerprint: parts.fingerprint })
      : undefined,
    wsSettings: parts.transport === "ws" ? stripUndefined({ path: parts.path, headers: parts.host ? { Host: parts.host } : undefined }) : undefined,
    grpcSettings: parts.transport === "grpc" ? stripUndefined({ serviceName: parts.serviceName ?? parts.path }) : undefined,
    tcpSettings: parts.transport === "tcp" && parts.type ? { header: { type: parts.type } } : undefined,
    xhttpSettings: parts.transport === "xhttp" ? stripUndefined({ host: parts.host, path: parts.path, mode: parts.mode }) : undefined,
    httpupgradeSettings: parts.transport === "httpupgrade" ? stripUndefined({ host: parts.host, path: parts.path }) : undefined,
    kcpSettings: parts.transport === "mkcp" ? stripUndefined({ seed: parts.seed, header: parts.type ? { type: parts.type } : undefined }) : undefined,
    httpSettings: parts.transport === "http" ? stripUndefined({ host: parseCsv(parts.host), path: parts.path }) : undefined,
    hysteriaSettings: parts.transport === "hysteria"
      ? stripUndefined({
          congestion: parseBoolean(parts.congestion),
          upMbps: parseNumber(parts.upMbps),
          downMbps: parseNumber(parts.downMbps)
        })
      : undefined
  });
}

function detectProtocol(rawUri: string): ProxyProtocol {
  const protocol = rawUri.match(/^([a-z][a-z0-9+.-]*):\/\//iu)?.[1]?.toLowerCase();
  if (protocol === "vless" || protocol === "vmess" || protocol === "trojan") {
    return protocol;
  }
  throw new Error("Unsupported proxy URI protocol.");
}

function assertSupported(security: ProxySecurity, transport: ProxyTransport): void {
  if (security === "unknown") {
    throw new Error("Unsupported proxy security mode.");
  }
  if (transport === "unknown") {
    throw new Error(`Unsupported proxy transport: ${transport}.`);
  }
}

function normalizeHost(value: string): string {
  return value.trim().replace(/^\[/u, "").replace(/\]$/u, "").toLowerCase();
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
  if (normalized === "tcp" || normalized === "ws" || normalized === "grpc") {
    return normalized;
  }
  if (normalized === "xhttp" || normalized === "http" || normalized === "httpupgrade" || normalized === "http-upgrade" || normalized === "http_upgrade" || normalized === "mkcp" || normalized === "hysteria") {
    return normalized === "http-upgrade" || normalized === "http_upgrade" ? "httpupgrade" : normalized;
  }
  return "unknown";
}

function xrayNetwork(transport: ProxyTransport): string | undefined {
  if (transport === "tcp") {
    return undefined;
  }
  if (transport === "mkcp") {
    return "kcp";
  }
  return transport;
}

function normalizeSecurity(value: string): ProxySecurity {
  const normalized = value.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return "none";
  }
  if (normalized === "tls" || normalized === "reality") {
    return normalized;
  }
  return "unknown";
}

function normalizeBase64(value: string): string {
  const normalized = value.replace(/\s+/gu, "").replace(/-/gu, "+").replace(/_/gu, "/");
  return normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
}

function parseCsv(value: string | undefined): string[] | undefined {
  const items = value?.split(",").map((item) => item.trim()).filter(Boolean);
  return items && items.length > 0 ? items : undefined;
}

function parseBoolean(value: string | undefined): boolean | undefined {
  if (!value) {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (normalized === "true" || normalized === "1" || normalized === "yes") {
    return true;
  }
  if (normalized === "false" || normalized === "0" || normalized === "no") {
    return false;
  }
  return undefined;
}

function parseNumber(value: string | undefined): number | undefined {
  if (!value) {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function stripUndefined<T extends Record<string, unknown>>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined)) as T;
}
