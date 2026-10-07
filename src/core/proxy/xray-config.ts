import type { ProxyProtocol, ProxySecurity, ProxyTransport } from "../../shared/types.js";
import {
  HYSTERIA2_DEFAULT_HOP_INTERVAL,
  isHysteria2Scheme,
  parseHysteria2Link,
  parseHysteriaBandwidth,
  type Hysteria2Congestion
} from "./hysteria2-link.js";

export interface XrayConfigInput extends XrayOutboundOptions {
  rawUri: string;
  socksHost: string;
  socksPort: number;
  httpHost?: string;
  httpPort?: number;
}

export interface XrayOutboundOptions {
  /**
   * Version of the Xray runtime that will load the config ("26.3.27"). It
   * picks the config shape where Xray releases differ; when unknown, the shape
   * of the release the app bundles is used.
   */
  xrayVersion?: string;
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
  const outbound = buildOutbound(input.rawUri, { xrayVersion: input.xrayVersion });
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
          // Xray is the only transport that can carry UDP: SSH has no
          // datagram channel. The association path is enabled here so the TUN
          // dataplane can forward QUIC and other UDP through `UDP ASSOCIATE`;
          // the inbound is loopback-only, so an idle association costs nothing.
          udp: true,
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

export function buildOutbound(rawUri: string, options: XrayOutboundOptions = {}): Record<string, unknown> {
  const protocol = detectProtocol(rawUri);
  if (protocol === "vmess") {
    return buildVmessOutbound(rawUri, options);
  }
  if (protocol === "hysteria2") {
    return buildHysteria2Outbound(rawUri, options);
  }
  return buildUriOutbound(rawUri, protocol, options);
}

/**
 * Xray's native Hysteria 2 client. Hysteria is QUIC, so TLS is mandatory and
 * ALPN is always h3. `insecure=1` has no Xray equivalent any more
 * (tlsSettings.allowInsecure was removed and now fails the whole config); a
 * pinSHA256 pin is the only way to accept a self-signed certificate, so the
 * flag itself is left out and the certificate is verified as usual.
 */
function buildHysteria2Outbound(rawUri: string, options: XrayOutboundOptions): Record<string, unknown> {
  const link = parseHysteria2Link(rawUri);
  const hop = link.hopPorts ? { ports: link.hopPorts, interval: link.hopInterval ?? HYSTERIA2_DEFAULT_HOP_INTERVAL } : undefined;
  const hopAsUdpMask = hop !== undefined && usesUdpHopMask(options.xrayVersion);
  const udpMasks = [
    // A udphop mask dials its own sockets, so Xray requires it first.
    ...(hop && hopAsUdpMask
      ? [{ type: "udphop", settings: { mode: "intervallocal,intervalremote", interval: hop.interval, remotePorts: hop.ports } }]
      : []),
    ...(link.obfsPassword !== undefined ? [{ type: "salamander", settings: { password: link.obfsPassword } }] : [])
  ];
  const quicParams = stripUndefined({
    congestion: link.congestion,
    brutalUp: link.brutalUp,
    brutalDown: link.brutalDown,
    // Always with an explicit interval: Xray 26.3 turns a missing one into a
    // duration that overflows and panics its hop timer.
    udpHop: hop && !hopAsUdpMask ? hop : undefined,
    ...link.quic
  });

  return {
    protocol: "hysteria",
    tag: "proxy",
    settings: { version: 2, address: link.host, port: link.port },
    streamSettings: stripUndefined({
      network: "hysteria",
      security: "tls",
      hysteriaSettings: { version: 2, auth: link.auth },
      tlsSettings: stripUndefined({
        // Required: without it Xray's QUIC dialer sends the SNI "hysteria".
        serverName: link.sni,
        alpn: ["h3"],
        pinnedPeerCertSha256: link.pinnedCertSha256.length > 0 ? link.pinnedCertSha256.join(",") : undefined,
        verifyPeerCertByName: link.verifyPeerCertByName,
        echConfigList: link.echConfigList
      }),
      finalmask: udpMasks.length > 0 || Object.keys(quicParams).length > 0
        ? stripUndefined({
            udp: udpMasks.length > 0 ? udpMasks : undefined,
            quicParams: Object.keys(quicParams).length > 0 ? quicParams : undefined
          })
        : undefined
    })
  };
}

/**
 * Xray 26.9.9 moved port hopping from finalmask.quicParams.udpHop (which it
 * now ignores) to a "udphop" UDP mask; 26.3.27, the bundled release, rejects
 * that mask type.
 */
export function usesUdpHopMask(xrayVersion: string | undefined): boolean {
  return isXrayAtLeast(xrayVersion, [26, 9, 9]);
}

/**
 * Xray 26.6.1 folded the header-* / mkcp-original / mkcp-aes128gcm UDP masks
 * into one "mkcp-legacy" mask; 26.3.27, the bundled release, knows only the
 * older names.
 */
export function usesMkcpLegacyMask(xrayVersion: string | undefined): boolean {
  return isXrayAtLeast(xrayVersion, [26, 6, 1]);
}

/** False for an unknown version: the config then takes the bundled release's shape. */
function isXrayAtLeast(xrayVersion: string | undefined, minimum: [number, number, number]): boolean {
  const match = /(\d+)\.(\d+)\.(\d+)/u.exec(xrayVersion ?? "");
  if (!match) {
    return false;
  }
  const version = match.slice(1).map(Number);
  for (const [index, part] of minimum.entries()) {
    if (version[index] !== part) {
      return version[index] > part;
    }
  }
  return true;
}

function buildUriOutbound(rawUri: string, protocol: Exclude<ProxyProtocol, "vmess" | "hysteria2">, options: XrayOutboundOptions): Record<string, unknown> {
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
    streamSettings: buildStreamSettings(url, host, security, transport, options)
  });
}

function buildVmessOutbound(rawUri: string, options: XrayOutboundOptions): Record<string, unknown> {
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
      serverHost: host,
      host: payload.host,
      path: payload.path,
      type: payload.headerType ?? payload.type,
      sni: payload.sni,
      alpn: payload.alpn,
      mode: payload.mode,
      // v2rayN keeps an mKCP seed in "path".
      seed: payload.seed ?? (transport === "mkcp" ? payload.path : undefined),
      xrayVersion: options.xrayVersion
    })
  });
}

function buildStreamSettings(
  url: URL,
  serverHost: string,
  security: ProxySecurity,
  transport: ProxyTransport,
  options: XrayOutboundOptions
): Record<string, unknown> {
  return buildStreamSettingsFromParts({
    security,
    transport,
    serverHost,
    xrayVersion: options.xrayVersion,
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
    mtu: url.searchParams.get("mtu") ?? undefined,
    tti: url.searchParams.get("tti") ?? undefined,
    finalmask: url.searchParams.get("fm") ?? undefined,
    auth: url.searchParams.get("auth") ?? undefined,
    congestion: url.searchParams.get("congestion") ?? undefined,
    upMbps: url.searchParams.get("upMbps") ?? url.searchParams.get("up") ?? undefined,
    downMbps: url.searchParams.get("downMbps") ?? url.searchParams.get("down") ?? undefined
  });
}

function buildStreamSettingsFromParts(parts: {
  security: ProxySecurity;
  transport: ProxyTransport;
  /** The server address; the hysteria transport needs it as the SNI fallback. */
  serverHost: string;
  xrayVersion?: string;
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
  mtu?: string;
  tti?: string;
  /** The link's `fm`: Xray finalmask JSON, as share links from Xray 26 panels carry it. */
  finalmask?: string;
  auth?: string;
  congestion?: string;
  upMbps?: string;
  downMbps?: string;
}): Record<string, unknown> {
  const hysteria = parts.transport === "hysteria";
  const quicParams = hysteria
    ? stripUndefined({
        congestion: parseCongestion(parts.congestion),
        brutalUp: parseHysteriaBandwidth(parts.upMbps),
        brutalDown: parseHysteriaBandwidth(parts.downMbps)
      })
    : {};
  const mkcpMasks = parts.transport === "mkcp" ? buildMkcpMasks(parts) : [];
  return stripUndefined({
    network: xrayNetwork(parts.transport),
    security: parts.security === "none" ? undefined : parts.security,
    tlsSettings: parts.security === "tls"
      ? stripUndefined({
          // Xray's QUIC dialer sends the SNI "hysteria" unless one is set.
          serverName: parts.sni?.trim() || (hysteria ? parts.serverHost : undefined),
          alpn: parseCsv(parts.alpn)
        })
      : undefined,
    realitySettings: parts.security === "reality"
      ? stripUndefined({ serverName: parts.sni, publicKey: parts.publicKey, shortId: parts.shortId, fingerprint: parts.fingerprint })
      : undefined,
    wsSettings: parts.transport === "ws" ? stripUndefined({ path: parts.path, headers: parts.host ? { Host: parts.host } : undefined }) : undefined,
    grpcSettings: parts.transport === "grpc" ? stripUndefined({ serviceName: parts.serviceName ?? parts.path }) : undefined,
    tcpSettings: parts.transport === "tcp" && parts.type ? { header: { type: parts.type } } : undefined,
    xhttpSettings: parts.transport === "xhttp" ? stripUndefined({ host: parts.host, path: parts.path, mode: parts.mode }) : undefined,
    httpupgradeSettings: parts.transport === "httpupgrade" ? stripUndefined({ host: parts.host, path: parts.path }) : undefined,
    kcpSettings: parts.transport === "mkcp"
      ? stripUndefined({ mtu: parseInteger(parts.mtu, 576, 1460), tti: parseInteger(parts.tti, 10, 100) })
      : undefined,
    hysteriaSettings: hysteria ? stripUndefined({ version: 2, auth: parts.auth }) : undefined,
    finalmask: Object.keys(quicParams).length > 0 || mkcpMasks.length > 0
      ? stripUndefined({
          udp: mkcpMasks.length > 0 ? mkcpMasks : undefined,
          quicParams: Object.keys(quicParams).length > 0 ? quicParams : undefined
        })
      : undefined
  });
}

const MKCP_HEADERS = ["dns", "dtls", "srtp", "utp", "wechat", "wireguard"] as const;

/** One layer of mKCP's pre-26 obfuscation: a fake packet header, or the packet cipher. */
type MkcpLayer = { header: (typeof MKCP_HEADERS)[number]; domain?: string } | { seed: string };

/**
 * Xray 26 dropped kcpSettings.header and .seed, and with them the obfuscation
 * every older mKCP server applies by default: a client now has to ask for it
 * with UDP masks. A link from an Xray 26 panel describes its masks in `fm`;
 * an older link only has headerType and seed, which map to the masks that
 * reproduce the old packets: the header first, then AES-128-GCM keyed by the
 * seed, or the default XOR obfuscation when there is none.
 */
function buildMkcpMasks(parts: { type?: string; host?: string; seed?: string; finalmask?: string; xrayVersion?: string }): Array<Record<string, unknown>> {
  const layers = mkcpLayersFromFinalMask(parts.finalmask) ?? legacyMkcpLayers(parts.type, parts.host, parts.seed);
  return layers.map((layer) => (usesMkcpLegacyMask(parts.xrayVersion) ? mkcpLegacyMask(layer) : mkcpSplitMask(layer)));
}

function legacyMkcpLayers(headerType: string | undefined, host: string | undefined, seed: string | undefined): MkcpLayer[] {
  const type = headerType?.trim().toLowerCase() ?? "";
  const header = type === "wechat-video" ? "wechat" : type;
  const layers: MkcpLayer[] = [];
  if (header && header !== "none") {
    if (!(MKCP_HEADERS as readonly string[]).includes(header)) {
      throw new Error(`Unsupported mKCP header type: ${headerType}.`);
    }
    layers.push({ header: header as (typeof MKCP_HEADERS)[number], domain: header === "dns" ? host?.trim() || undefined : undefined });
  }
  layers.push({ seed: seed ?? "" });
  return layers;
}

/** The mKCP masks in an `fm` JSON, in either Xray naming; undefined when it has no UDP masks. */
function mkcpLayersFromFinalMask(value: string | undefined): MkcpLayer[] | undefined {
  if (!value?.trim()) {
    return undefined;
  }
  let json: unknown;
  try {
    json = JSON.parse(value);
  } catch {
    throw new Error("Invalid fm parameter: expected finalmask JSON.");
  }
  const udp = isRecord(json) ? json.udp : undefined;
  if (udp === undefined) {
    return undefined;
  }
  if (!Array.isArray(udp)) {
    throw new Error("Invalid fm parameter: expected finalmask JSON.");
  }
  return udp.map((mask): MkcpLayer => {
    const type = isRecord(mask) && typeof mask.type === "string" ? mask.type.toLowerCase() : "";
    const settings = isRecord(mask) && isRecord(mask.settings) ? mask.settings : {};
    const text = (key: string): string => (typeof settings[key] === "string" ? (settings[key] as string) : "");
    if (type === "mkcp-original") {
      return { seed: "" };
    }
    if (type === "mkcp-aes128gcm") {
      return { seed: text("password") };
    }
    if (type === "mkcp-legacy") {
      const header = text("header").toLowerCase();
      if (!header) {
        return { seed: text("value") };
      }
      if ((MKCP_HEADERS as readonly string[]).includes(header)) {
        return { header: header as (typeof MKCP_HEADERS)[number], domain: header === "dns" ? text("value") || undefined : undefined };
      }
    }
    const header = type.replace(/^header-/u, "");
    if (type.startsWith("header-") && (MKCP_HEADERS as readonly string[]).includes(header)) {
      return { header: header as (typeof MKCP_HEADERS)[number], domain: header === "dns" ? text("domain") || undefined : undefined };
    }
    throw new Error(`Unsupported finalmask type for mKCP: ${type || "?"}.`);
  });
}

/** Xray 26.6.1 and later. */
function mkcpLegacyMask(layer: MkcpLayer): Record<string, unknown> {
  return "seed" in layer
    ? { type: "mkcp-legacy", settings: { header: "", value: layer.seed } }
    : { type: "mkcp-legacy", settings: { header: layer.header, value: layer.domain ?? "" } };
}

/** Xray before 26.6.1, the bundled 26.3.27 included. */
function mkcpSplitMask(layer: MkcpLayer): Record<string, unknown> {
  if ("seed" in layer) {
    return layer.seed ? { type: "mkcp-aes128gcm", settings: { password: layer.seed } } : { type: "mkcp-original", settings: {} };
  }
  return { type: `header-${layer.header}`, settings: layer.domain ? { domain: layer.domain } : {} };
}

function detectProtocol(rawUri: string): ProxyProtocol {
  const protocol = rawUri.match(/^([a-z][a-z0-9+.-]*):\/\//iu)?.[1]?.toLowerCase();
  if (protocol === "vless" || protocol === "vmess" || protocol === "trojan") {
    return protocol;
  }
  if (isHysteria2Scheme(protocol)) {
    return "hysteria2";
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
  // Xray loads such a config but its hysteria dialer refuses every connection.
  if (transport === "hysteria" && security !== "tls") {
    throw new Error("The hysteria transport needs security=tls.");
  }
  // Profiles saved before the parsers flagged it: Xray 26 refuses the whole config.
  if (transport === "http") {
    throw new Error("Xray no longer runs the HTTP/2 transport (type=h2 or http). Ask your provider for an XHTTP link.");
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

function parseInteger(value: string | undefined, min: number, max: number): number | undefined {
  const text = value?.trim() ?? "";
  if (!/^\d{1,5}$/u.test(text)) {
    return undefined;
  }
  const parsed = Number(text);
  return parsed >= min && parsed <= max ? parsed : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseCongestion(value: string | undefined): Hysteria2Congestion | undefined {
  const normalized = value?.trim().toLowerCase();
  // force-brutal also needs an upload rate, which a share link rarely carries.
  return normalized === "reno" || normalized === "bbr" || normalized === "brutal" ? normalized : undefined;
}

function stripUndefined<T extends Record<string, unknown>>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined)) as T;
}
