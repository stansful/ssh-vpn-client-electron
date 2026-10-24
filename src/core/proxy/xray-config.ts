import type { ProxyProtocol, ProxySecurity, ProxyTransport, RoutingRule } from "../../shared/types.js";
import { normalizeRuleValue, validateRoutingRuleValue } from "../../shared/validation.js";
import {
  formatCidrRange,
  isLocalDestinationHost,
  LOCAL_DESTINATION_CIDRS,
  overlapsLocalDestinationRange,
  parseCidrRange
} from "../routing/ip-address.js";
import {
  HYSTERIA2_DEFAULT_HOP_INTERVAL,
  isHysteria2Scheme,
  parseHysteria2Link,
  parseHysteriaBandwidth,
  type Hysteria2Congestion
} from "./hysteria2-link.js";
import { shareLinkHostToAscii, uriSecurityText, vmessSecurityText, vmessText } from "./share-link-fields.js";

export interface XrayConfigInput extends XrayOutboundOptions {
  rawUri: string;
  socksHost: string;
  socksPort: number;
  httpHost?: string;
  httpPort?: number;
  /**
   * Keeps the local network out of the tunnel for what reaches the HTTP
   * inbound - the one the Windows proxy points at, whose bypass list cannot
   * name a private address - unless a user rule names it (`localRuleOverrides`).
   * Only that inbound: the TUN adapter and the routing listener come in
   * through the SOCKS one having applied the routing order already, and an
   * app pointed at Xray by hand - all there is on macOS and Linux - asked
   * for the tunnel.
   */
  localNetworkDirect?: boolean;
  /** The user's rules for the local network, which win over its direct rule; see {@link xrayLocalRuleOverrides}. */
  localRuleOverrides?: XrayLocalRuleOverrides;
}

/**
 * The enabled user rules that name part of the local network, in Xray's
 * syntax. Xray's routing keeps that network direct, but an explicit rule wins
 * over it on every path (step 2 of the shared order, ahead of the local
 * network), so these go to the tunnel first.
 */
export interface XrayLocalRuleOverrides {
  /** IP rules that overlap a local range, as `network/prefix`. */
  ip: string[];
  /** Domain rules for `.local` names: `domain:` for a plain rule, a suffix `regexp:` for `*.`. */
  domain: string[];
}

export interface XrayOutboundOptions {
  /**
   * Version of the Xray runtime that will load the config ("26.3.27"). It
   * picks the config shape where Xray releases differ; when unknown, the shape
   * of the release the app bundles is used.
   */
  xrayVersion?: string;
}

/** Panels write these as strings, numbers or booleans; every field is read through `vmessText`. */
interface VmessPayload {
  id?: unknown;
  aid?: unknown;
  scy?: unknown;
  add?: unknown;
  port?: unknown;
  net?: unknown;
  type?: unknown;
  host?: unknown;
  path?: unknown;
  tls?: unknown;
  sni?: unknown;
  alpn?: unknown;
  fp?: unknown;
  ps?: unknown;
  mode?: unknown;
  seed?: unknown;
  headerType?: unknown;
}

/**
 * Local and private destinations the Windows proxy hands to the HTTP inbound
 * leave through a plain direct outbound, so LAN and intranet traffic (proxy-all
 * on the static proxy, whose bypass list names no address range) is not
 * carried to the remote server. The list is written out rather than taken
 * from geoip, whose data files are not packaged. With the default AsIs
 * strategy the IP rule matches literal addresses only, which is the rule
 * every other routing path applies. The SOCKS inbound has no such rule: what
 * the TUN adapter or the routing listener sends there was chosen by the
 * routing order already - a private address a domain rule picked arrives as
 * a bare address, and must stay in the tunnel - and an app pointed at it by
 * hand asked for the tunnel.
 *
 * The user's own rules for that network come first (see
 * {@link xrayLocalRuleOverrides}): what reaches Xray in split routing was
 * already chosen upstream by the PAC, which lets an explicit rule win over
 * the local network, and must not be sent direct here. Xray reads this only
 * at start, so the service restarts it when that set of rules changes.
 *
 * An IP rule also selects a single-label or `.local` name by the address it
 * resolves to, as the PAC and the SSH listener judge it. Xray then resolves
 * such names, and only them (IPOnDemand, see buildRoutingRules): every other
 * name is sent to the tunnel by a name rule ahead of any IP rule, so its
 * lookup never goes to the local resolver.
 */
const PROXY_OUTBOUND_TAG = "proxy";
const DIRECT_OUTBOUND_TAG = "direct";
const HTTP_INBOUND_TAG = "http-in";
/**
 * Every name that is neither single-label nor under `.local`: its last label
 * is anything but "local". RE2 has no lookahead, so the label is spelled out
 * as "not five letters long, or different from `local` at some letter".
 */
const NOT_LOCAL_NAME_PATTERN =
  "regexp:(?i)\\.(?:[^.]{1,4}|[^.]{6,}|[^l.][^.]{4}|l[^o.][^.]{3}|lo[^c.][^.]{2}|loc[^a.][^.]|loca[^l.])$";
const LOCAL_DESTINATION_ROUTING_RULES = [
  { type: "field", ip: [...LOCAL_DESTINATION_CIDRS], outboundTag: DIRECT_OUTBOUND_TAG },
  // Names without a dot (localhost, intranet hosts) and mDNS .local names.
  { type: "field", domain: ["regexp:^[^.]+$", "domain:local"], outboundTag: DIRECT_OUTBOUND_TAG }
];

/**
 * The enabled, valid user rules that Xray's direct rule for the local network
 * would otherwise override: IP rules overlapping a local range - `10.0.0.0/8`,
 * or `0.0.0.0/0` - and domain rules for `.local` names. A domain rule always
 * has a dot, so no single-label or `localhost` rule exists to carry over.
 * Sorted and deduplicated, so equal rule sets give equal answers.
 */
export function xrayLocalRuleOverrides(rules: readonly RoutingRule[]): XrayLocalRuleOverrides {
  const ip = new Set<string>();
  const domain = new Set<string>();
  for (const rule of rules) {
    if (!rule.enabled || !validateRoutingRuleValue(rule.type, rule.value).ok) {
      continue;
    }
    const value = normalizeRuleValue(rule.type, rule.value);
    if (rule.type === "ip") {
      const range = parseCidrRange(value);
      if (range && overlapsLocalDestinationRange(value)) {
        ip.add(formatCidrRange(range));
      }
    } else if (rule.type === "domain") {
      const wildcard = value.startsWith("*.");
      const name = wildcard ? value.slice(2) : value;
      if (isLocalDestinationHost(name)) {
        // Labels are letters, digits and hyphens, so the dots are all that needs escaping.
        domain.add(wildcard ? `regexp:\\.${name.replaceAll(".", "\\.")}$` : `domain:${name}`);
      }
    }
  }
  return { ip: [...ip].sort(), domain: [...domain].sort() };
}

/**
 * The HTTP inbound's rules. With IP rules for the local network, Xray
 * resolves the names those rules may select (domainStrategy IPOnDemand, which
 * looks a name up only when it reaches an IP rule), and the order keeps every
 * other name from reaching one: the user's domain rules for local names come
 * first, then every name that is not single-label or `.local` goes to the
 * tunnel by name, as it does without these rules. Only then come the IP
 * rules, for addresses and for the local names left.
 */
function buildRoutingRules(input: XrayConfigInput): Array<Record<string, unknown>> {
  if (!input.localNetworkDirect || !input.httpHost || !input.httpPort) {
    return [];
  }
  const overrides = input.localRuleOverrides;
  return [
    ...(overrides && overrides.domain.length > 0 ? [{ type: "field", domain: overrides.domain, outboundTag: PROXY_OUTBOUND_TAG }] : []),
    ...(resolvesLocalNames(input)
      ? [
          { type: "field", domain: [NOT_LOCAL_NAME_PATTERN], outboundTag: PROXY_OUTBOUND_TAG },
          { type: "field", ip: overrides?.ip, outboundTag: PROXY_OUTBOUND_TAG }
        ]
      : []),
    ...LOCAL_DESTINATION_ROUTING_RULES
  ].map((rule) => ({ ...rule, inboundTag: [HTTP_INBOUND_TAG] }));
}

/** Whether the HTTP inbound has IP rules for the local network, so Xray resolves local names (see buildRoutingRules). */
function resolvesLocalNames(input: XrayConfigInput): boolean {
  return Boolean(input.localNetworkDirect && input.httpHost && input.httpPort && input.localRuleOverrides && input.localRuleOverrides.ip.length > 0);
}

export function buildXrayConfig(input: XrayConfigInput): string {
  const outbound = buildOutbound(input.rawUri, { xrayVersion: input.xrayVersion });
  // SOCKS/HTTP already supplies the destination, so Xray sniffing is omitted:
  // it would only add HTTP/TLS/QUIC DPI work. The tunnel outbound stays first,
  // which makes it the default for everything the routing rules do not match.
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
              tag: HTTP_INBOUND_TAG,
              protocol: "http",
              listen: input.httpHost,
              port: input.httpPort,
              settings: {}
            }
          ]
        : [])
    ],
    outbounds: [outbound, { tag: DIRECT_OUTBOUND_TAG, protocol: "freedom" }],
    routing: {
      domainStrategy: resolvesLocalNames(input) ? "IPOnDemand" : "AsIs",
      rules: buildRoutingRules(input)
    }
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
    tag: PROXY_OUTBOUND_TAG,
    settings: { version: 2, address: link.host, port: link.port },
    streamSettings: stripUndefined({
      network: "hysteria",
      security: "tls",
      hysteriaSettings: { version: 2, auth: link.auth },
      tlsSettings: stripUndefined({
        // Required: without it Xray's QUIC dialer sends the SNI "hysteria".
        serverName: asciiServerName(link.sni),
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
  const host = shareLinkHostToAscii(url.hostname);
  if (!host) {
    throw new Error(`${protocol.toUpperCase()} URI must contain host and valid port.`);
  }
  const port = Number(url.port);
  const security = normalizeSecurity(uriSecurityText(protocol, url.searchParams));
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
    tag: PROXY_OUTBOUND_TAG,
    settings: {
      vnext: protocol === "vless" ? [server] : undefined,
      servers: protocol === "trojan" ? [server] : undefined
    },
    streamSettings: buildStreamSettings(url, host, security, transport, options)
  });
}

function buildVmessOutbound(rawUri: string, options: XrayOutboundOptions): Record<string, unknown> {
  const parsed = JSON.parse(Buffer.from(normalizeBase64(rawUri.replace(/^vmess:\/\//iu, "").trim()), "base64").toString("utf8")) as unknown;
  const payload: VmessPayload = isRecord(parsed) ? parsed : {};
  const host = shareLinkHostToAscii(vmessText(payload.add) ?? "");
  if (!host) {
    throw new Error("VMess payload must contain add and valid port.");
  }
  const port = Number(payload.port);
  const security = normalizeSecurity(vmessSecurityText(payload.tls));
  const transport = normalizeTransport(vmessText(payload.net) ?? "tcp");
  assertSupported(security, transport);
  const path = vmessText(payload.path);

  return stripUndefined({
    protocol: "vmess",
    tag: PROXY_OUTBOUND_TAG,
    settings: {
      vnext: [
        {
          address: host,
          port,
          users: [
            {
              id: vmessText(payload.id),
              alterId: Number(payload.aid ?? 0),
              security: vmessText(payload.scy) ?? "auto"
            }
          ]
        }
      ]
    },
    streamSettings: buildStreamSettingsFromParts({
      security,
      transport,
      serverHost: host,
      host: vmessText(payload.host),
      path,
      type: vmessText(payload.headerType) ?? vmessText(payload.type),
      sni: vmessText(payload.sni),
      alpn: vmessText(payload.alpn),
      fingerprint: vmessText(payload.fp),
      mode: vmessText(payload.mode),
      // v2rayN keeps an mKCP seed in "path".
      seed: vmessText(payload.seed) ?? (transport === "mkcp" ? path : undefined),
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
    alpn: url.searchParams.get("alpn") ?? undefined,
    publicKey: url.searchParams.get("pbk") ?? undefined,
    shortId: url.searchParams.get("sid") ?? undefined,
    spiderX: url.searchParams.get("spx") ?? undefined,
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

/**
 * The TLS server name as Xray must send it. A link may carry an
 * internationalised `sni` (`sni=пример.рф`) as written; Go's TLS sends and
 * verifies it as given, so it would match neither the certificate, which
 * names the punycode form, nor the server's SNI routing. Punycode, as the
 * dial address already is (shareLinkHostToAscii); an ASCII name is passed
 * on as it is, and one that is not a usable host name too, for Xray to judge.
 * The ws, httpupgrade and xhttp `host` need no such care: Go's HTTP stack
 * converts the Host header itself.
 */
function asciiServerName(value: string | undefined): string | undefined {
  const name = value?.trim();
  if (!name) {
    return undefined;
  }
  if (!/[\u{80}-\u{10ffff}]/u.test(name)) {
    return name;
  }
  return shareLinkHostToAscii(name) ?? name;
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
  /** REALITY `spx`: the path the client's spider starts from. */
  spiderX?: string;
  /** The uTLS ClientHello to imitate (`fp`), for TLS as well as REALITY. */
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
  const fingerprint = parts.fingerprint?.trim() || undefined;
  // v2rayN writes the gRPC mode as `mode` in links and as `type` in VMess JSON.
  const grpcMultiMode = [parts.mode, parts.type].some((value) => value?.trim().toLowerCase() === "multi");
  return stripUndefined({
    network: xrayNetwork(parts.transport),
    security: parts.security === "none" ? undefined : parts.security,
    tlsSettings: parts.security === "tls"
      ? stripUndefined({
          // Xray's QUIC dialer sends the SNI "hysteria" unless one is set.
          serverName: asciiServerName(parts.sni) || (hysteria ? parts.serverHost : undefined),
          alpn: parseCsv(parts.alpn),
          // Without it Xray sends Go's own ClientHello, which DPI singles out.
          // uTLS shapes a TCP handshake only, so QUIC transports go without.
          fingerprint: hysteria || parts.transport === "mkcp" ? undefined : xrayTlsFingerprint(fingerprint)
        })
      : undefined,
    realitySettings: parts.security === "reality"
      ? stripUndefined({
          serverName: asciiServerName(parts.sni),
          publicKey: parts.publicKey,
          shortId: parts.shortId,
          spiderX: parts.spiderX || undefined,
          fingerprint
        })
      : undefined,
    wsSettings: parts.transport === "ws" ? stripUndefined({ path: parts.path, headers: parts.host ? { Host: parts.host } : undefined }) : undefined,
    grpcSettings: parts.transport === "grpc"
      ? stripUndefined({ serviceName: parts.serviceName ?? parts.path, multiMode: grpcMultiMode || undefined })
      : undefined,
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

/**
 * Every `fingerprint` the bundled Xray (26.3.27) accepts, compared without
 * case: its presets, and the uTLS ids it maps by name. Anything else - a
 * made-up `hello…` name, `hellocustom`, an id from a newer uTLS such as
 * `hellochrome_133`, or `randomizedalpn` without its `hello` - makes it refuse
 * the whole config. Checked against the binary with `xray run -test`.
 */
const XRAY_TLS_FINGERPRINTS = new Set([
  "chrome",
  "firefox",
  "safari",
  "ios",
  "android",
  "edge",
  "360",
  "qq",
  "random",
  "randomized",
  "randomizednoalpn",
  "unsafe",
  "hellogolang",
  "hellorandomized",
  "hellorandomizedalpn",
  "hellorandomizednoalpn",
  "hellofirefox_auto",
  "hellofirefox_55",
  "hellofirefox_56",
  "hellofirefox_63",
  "hellofirefox_65",
  "hellofirefox_99",
  "hellofirefox_102",
  "hellofirefox_105",
  "hellofirefox_120",
  "hellochrome_auto",
  "hellochrome_58",
  "hellochrome_62",
  "hellochrome_70",
  "hellochrome_72",
  "hellochrome_83",
  "hellochrome_87",
  "hellochrome_96",
  "hellochrome_100",
  "hellochrome_102",
  "hellochrome_106_shuffle",
  "hellochrome_120",
  "hellochrome_131",
  "hellochrome_100_psk",
  "hellochrome_112_psk_shuf",
  "hellochrome_114_padding_psk_shuf",
  "hellochrome_115_pq",
  "hellochrome_115_pq_psk",
  "hellochrome_120_pq",
  "helloios_auto",
  "helloios_11_1",
  "helloios_12_1",
  "helloios_13",
  "helloios_14",
  "helloandroid_11_okhttp",
  "helloedge_auto",
  "helloedge_85",
  "helloedge_106",
  "hellosafari_auto",
  "hellosafari_16_0",
  "hello360_auto",
  "hello360_7_5",
  "hello360_11_0",
  "helloqq_auto",
  "helloqq_11_1"
]);

/**
 * A link's `fp` for TLS, when Xray knows it. Links made for other clients
 * carry values Xray refuses - mihomo's "none", Go's "golang" - and with one of
 * them Xray rejects the whole config, so a profile that connected while `fp`
 * was ignored on TLS would stop at Connect. Such a value is left out, as it
 * always was; REALITY, which needs a fingerprint, keeps the link's.
 */
function xrayTlsFingerprint(value: string | undefined): string | undefined {
  const name = value?.trim().toLowerCase();
  if (!name) {
    return undefined;
  }
  return XRAY_TLS_FINGERPRINTS.has(name) ? value?.trim() : undefined;
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

/** The share-link parser's reading, so a link it saved as "none" also runs as none. */
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
