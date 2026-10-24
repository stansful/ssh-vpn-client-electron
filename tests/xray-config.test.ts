import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildOutbound,
  buildXrayConfig,
  usesMkcpLegacyMask,
  usesUdpHopMask,
  xrayLocalRuleOverrides,
  type XrayLocalRuleOverrides
} from "../src/core/proxy/xray-config.js";
import { ipMatchesCidr, parseCidrRange, parseIpAddressUnmapped } from "../src/core/routing/ip-address.js";
import type { RoutingRule } from "../src/shared/types.js";

const PIN = "ba88452f1b0c1a3c4d7e6f5a49382716ba88452f1b0c1a3c4d7e6f5a49382716";

describe("xray config builder", () => {
  it("builds a local SOCKS inbound and VLESS outbound", () => {
    const config = JSON.parse(
      buildXrayConfig({
        rawUri: "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&security=tls&path=%2Fws#demo",
        socksHost: "127.0.0.1",
        socksPort: 19080,
        httpHost: "127.0.0.1",
        httpPort: 19081
      })
    ) as {
      inbounds: Array<{ protocol: string; port: number; settings?: { udp?: boolean }; sniffing?: unknown }>;
      outbounds: Array<{ protocol: string; streamSettings?: { network?: string } }>;
    };

    expect(config.inbounds[0]).toMatchObject({ protocol: "socks", port: 19080 });
    expect(config.inbounds[1]).toMatchObject({ protocol: "http", port: 19081 });
    // Xray is the only transport with a datagram path, so its SOCKS inbound
    // has to accept UDP ASSOCIATE for the TUN dataplane to forward QUIC.
    expect(config.inbounds[0]?.settings?.udp).toBe(true);
    // PAC/SOCKS already supplies the destination and this client has a single
    // outbound, so protocol sniffing would only add per-connection DPI work.
    expect(config.inbounds.every((inbound) => inbound.sniffing === undefined)).toBe(true);
    expect(config.outbounds[0]).toMatchObject({ protocol: "vless" });
    expect(config.outbounds[0]?.streamSettings?.network).toBe("ws");
  });

  it("builds VMess and Trojan outbounds", () => {
    const vmess = Buffer.from(
      JSON.stringify({
        ps: "vmess-demo",
        add: "vmess.example.com",
        port: 443,
        id: "22222222-2222-4222-8222-222222222222",
        aid: 0,
        net: "grpc",
        tls: "tls"
      }),
      "utf8"
    ).toString("base64");

    expect(buildOutbound(`vmess://${vmess}`)).toMatchObject({ protocol: "vmess" });
    expect(buildOutbound("trojan://secret@trojan.example.com:443?security=tls#demo")).toMatchObject({ protocol: "trojan" });
  });

  it("builds XHTTP stream settings", () => {
    const outbound = buildOutbound(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fx&mode=packet-up#demo"
    ) as { streamSettings?: { network?: string; xhttpSettings?: { host?: string; path?: string; mode?: string } } };

    expect(outbound.streamSettings).toMatchObject({
      network: "xhttp",
      xhttpSettings: {
        host: "cdn.example.com",
        path: "/x",
        mode: "packet-up"
      }
    });
  });

  it("builds additional Xray transport settings", () => {
    expect(buildOutbound(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=httpupgrade&security=tls&host=cdn.example.com&path=%2Fup#demo"
    )).toMatchObject({
      streamSettings: {
        network: "httpupgrade",
        httpupgradeSettings: { host: "cdn.example.com", path: "/up" }
      }
    });

    expect(buildOutbound(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=kcp&security=none&headerType=wechat-video&seed=demo&mtu=1200&tti=30#demo"
    )).toEqual({
      protocol: "vless",
      tag: "proxy",
      settings: { vnext: [{ address: "example.com", port: 443, users: [{ id: "11111111-1111-4111-8111-111111111111", encryption: "none" }] }] },
      streamSettings: {
        network: "kcp",
        kcpSettings: { mtu: 1200, tti: 30 },
        // Xray 26 refuses kcpSettings.header/seed; these masks write the same packets.
        finalmask: {
          udp: [
            { type: "header-wechat", settings: {} },
            { type: "mkcp-aes128gcm", settings: { password: "demo" } }
          ]
        }
      }
    });
  });

  it("reproduces pre-26 mKCP obfuscation with UDP masks, in the shape the Xray version reads", () => {
    const kcp = (query: string, xrayVersion?: string) =>
      (buildOutbound(`vless://11111111-1111-4111-8111-111111111111@example.com:443?type=kcp&${query}#demo`, { xrayVersion }) as {
        streamSettings: { finalmask?: { udp?: unknown[] } };
      }).streamSettings.finalmask?.udp;

    // Every older mKCP server applies the XOR obfuscation when there is no seed.
    expect(kcp("security=none")).toEqual([{ type: "mkcp-original", settings: {} }]);
    expect(kcp("headerType=none&seed=s")).toEqual([{ type: "mkcp-aes128gcm", settings: { password: "s" } }]);
    expect(kcp("headerType=dns&host=a.example.com")).toEqual([
      { type: "header-dns", settings: { domain: "a.example.com" } },
      { type: "mkcp-original", settings: {} }
    ]);

    // Xray 26.6.1 folded these masks into mkcp-legacy.
    expect(kcp("headerType=srtp&seed=s", "26.6.1")).toEqual([
      { type: "mkcp-legacy", settings: { header: "srtp", value: "" } },
      { type: "mkcp-legacy", settings: { header: "", value: "s" } }
    ]);
    expect(kcp("headerType=dns&host=a.example.com", "26.9.30")).toEqual([
      { type: "mkcp-legacy", settings: { header: "dns", value: "a.example.com" } },
      { type: "mkcp-legacy", settings: { header: "", value: "" } }
    ]);
    expect(usesMkcpLegacyMask("26.5.9")).toBe(false);
    expect(usesMkcpLegacyMask("Xray 26.6.1 (Xray, Penetrates Everything.)")).toBe(true);

    expect(() => kcp("headerType=video")).toThrow("Unsupported mKCP header type: video.");
  });

  it("takes an Xray 26 panel's mKCP masks from fm, in either naming", () => {
    const fm = (udp: unknown) => `fm=${encodeURIComponent(JSON.stringify({ udp }))}`;
    const kcp = (query: string, xrayVersion?: string) =>
      (buildOutbound(`vless://11111111-1111-4111-8111-111111111111@example.com:443?type=kcp&headerType=utp&seed=ignored&${query}#demo`, { xrayVersion }) as {
        streamSettings: { finalmask?: { udp?: unknown[] } };
      }).streamSettings.finalmask?.udp;
    const newer = fm([{ type: "mkcp-legacy", settings: { header: "wireguard" } }, { type: "mkcp-legacy", settings: { value: "pw" } }]);
    const older = fm([{ type: "header-wireguard" }, { type: "mkcp-aes128gcm", settings: { password: "pw" } }]);

    expect(kcp(newer)).toEqual([{ type: "header-wireguard", settings: {} }, { type: "mkcp-aes128gcm", settings: { password: "pw" } }]);
    expect(kcp(older, "26.9.30")).toEqual([
      { type: "mkcp-legacy", settings: { header: "wireguard", value: "" } },
      { type: "mkcp-legacy", settings: { header: "", value: "pw" } }
    ]);
    // A plain mKCP server from Xray 26 shares an fm without masks.
    expect(kcp(fm([]))).toBeUndefined();
    expect(() => kcp(fm([{ type: "noise" }]))).toThrow("Unsupported finalmask type for mKCP: noise.");
  });

  it("reads a VMess mKCP seed from path, as v2rayN writes it", () => {
    const vmess = Buffer.from(JSON.stringify({ add: "vmess.example.com", port: 443, id: "22222222-2222-4222-8222-222222222222", net: "kcp", type: "dtls", path: "seed" })).toString("base64");

    expect(buildOutbound(`vmess://${vmess}`)).toMatchObject({
      streamSettings: {
        network: "kcp",
        finalmask: { udp: [{ type: "header-dtls", settings: {} }, { type: "mkcp-aes128gcm", settings: { password: "seed" } }] }
      }
    });
  });

  it("refuses the HTTP/2 transport, which Xray 26 removed", () => {
    expect(() => buildOutbound("vless://11111111-1111-4111-8111-111111111111@example.com:443?type=h2&security=tls&path=%2Fh2#demo")).toThrow(
      "Xray no longer runs the HTTP/2 transport (type=h2 or http). Ask your provider for an XHTTP link."
    );
  });

  it("builds a Hysteria 2 outbound with TLS over QUIC and an explicit SNI", () => {
    const outbound = buildOutbound("hy2://letmein@example.com:8443/?insecure=1#demo");

    expect(outbound).toEqual({
      protocol: "hysteria",
      tag: "proxy",
      settings: { version: 2, address: "example.com", port: 8443 },
      streamSettings: {
        network: "hysteria",
        security: "tls",
        hysteriaSettings: { version: 2, auth: "letmein" },
        // Without serverName Xray's QUIC dialer would send the SNI "hysteria".
        tlsSettings: { serverName: "example.com", alpn: ["h3"] }
      }
    });
    // Xray removed allowInsecure: writing it would make the whole config fail to load.
    expect(JSON.stringify(outbound)).not.toMatch(/allowInsecure/u);
  });

  it("maps Hysteria 2 obfuscation, pins, bandwidth and port hopping to finalmask", () => {
    const outbound = buildOutbound(
      `hysteria2://pw@example.com:443,20000-30000/?sni=cdn.example.com&obfs=salamander&obfs-password=secret&pinSHA256=${PIN}&up=50&down=100&hop_interval=10#demo`
    );

    expect(outbound).toMatchObject({
      settings: { version: 2, address: "example.com", port: 443 },
      streamSettings: {
        tlsSettings: { serverName: "cdn.example.com", alpn: ["h3"], pinnedPeerCertSha256: PIN },
        finalmask: {
          udp: [{ type: "salamander", settings: { password: "secret" } }],
          quicParams: {
            brutalUp: "50000000 bps",
            brutalDown: "100000000 bps",
            udpHop: { ports: "443,20000-30000", interval: 10 }
          }
        }
      }
    });
  });

  it("always gives Hysteria 2 port hopping an interval, in the shape the Xray version reads", () => {
    const link = "hysteria2://pw@example.com:20000-30000?obfs-password=secret";
    expect(buildOutbound(link)).toMatchObject({
      streamSettings: { finalmask: { quicParams: { udpHop: { ports: "20000-30000", interval: 30 } } } }
    });

    // Xray 26.9.9 reads hopping from a udphop UDP mask, which has to come first.
    const newer = buildOutbound(link, { xrayVersion: "26.9.30" }) as {
      streamSettings: { finalmask: { udp: Array<{ type: string; settings: Record<string, unknown> }>; quicParams?: unknown } };
    };
    expect(newer.streamSettings.finalmask.udp).toEqual([
      { type: "udphop", settings: { mode: "intervallocal,intervalremote", interval: 30, remotePorts: "20000-30000" } },
      { type: "salamander", settings: { password: "secret" } }
    ]);
    expect(newer.streamSettings.finalmask.quicParams).toBeUndefined();

    expect(usesUdpHopMask(undefined)).toBe(false);
    expect(usesUdpHopMask("Xray 26.3.27 (Xray, Penetrates Everything.)")).toBe(false);
    expect(usesUdpHopMask("26.9.8")).toBe(false);
    expect(usesUdpHopMask("26.9.9")).toBe(true);
    expect(usesUdpHopMask("26.10.1")).toBe(true);
    expect(usesUdpHopMask("27.1.0")).toBe(true);
  });

  it("builds a full config around a Hysteria 2 outbound", () => {
    const config = JSON.parse(buildXrayConfig({
      rawUri: "hysteria2://pw@example.com:443#demo",
      socksHost: "127.0.0.1",
      socksPort: 19080
    })) as { inbounds: Array<{ settings?: { udp?: boolean } }>; outbounds: Array<{ protocol: string; tag: string }> };

    expect(config.inbounds[0]?.settings?.udp).toBe(true);
    // The tunnel stays first: Xray sends whatever no rule matches to the first outbound.
    expect(config.outbounds).toEqual([
      expect.objectContaining({ protocol: "hysteria", tag: "proxy" }),
      { tag: "direct", protocol: "freedom" }
    ]);
  });

  // Proxy-all on the Windows proxy path hands Xray's HTTP inbound every
  // HTTP(S) request, LAN and intranet ones included; they must not reach the
  // remote server.
  it("routes local and private destinations to a direct outbound without geo data", () => {
    const config = JSON.parse(buildXrayConfig({
      rawUri: "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls#demo",
      socksHost: "127.0.0.1",
      socksPort: 19080,
      httpHost: "127.0.0.1",
      httpPort: 19081,
      localNetworkDirect: true
    })) as {
      routing: { domainStrategy: string; rules: Array<{ ip?: string[]; domain?: string[]; inboundTag?: string[]; outboundTag: string }> };
    };

    expect(config.routing.domainStrategy).toBe("AsIs");
    expect(config.routing.rules.every((rule) => rule.outboundTag === "direct")).toBe(true);
    // Only for the Windows proxy's inbound: the TUN adapter and the routing
    // listener reach the SOCKS one having applied the routing order already.
    expect(config.routing.rules.every((rule) => JSON.stringify(rule.inboundTag) === JSON.stringify(["http-in"]))).toBe(true);
    const ips = config.routing.rules.flatMap((rule) => rule.ip ?? []);
    expect(ips).toEqual(expect.arrayContaining([
      "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8",
      "::1/128", "fe80::/10", "fc00::/7"
    ]));
    const domains = config.routing.rules.flatMap((rule) => rule.domain ?? []);
    expect(domains).toEqual(["regexp:^[^.]+$", "domain:local"]);
    expect(JSON.stringify(config)).not.toMatch(/geoip|geosite/u);
  });

  // A private address a domain rule picked reaches the SOCKS inbound from the
  // TUN adapter as a bare address, and an app pointed at Xray by hand - all
  // there is on macOS and Linux - asked for the tunnel.
  it("keeps everything in the tunnel where nothing steers the system's traffic to Xray", () => {
    for (const input of [
      { httpHost: "127.0.0.1", httpPort: 19081 },
      { httpHost: "127.0.0.1", httpPort: 19081, localNetworkDirect: false, localRuleOverrides: { ip: ["10.0.0.0/8"], domain: [] } },
      // No HTTP inbound for the rules to apply to.
      { localNetworkDirect: true }
    ]) {
      const config = JSON.parse(buildXrayConfig({
        rawUri: "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls#demo",
        socksHost: "127.0.0.1",
        socksPort: 19080,
        ...input
      })) as { routing: XrayRouting; outbounds: Array<{ tag: string }> };
      expect(config.routing.rules).toEqual([]);
      expect(config.outbounds[0]?.tag).toBe("proxy");
      expect(outboundFor(config.routing, "10.20.0.5")).toBe("proxy");
    }
  });

  // Traffic reaches Xray in split routing because a rule chose it upstream,
  // and an explicit rule wins over the local network on every path.
  it("sends the user's rules for the local network to the tunnel ahead of the direct rule", () => {
    const rules: RoutingRule[] = [
      ruleOf("ip", "10.0.0.0/8"),
      ruleOf("ip", "10.10.25.7/16"),
      ruleOf("ip", "0.0.0.0/0"),
      ruleOf("ip", "fd00::/8"),
      ruleOf("ip", "91.108.4.0/22"),
      ruleOf("ip", "2001:db8::/32"),
      ruleOf("ip", "192.168.0.0/16", false),
      ruleOf("ip", "172.16.0.0/012"),
      ruleOf("domain", "corp.local"),
      ruleOf("domain", "*.home.local"),
      ruleOf("domain", "example.org"),
      ruleOf("process.name", "telegram.exe")
    ];
    const overrides = xrayLocalRuleOverrides(rules);
    expect(overrides).toEqual({
      ip: ["0.0.0.0/0", "10.0.0.0/8", "10.10.0.0/16", "fd00::/8"],
      domain: ["domain:corp.local", "regexp:\\.home\\.local$"]
    });
    // Equal rule sets give equal answers, whatever their order.
    expect(xrayLocalRuleOverrides([...rules].reverse())).toEqual(overrides);
    expect(xrayLocalRuleOverrides([ruleOf("ip", "91.108.4.0/22"), ruleOf("domain", "example.org")])).toEqual({ ip: [], domain: [] });

    const routed = routingOf({ ip: ["10.0.0.0/8"], domain: ["domain:corp.local"] });
    expect(routed.rules[0]).toEqual({ type: "field", domain: ["domain:corp.local"], outboundTag: "proxy", inboundTag: ["http-in"] });
    expect(routed.rules[2]).toEqual({ type: "field", ip: ["10.0.0.0/8"], outboundTag: "proxy", inboundTag: ["http-in"] });
    // A user rule 10.0.0.0/8 tunnels 10.1.2.3; without it the address goes direct.
    expect(outboundFor(routed, "10.1.2.3")).toBe("proxy");
    expect(outboundFor(routed, "192.168.1.1")).toBe("direct");
    expect(outboundFor(routingOf(undefined), "10.1.2.3")).toBe("direct");
    expect(outboundFor(routingOf({ ip: [], domain: [] }), "10.1.2.3")).toBe("direct");
    // The proxy outbound the rule names is the tunnel.
    const config = JSON.parse(buildXrayConfig({
      rawUri: "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls#demo",
      socksHost: "127.0.0.1",
      socksPort: 19080,
      localRuleOverrides: { ip: ["10.0.0.0/8"], domain: [] }
    })) as { outbounds: Array<{ tag: string }> };
    expect(config.outbounds[0]?.tag).toBe("proxy");
  });

  // The PAC and the SSH listener let an IP rule select a single-label or
  // `.local` name by the address it resolves to. Xray sent `nas` direct
  // although 10.0.0.0/8 named the 10.1.2.3 it resolves to: under AsIs an IP
  // rule never matches a name.
  it("resolves single-label and .local names for an IP rule, and no other name", () => {
    const routed = routingOf({ ip: ["10.0.0.0/8"], domain: [] });
    expect(routed.domainStrategy).toBe("IPOnDemand");
    const addresses: Record<string, string> = {
      nas: "10.1.2.3",
      printer: "192.168.1.5",
      "wiki.corp.local": "10.4.4.4",
      "printer.local": "192.168.1.6",
      "example.com": "10.9.9.9",
      "foo.locals": "10.9.9.10"
    };
    const route = (name: string): { outbound: string; lookups: string[] } => {
      const lookups: string[] = [];
      const outbound = outboundForName(routed, name, (host) => {
        lookups.push(host);
        return addresses[host];
      });
      return { outbound, lookups };
    };
    expect(route("nas")).toEqual({ outbound: "proxy", lookups: ["nas"] });
    expect(route("wiki.corp.local")).toEqual({ outbound: "proxy", lookups: ["wiki.corp.local"] });
    // Local names the rule does not cover stay direct.
    expect(route("printer").outbound).toBe("direct");
    expect(route("printer.local").outbound).toBe("direct");
    expect(route("unresolvable").outbound).toBe("direct");
    // Every other name goes to the tunnel by name, never looked up here.
    expect(route("example.com")).toEqual({ outbound: "proxy", lookups: [] });
    expect(route("foo.locals")).toEqual({ outbound: "proxy", lookups: [] });
    expect(route("WWW.Example.ORG")).toEqual({ outbound: "proxy", lookups: [] });

    // Without an IP rule for the local network nothing is resolved.
    expect(routingOf({ ip: [], domain: ["domain:corp.local"] }).domainStrategy).toBe("AsIs");
    expect(routingOf(undefined).domainStrategy).toBe("AsIs");
  });

  it("reads security=0 and security=false as no security, like the share-link parser", () => {
    for (const value of ["0", "false"]) {
      expect(buildOutbound(`vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&security=${value}#demo`)).toMatchObject({
        streamSettings: { network: "ws" }
      });
      expect(buildOutbound(`vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&security=${value}#demo`)).not.toHaveProperty(
        "streamSettings.security"
      );
    }
  });

  it("dials a trojan link without a security parameter over TLS, with its server name", () => {
    expect(buildOutbound("trojan://secret@host.example.com:443?sni=sni.example.com#gfw")).toMatchObject({
      protocol: "trojan",
      streamSettings: { security: "tls", tlsSettings: { serverName: "sni.example.com" } }
    });
    expect(buildOutbound("trojan://secret@host.example.com:443?security=none#plain")).not.toHaveProperty("streamSettings.security");
  });

  it("dials an internationalised server name in its punycode form", () => {
    const vless = buildOutbound("vless://11111111-1111-4111-8111-111111111111@пример.рф:443?security=tls#idn") as {
      settings: { vnext: Array<{ address: string }> };
    };
    expect(vless.settings.vnext[0]?.address).toBe("xn--e1afmkfd.xn--p1ai");
    const trojan = buildOutbound("trojan://secret@MÜNCHEN.de:443?security=tls#idn") as { settings: { servers: Array<{ address: string }> } };
    expect(trojan.settings.servers[0]?.address).toBe("xn--mnchen-3ya.de");
    const vmess = buildOutbound(`vmess://${vmessLink({ add: "Пример.рф", port: 443, id: "22222222-2222-4222-8222-222222222222", tls: "tls" })}`) as {
      settings: { vnext: Array<{ address: string }> };
    };
    expect(vmess.settings.vnext[0]?.address).toBe("xn--e1afmkfd.xn--p1ai");
  });

  it("sends an internationalised TLS server name in its punycode form too", () => {
    // The certificate names the punycode form; Go's TLS sends and verifies
    // the name as given, so a Unicode `sni` failed the handshake.
    expect(buildOutbound(
      "vless://11111111-1111-4111-8111-111111111111@пример.рф:443?security=tls&sni=%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.%D1%80%D1%84&type=ws&host=cdn.example.com&path=%2F#idn"
    )).toMatchObject({ streamSettings: { tlsSettings: { serverName: "xn--e1afmkfd.xn--p1ai" }, wsSettings: { headers: { Host: "cdn.example.com" } } } });
    expect(buildOutbound("trojan://secret@host.example.com:443?servername=M%C3%BCnchen.de#idn")).toMatchObject({
      streamSettings: { tlsSettings: { serverName: "xn--mnchen-3ya.de" } }
    });
    expect(buildOutbound(`vmess://${vmessLink({ add: "host.example.com", port: 443, id: "22222222-2222-4222-8222-222222222222", tls: "tls", sni: "пример.рф" })}`)).toMatchObject({
      streamSettings: { tlsSettings: { serverName: "xn--e1afmkfd.xn--p1ai" } }
    });
    expect(buildOutbound("hysteria2://auth@host.example.com:443?sni=%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.%D1%80%D1%84#hy2")).toMatchObject({
      streamSettings: { tlsSettings: { serverName: "xn--e1afmkfd.xn--p1ai" } }
    });
    // An ASCII name goes as it was written.
    expect(buildOutbound("trojan://secret@host.example.com:443?sni=CDN.example.com#ascii")).toMatchObject({
      streamSettings: { tlsSettings: { serverName: "CDN.example.com" } }
    });
  });

  it("passes TLS alpn and the uTLS fingerprint for share links, not only for REALITY", () => {
    expect(buildOutbound(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&security=tls&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1&fp=chrome#tls"
    )).toMatchObject({
      streamSettings: { tlsSettings: { serverName: "cdn.example.com", alpn: ["h2", "http/1.1"], fingerprint: "chrome" } }
    });
    expect(buildOutbound("trojan://secret@example.com:443?security=tls&fp=firefox&alpn=http%2F1.1#tls")).toMatchObject({
      streamSettings: { tlsSettings: { alpn: ["http/1.1"], fingerprint: "firefox" } }
    });
    // uTLS shapes TCP handshakes only.
    expect(buildOutbound(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=hysteria&security=tls&auth=pw&fp=chrome#quic"
    )).not.toHaveProperty("streamSettings.tlsSettings.fingerprint");
    expect(buildOutbound(
      `vmess://${vmessLink({ add: "example.com", port: 443, id: "22222222-2222-4222-8222-222222222222", net: "ws", tls: "tls", fp: "safari", alpn: "h2" })}`
    )).toMatchObject({ streamSettings: { tlsSettings: { alpn: ["h2"], fingerprint: "safari" } } });
  });

  it("leaves out a TLS fingerprint Xray does not know, instead of failing the whole config", () => {
    // Xray rejects its config for `unknown "fingerprint": none`; links written
    // for other clients carry such values, and fp used to be ignored on TLS.
    // A `hello…` name is only as good as the uTLS id it names in this Xray:
    // a made-up one, `hellocustom` or a newer Chrome's refuses the config too.
    for (const fp of ["none", "golang", "disabled", "hellocustom", "hellofoo", "hellochrome_133", "randomizedalpn"]) {
      expect(buildOutbound(
        `vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=tcp&fp=${fp}#tls`
      )).not.toHaveProperty("streamSettings.tlsSettings.fingerprint");
      expect(buildOutbound(
        `vmess://${vmessLink({ add: "example.com", port: 443, id: "22222222-2222-4222-8222-222222222222", net: "ws", tls: "tls", fp })}`
      )).not.toHaveProperty("streamSettings.tlsSettings.fingerprint");
    }
    for (const fp of ["Chrome", "360", "random", "randomizednoalpn", "hellochrome_auto", "HelloChrome_120", "hellorandomizedalpn", "helloios_auto"]) {
      expect(buildOutbound(
        `trojan://secret@example.com:443?security=tls&fp=${fp}#tls`
      )).toMatchObject({ streamSettings: { tlsSettings: { fingerprint: fp } } });
    }
  });

  it("keeps REALITY spiderX and gRPC multi mode", () => {
    expect(buildOutbound(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=grpc&security=reality&sni=www.example.com&pbk=PUBLICKEY&sid=ab&fp=chrome&spx=%2Fsearch&serviceName=svc&mode=multi#reality"
    )).toMatchObject({
      streamSettings: {
        network: "grpc",
        security: "reality",
        realitySettings: { serverName: "www.example.com", publicKey: "PUBLICKEY", shortId: "ab", fingerprint: "chrome", spiderX: "/search" },
        grpcSettings: { serviceName: "svc", multiMode: true }
      }
    });
    expect(buildOutbound(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=grpc&security=tls&serviceName=svc&mode=gun#gun"
    )).not.toHaveProperty("streamSettings.grpcSettings.multiMode");
    // v2rayN keeps the gRPC mode in the VMess "type" field.
    expect(buildOutbound(
      `vmess://${vmessLink({ add: "example.com", port: 443, id: "22222222-2222-4222-8222-222222222222", net: "grpc", type: "multi", path: "svc", tls: "tls" })}`
    )).toMatchObject({ streamSettings: { grpcSettings: { serviceName: "svc", multiMode: true } } });
  });

  it("reads VMess JSON whose tls and other fields are not strings", () => {
    expect(buildOutbound(
      `vmess://${vmessLink({ add: "example.com", port: 443, id: "22222222-2222-4222-8222-222222222222", aid: 0, net: "ws", tls: true, path: "/ws" })}`
    )).toMatchObject({ protocol: "vmess", streamSettings: { network: "ws", security: "tls", wsSettings: { path: "/ws" } } });
    expect(buildOutbound(
      `vmess://${vmessLink({ add: "example.com", port: 443, id: "22222222-2222-4222-8222-222222222222", tls: false })}`
    )).not.toHaveProperty("streamSettings.security");
    expect(() => buildOutbound(`vmess://${vmessLink({ add: 42, port: 443 })}`)).not.toThrow(/trim/u);
  });

  it("gives VLESS over the hysteria transport the settings Xray 26 requires", () => {
    const outbound = buildOutbound(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=hysteria&security=tls&auth=pw&up=20&congestion=bbr#demo"
    );

    expect(outbound).toMatchObject({
      streamSettings: {
        network: "hysteria",
        hysteriaSettings: { version: 2, auth: "pw" },
        tlsSettings: { serverName: "example.com" },
        finalmask: { quicParams: { congestion: "bbr", brutalUp: "20000000 bps" } }
      }
    });
    // An empty sni= must not leave Xray's QUIC dialer to send the SNI "hysteria".
    expect(buildOutbound(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=hysteria&security=tls&sni=&auth=pw#demo"
    )).toMatchObject({ streamSettings: { tlsSettings: { serverName: "example.com" } } });
    // Xray would load it and then refuse every connection with "tls config is nil".
    expect(() => buildOutbound("vless://11111111-1111-4111-8111-111111111111@example.com:443?type=hysteria&auth=pw#demo")).toThrow(
      "The hysteria transport needs security=tls."
    );
  });

  const xray = bundledXrayPath();
  it.skipIf(!xray)("writes Hysteria 2 and mKCP configs the bundled Xray accepts", () => {
    const links = [
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=kcp&security=none#kcp-plain",
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=kcp&security=none&headerType=wechat-video&seed=demo&mtu=1200&tti=30#kcp-full",
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=kcp&headerType=dns&host=a.example.com#kcp-dns",
      `vless://11111111-1111-4111-8111-111111111111@example.com:443?type=kcp&fm=${encodeURIComponent(JSON.stringify({ udp: [{ type: "mkcp-legacy", settings: { header: "srtp" } }, { type: "mkcp-legacy", settings: { value: "pw" } }] }))}#kcp-fm`,
      "hy2://letmein@example.com#plain",
      "hysteria2://user:pass@[2001:db8::1]:443/?insecure=1#ipv6",
      `hysteria2://pw@example.com:443,20000-30000/?sni=cdn.example.com&obfs=salamander&obfs-password=secret&pinSHA256=${PIN}&up=50&down=100&hop_interval=10-20#full`,
      `hysteria2://pw@example.com?fm=${encodeURIComponent(JSON.stringify({ quicParams: { congestion: "force-brutal", brutalUp: "60 mbps", maxIdleTimeout: 60 } }))}#fm`,
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=hysteria&security=tls&auth=pw&up=20#vless",
      "vless://11111111-1111-4111-8111-111111111111@пример.рф:443?type=ws&security=tls&alpn=h2%2Chttp%2F1.1&fp=chrome&path=%2Fws#tls-fp",
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=grpc&security=reality&sni=www.example.com&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2&fp=chrome&spx=%2F&serviceName=svc&mode=multi#reality-grpc",
      "trojan://secret@example.com:443?security=tls&fp=firefox&alpn=http%2F1.1#trojan-fp",
      `vmess://${vmessLink({ add: "example.com", port: 443, id: "22222222-2222-4222-8222-222222222222", net: "ws", tls: true, fp: "safari" })}`,
      // Whatever `fp` a link carries, the config must load: a known uTLS id
      // is kept, any other is left out.
      ...["HelloChrome_131", "helloios_14", "hellorandomizedalpn", "hellocustom", "hellochrome_133", "hellofoo"].map(
        (fp) => `trojan://secret@example.com:443?security=tls&fp=${fp}#trojan-${fp}`
      )
    ];
    const directory = mkdtempSync(path.join(tmpdir(), "shadow-ssh-xray-config-"));
    // The routing rules a user's rules for the local network add, too.
    const localRuleOverrides = xrayLocalRuleOverrides([
      ruleOf("ip", "10.0.0.0/8"),
      ruleOf("ip", "fd00::/8"),
      ruleOf("domain", "corp.local"),
      ruleOf("domain", "*.home.local")
    ]);
    try {
      for (const [index, rawUri] of links.entries()) {
        const file = path.join(directory, `config-${index}.json`);
        writeFileSync(
          file,
          buildXrayConfig({
            rawUri,
            socksHost: "127.0.0.1",
            socksPort: 19080,
            httpHost: "127.0.0.1",
            httpPort: 19081,
            localNetworkDirect: true,
            localRuleOverrides
          })
        );
        const result = spawnSync(xray as string, ["run", "-test", "-config", file], { encoding: "utf8", timeout: 20_000 });
        expect(`${rawUri}\n${result.stdout}${result.stderr}`).toMatch(/Configuration OK/u);
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

function ruleOf(type: RoutingRule["type"], value: string, enabled = true): RoutingRule {
  return { id: `${type}:${value}`, type, value, enabled, createdAt: "", updatedAt: "" };
}

interface XrayRouting {
  domainStrategy: string;
  rules: Array<{ type: string; ip?: string[]; domain?: string[]; inboundTag?: string[]; outboundTag: string }>;
}

function routingOf(localRuleOverrides: XrayLocalRuleOverrides | undefined): XrayRouting {
  return (JSON.parse(buildXrayConfig({
    rawUri: "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls#demo",
    socksHost: "127.0.0.1",
    socksPort: 19080,
    httpHost: "127.0.0.1",
    httpPort: 19081,
    localNetworkDirect: true,
    localRuleOverrides
  })) as { routing: XrayRouting }).routing;
}

/** Xray's answer for a literal address under AsIs: the first IP rule that covers it, else the first outbound. */
function outboundFor(routing: XrayRouting, address: string): string {
  const ip = parseIpAddressUnmapped(address);
  const rule = routing.rules.find((candidate) =>
    (candidate.ip ?? []).some((cidr) => {
      const range = parseCidrRange(cidr);
      return ip !== undefined && range !== undefined && ipMatchesCidr(ip, range);
    })
  );
  return rule?.outboundTag ?? "proxy";
}

/**
 * Xray's answer for a name under IPOnDemand: rules in order, a name rule
 * matched on the name, an IP rule on the addresses the name resolves to -
 * looked up only when an IP rule is reached - else the first outbound.
 */
function outboundForName(routing: XrayRouting, name: string, resolve: (host: string) => string | undefined): string {
  let resolved: { address?: string } | undefined;
  for (const rule of routing.rules) {
    if (rule.domain) {
      const matches = rule.domain.some((pattern) => {
        if (pattern.startsWith("regexp:")) {
          const source = pattern.slice("regexp:".length);
          const caseless = source.startsWith("(?i)");
          return new RegExp(caseless ? source.slice(4) : source, caseless ? "iu" : "u").test(name);
        }
        const suffix = pattern.slice("domain:".length);
        return name === suffix || name.endsWith(`.${suffix}`);
      });
      if (matches) {
        return rule.outboundTag;
      }
      continue;
    }
    resolved ??= { address: resolve(name) };
    const ip = resolved.address === undefined ? undefined : parseIpAddressUnmapped(resolved.address);
    if ((rule.ip ?? []).some((cidr) => {
      const range = parseCidrRange(cidr);
      return ip !== undefined && range !== undefined && ipMatchesCidr(ip, range);
    })) {
      return rule.outboundTag;
    }
  }
  return "proxy";
}

function vmessLink(payload: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

function bundledXrayPath(): string | undefined {
  const platform = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "macos" : process.platform === "linux" ? "linux" : undefined;
  const arch = process.arch === "x64" || process.arch === "arm64" ? process.arch : undefined;
  if (!platform || !arch) {
    return undefined;
  }
  const file = path.join(process.cwd(), "resources", "xray", platform, arch, platform === "windows" ? "xray.exe" : "xray");
  return existsSync(file) ? file : undefined;
}
