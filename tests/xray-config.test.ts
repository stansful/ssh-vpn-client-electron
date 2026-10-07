import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildOutbound, buildXrayConfig, usesMkcpLegacyMask, usesUdpHopMask } from "../src/core/proxy/xray-config.js";

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
    expect(config.outbounds).toHaveLength(1);
    expect(config.outbounds[0]).toMatchObject({ protocol: "hysteria", tag: "proxy" });
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
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=hysteria&security=tls&auth=pw&up=20#vless"
    ];
    const directory = mkdtempSync(path.join(tmpdir(), "shadow-ssh-xray-config-"));
    try {
      for (const [index, rawUri] of links.entries()) {
        const file = path.join(directory, `config-${index}.json`);
        writeFileSync(file, buildXrayConfig({ rawUri, socksHost: "127.0.0.1", socksPort: 19080 }));
        const result = spawnSync(xray as string, ["run", "-test", "-config", file], { encoding: "utf8", timeout: 20_000 });
        expect(`${rawUri}\n${result.stdout}${result.stderr}`).toMatch(/Configuration OK/u);
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

function bundledXrayPath(): string | undefined {
  const platform = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "macos" : process.platform === "linux" ? "linux" : undefined;
  const arch = process.arch === "x64" || process.arch === "arm64" ? process.arch : undefined;
  if (!platform || !arch) {
    return undefined;
  }
  const file = path.join(process.cwd(), "resources", "xray", platform, arch, platform === "windows" ? "xray.exe" : "xray");
  return existsSync(file) ? file : undefined;
}
