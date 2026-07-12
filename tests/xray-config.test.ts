import { describe, expect, it } from "vitest";
import { buildOutbound, buildXrayConfig } from "../src/core/proxy/xray-config.js";

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
    expect(config.inbounds[0]?.settings?.udp).toBe(false);
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
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=kcp&security=none&headerType=wechat-video&seed=demo#demo"
    )).toMatchObject({
      streamSettings: {
        network: "kcp",
        kcpSettings: { seed: "demo", header: { type: "wechat-video" } }
      }
    });

    expect(buildOutbound(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=h2&security=tls&host=a.example.com,b.example.com&path=%2Fh2#demo"
    )).toMatchObject({
      streamSettings: {
        network: "http",
        httpSettings: { host: ["a.example.com", "b.example.com"], path: "/h2" }
      }
    });
  });
});
