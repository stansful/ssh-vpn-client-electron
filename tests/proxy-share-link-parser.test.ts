import { describe, expect, it } from "vitest";
import { parseProxyShareLink, parseProxyShareLinks } from "../src/core/proxy/share-link-parser.js";

describe("proxy share-link parser", () => {
  it("parses VLESS links with transport and security metadata", () => {
    const profile = parseProxyShareLink(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&security=tls&path=%2Fws#Netherlands"
    );

    expect(profile).toMatchObject({
      name: "Netherlands",
      protocol: "vless",
      host: "example.com",
      port: 443,
      transport: "ws",
      security: "tls"
    });
    expect(profile.fingerprint).toMatch(/^sha256:/u);
  });

  it("parses VMess base64 JSON payloads", () => {
    const payload = Buffer.from(
      JSON.stringify({
        v: "2",
        ps: "vmess-demo",
        add: "vmess.example.com",
        port: "8443",
        id: "22222222-2222-4222-8222-222222222222",
        aid: "0",
        net: "grpc",
        tls: "tls"
      }),
      "utf8"
    ).toString("base64");

    expect(parseProxyShareLink(`vmess://${payload}`)).toMatchObject({
      name: "vmess-demo",
      protocol: "vmess",
      host: "vmess.example.com",
      port: 8443,
      transport: "grpc",
      security: "tls"
    });
  });

  it("parses Trojan links and reports invalid lines during bulk import", () => {
    const result = parseProxyShareLinks("trojan://secret@trojan.example.com:443?security=tls#trojan-demo\nnot-a-link\n");

    expect(result.profiles).toHaveLength(1);
    expect(result.profiles[0]).toMatchObject({
      name: "trojan-demo",
      protocol: "trojan",
      host: "trojan.example.com",
      port: 443
    });
    expect(result.errors).toHaveLength(1);
  });

  it("normalizes additional Xray transport aliases", () => {
    expect(parseProxyShareLink(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=xhttp&security=tls&path=%2Fx&mode=packet-up#xhttp"
    )).toMatchObject({ transport: "xhttp" });

    expect(parseProxyShareLink(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=kcp&security=none#kcp"
    )).toMatchObject({ transport: "mkcp" });

    expect(parseProxyShareLink(
      "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=h2&security=tls#h2"
    )).toMatchObject({ transport: "http" });
  });
});
