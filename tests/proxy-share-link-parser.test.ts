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
    )).toMatchObject({ transport: "unknown" });
  });

  it("rejects oversized direct links and bulk input before parsing", () => {
    expect(() => parseProxyShareLink(`vless://${"a".repeat(64 * 1024)}`)).toThrow(/longer/u);

    const result = parseProxyShareLinks("a".repeat(2 * 1024 * 1024 + 1));
    expect(result.profiles).toEqual([]);
    expect(result.errors[0]).toMatch(/Import text is longer/u);
  });

  it("parses Hysteria 2 links as QUIC + TLS profiles, hy2:// included", () => {
    const profile = parseProxyShareLink("hysteria2://letmein@example.com:8443/?sni=real.example.com&obfs=salamander&obfs-password=x#Helsinki");

    expect(profile).toEqual({
      name: "Helsinki",
      protocol: "hysteria2",
      host: "example.com",
      port: 8443,
      transport: "hysteria",
      security: "tls",
      flow: "",
      rawUri: "hysteria2://letmein@example.com:8443/?sni=real.example.com&obfs=salamander&obfs-password=x#Helsinki",
      fingerprint: expect.stringMatching(/^sha256:/u)
    });
    expect(parseProxyShareLink("hy2://letmein@example.com")).toMatchObject({ protocol: "hysteria2", port: 443 });
  });

  it("keeps a Hysteria 2 port-hopping list next to the first port", () => {
    expect(parseProxyShareLink("hysteria2://pw@example.com:443,20000-30000/#hop")).toMatchObject({
      port: 443,
      hopPorts: "443,20000-30000"
    });
    expect(parseProxyShareLink("hy2://pw@example.com:443?mport=20000-30000")).toMatchObject({ port: 443, hopPorts: "20000-30000" });
  });

  it("flags Hysteria 2 links that ask to skip certificate checks without a pin, and only those", () => {
    const pin = "4f1c9e0b7d2a51c8e3f6a0b94d17c2e85a6f3b10d9c4e27f81a5b3c6d0e9a92e";
    expect(parseProxyShareLink("hy2://pw@example.com?insecure=1#self-signed")).toMatchObject({ protocol: "hysteria2", insecureWithoutPin: true });
    expect(parseProxyShareLink("hysteria2://pw@example.com?allowInsecure=true#panel").insecureWithoutPin).toBe(true);
    expect(parseProxyShareLink("hysteria2://pw@example.com?allow_insecure=1#throne").insecureWithoutPin).toBe(true);
    // A pin is what gets checked, so insecure=1 next to one is fine. Only `true` is ever set.
    expect(parseProxyShareLink(`hy2://pw@example.com?insecure=1&pinSHA256=${pin}#pinned`)).not.toHaveProperty("insecureWithoutPin");
    expect(parseProxyShareLink("hy2://pw@example.com?insecure=0#checked")).not.toHaveProperty("insecureWithoutPin");
    expect(parseProxyShareLink("hy2://pw@example.com#plain")).not.toHaveProperty("insecureWithoutPin");
    expect(parseProxyShareLink("vless://id@example.com:443?security=tls&allowInsecure=1#vless")).not.toHaveProperty("insecureWithoutPin");

    const { profiles } = parseProxyShareLinks(["hy2://pw@a.example.com?insecure=1#a", "hy2://pw@b.example.com#b"].join("\n"));
    expect(profiles.map((profile) => profile.insecureWithoutPin)).toEqual([true, undefined]);
  });

  it("fingerprints hysteria2:// and hy2:// spellings of one link alike, and different passwords apart", () => {
    const fingerprint = (link: string) => parseProxyShareLink(link).fingerprint;
    expect(fingerprint("hy2://pw@example.com?sni=a#n")).toBe(fingerprint("hysteria2://pw@example.com:443/?sni=a#n"));
    expect(fingerprint("hy2://user:one@example.com")).not.toBe(fingerprint("hy2://user:two@example.com"));
  });

  it("counts Hysteria 2 lines as imported and names unsupported schemes in the error", () => {
    const result = parseProxyShareLinks("hy2://pw@example.com#one\nhysteria://pw@example.com:443#v1\ntuic://x@example.com:443");

    expect(result.profiles.map((profile) => profile.protocol)).toEqual(["hysteria2"]);
    expect(result.errors).toEqual([
      "Line 2: Only vless://, vmess://, trojan://, and hysteria2:// links are supported.",
      "Line 3: Only vless://, vmess://, trojan://, and hysteria2:// links are supported."
    ]);
  });
});
