import { createHash } from "node:crypto";
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

  it("reads a trojan link without a security parameter as TLS, and only a trojan link", () => {
    // The trojan-gfw scheme has no such parameter: Trojan always runs over
    // TLS. Read as none, the profile dialled a TLS server in plaintext.
    expect(parseProxyShareLink("trojan://secret@host.example.com:443?sni=host.example.com#gfw")).toMatchObject({ security: "tls" });
    expect(parseProxyShareLink("trojan://secret@host.example.com:443?security=none#plain")).toMatchObject({ security: "none" });
    expect(parseProxyShareLink("trojan://secret@host.example.com:443?tls=0#legacy")).toMatchObject({ security: "none" });
    expect(parseProxyShareLink("vless://11111111-1111-4111-8111-111111111111@example.com:443#bare")).toMatchObject({ security: "none" });
    // The fingerprint hashes the link as written, so a saved profile is still found on re-import.
    const before = JSON.stringify({ protocol: "trojan", username: "secret", host: "host.example.com", port: 443, params: [], hash: "gfw" });
    expect(parseProxyShareLink("trojan://secret@host.example.com:443#gfw").fingerprint).toBe(
      `sha256:${createHash("sha256").update(before).digest("hex")}`
    );
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

  // WHATWG URL keeps a non-ASCII host of a vless:// or trojan:// link
  // percent-encoded, which Xray could not dial.
  it("stores an internationalised server name as punycode and keeps its old fingerprint", () => {
    const link = "vless://11111111-1111-4111-8111-111111111111@пример.рф:443?type=ws&security=tls#idn";
    const profile = parseProxyShareLink(link);

    expect(profile).toMatchObject({ host: "xn--e1afmkfd.xn--p1ai", port: 443 });
    // Profiles saved before this hashed the percent-encoded host; a different
    // canonical form would duplicate them on re-import.
    const legacyCanonical = JSON.stringify({
      protocol: "vless",
      username: "11111111-1111-4111-8111-111111111111",
      host: "%d0%bf%d1%80%d0%b8%d0%bc%d0%b5%d1%80.%d1%80%d1%84",
      port: 443,
      params: [["security", "tls"], ["type", "ws"]],
      hash: "idn"
    });
    expect(profile.fingerprint).toBe(`sha256:${createHash("sha256").update(legacyCanonical).digest("hex")}`);

    expect(parseProxyShareLink("trojan://secret@MÜNCHEN.de:443?security=tls")).toMatchObject({
      host: "xn--mnchen-3ya.de",
      name: "trojan-xn--mnchen-3ya.de:443"
    });
    const vmess = (payload: unknown): string => `vmess://${Buffer.from(JSON.stringify(payload), "utf8").toString("base64")}`;
    const vmessPayload = { add: "Пример.рф", port: 443, id: "22222222-2222-4222-8222-222222222222", ps: "idn" };
    const vmessProfile = parseProxyShareLink(vmess(vmessPayload));
    expect(vmessProfile.host).toBe("xn--e1afmkfd.xn--p1ai");
    const legacyVmess = JSON.stringify(
      Object.fromEntries(
        Object.entries({ ...vmessPayload, add: "пример.рф", port: 443, net: "tcp", tls: "none" }).sort(([left], [right]) => left.localeCompare(right))
      )
    );
    expect(vmessProfile.fingerprint).toBe(`sha256:${createHash("sha256").update(`vmess:${legacyVmess}`).digest("hex")}`);
    // ASCII hosts read exactly as before.
    expect(parseProxyShareLink("vless://u@Example.COM:443?security=tls").host).toBe("example.com");
    expect(() => parseProxyShareLink("vless://u@%zz.example:443")).toThrow("VLESS URI must contain host and valid port.");
  });

  it("reads VMess payloads whose tls and net are not strings", () => {
    const vmess = (payload: unknown): string => `vmess://${Buffer.from(JSON.stringify(payload), "utf8").toString("base64")}`;
    const base = { add: "vmess.example.com", port: 443, id: "22222222-2222-4222-8222-222222222222" };

    expect(parseProxyShareLink(vmess({ ...base, tls: true, net: "ws" }))).toMatchObject({ security: "tls", transport: "ws" });
    expect(parseProxyShareLink(vmess({ ...base, tls: false }))).toMatchObject({ security: "none", transport: "tcp" });
    expect(parseProxyShareLink(vmess({ ...base, net: 7 }))).toMatchObject({ transport: "unknown" });
    expect(() => parseProxyShareLink(vmess(null))).toThrow("VMess payload must contain add and valid port.");
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
