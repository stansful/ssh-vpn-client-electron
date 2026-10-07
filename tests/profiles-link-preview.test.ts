import { describe, expect, it } from "vitest";
import { parseProxyShareLink, UNSUPPORTED_PROXY_SCHEME_MESSAGE } from "../src/core/proxy/share-link-parser.js";
import {
  HYSTERIA2_ECH_MESSAGE,
  HYSTERIA2_HOST_MESSAGE,
  HYSTERIA2_PORTS_MESSAGE,
  INVALID_HYSTERIA2_URI_MESSAGE
} from "../src/core/proxy/hysteria2-link.js";
import {
  applySchemeFix,
  describeLinkProblem,
  HYSTERIA2_INSECURE_WARNING,
  importFailureHint,
  importFailureMessage,
  linkFingerprint,
  previewShareLink,
  suggestScheme,
  UNSUPPORTED_SCHEME_MESSAGE
} from "../src/renderer/components/pages/profiles/link-preview.js";
import { proxyProtocolMark } from "../src/shared/proxy-protocols.js";

const vmess = (payload: unknown, transform: (encoded: string) => string = (value) => value): string =>
  `vmess://${transform(Buffer.from(JSON.stringify(payload), "utf8").toString("base64"))}`;

const vmessPayload = { v: "2", ps: "sg-sin-ws", add: "SG.example.net", port: "443", id: "22222222-2222-4222-8222-222222222222", aid: "0", net: "ws", tls: "tls", path: "/ws" };

const PIN = "4f1c9e0b7d2a51c8e3f6a0b94d17c2e85a6f3b10d9c4e27f81a5b3c6d0e9a92e";
/** 66 ports that don't touch, so they stay 66 ranges after merging: past the limit of 64. */
const TOO_MANY_RANGES = Array.from({ length: 66 }, (_, index) => 1000 + index * 2).join(",");
/** A minimal ECHConfigList: a 2-byte length, then that many bytes. */
const ECH_CONFIG_LIST = encodeURIComponent(Buffer.from([0, 2, 0xab, 0xcd]).toString("base64"));
const FM_PACKET_SIZE = encodeURIComponent(JSON.stringify({ udp: [{ type: "salamander", settings: { password: "x", packetSize: 1200 } }] }));

// Links the renderer preview must read exactly like the main process does.
const LINKS = [
  "vless://3c8f2a4e-91b0-4d7a-a6e2-5f0d9c1b7e44@198.51.100.140:443?type=xhttp&security=reality&sni=www.example.com#pl-waw-xhttp",
  "vless://11111111-1111-4111-8111-111111111111@Example.COM:443?type=ws&security=tls&path=%2Fws#Netherlands%20%C2%B7%20Amsterdam",
  "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=ws#Netherlands",
  "vless://u@[2001:db8::1]:443?type=ws&security=tls#warsaw-v6",
  "vless://u@203.0.113.9:8443?type=raw&security=0",
  "vless://u@203.0.113.9:8443?net=h2&tls=1#h2",
  "vless://u@203.0.113.9:8443?type=http-upgrade&security=none#hu",
  "vless://u@192.0.2.9:443?type=tcp&security=xtls#lab-unknown",
  "vless://u@192.0.2.9:443?type=quic&security=tls#odd-transport",
  "VLESS://u@upper.example.org:443?type=grpc&security=tls#caps",
  "trojan://b71e0c2a9d4f6e83@203.0.113.77:443?security=tls&type=tcp#trojan-tokyo",
  "trojan://secret@trojan.example.com:443",
  "vless://u@bad-name.example:443#%E0%A4%A",
  vmess(vmessPayload),
  vmess({ ...vmessPayload, ps: "" }),
  vmess({ ...vmessPayload, ps: "Сингапур · ws", net: "kcp", tls: "" }),
  vmess(vmessPayload, (encoded) => encoded.replace(/=+$/u, "").replace(/\+/gu, "-").replace(/\//gu, "_")),
  vmess(vmessPayload, (encoded) => `${encoded.slice(0, 10)}\n ${encoded.slice(10)}`),
  vmess(vmessPayload, (encoded) => `${encoded.slice(0, 12)}$${encoded.slice(12)}`),
  `hysteria2://letmein@hy.example.com:443/?sni=real.example.com&obfs=salamander&obfs-password=gawrgura&pinSHA256=${PIN}&insecure=1&up=50&down=200#fi-hel-hy2`,
  "hy2://letmein@hy.example.com#short",
  "HYSTERIA2://letmein@Upper.Example.ORG:8443#caps",
  "hysteria2://user:p%40ss@userpass.example.net:443/?sni=userpass.example.net#userpass",
  "hy2://letmein@[2001:db8::7]:443#hy2-v6",
  "hysteria2://letmein@noport.example.com/?sni=noport.example.com",
  "hysteria2://letmein@range.example.com:20000-30000#range",
  "hysteria2://letmein@list.example.com:443,20000-30000,40000#list",
  "hy2://letmein@mport.example.com:443?mport=20000:30000&hopInterval=15#mport",
  "hy2://letmein@obfs.example.com:443?obfs-password=secret#obfs-only",
  "hysteria2://letmein@insecure.example.com:443?insecure=1&sni=insecure.example.com#insecure",
  "hysteria2://letmein@hy.example.com:443#%E0%A4%A",
  // Sorted and merged: dial port 20000, hop list "443,20000-35000".
  "hysteria2://pw@example.com:20000-30000,443,25000-35000",
  `hysteria2://pw@example.com:443?ech=${ECH_CONFIG_LIST}#ech`,
  // Rejected ones: the preview must fail with the same message.
  "ss://YWVzLTI1Ni1nY206c2VjcmV0@198.51.100.7:8388#home-ss",
  "vles://8e2d41c0-5a7b-4c19-b3f6-2d9e0a1c7b55@203.0.113.91:443?type=ws&security=tls#jp-osa-ws",
  "https://example.com/subscription",
  "not a link",
  "vless://u@example.com?type=ws",
  "vless://u@example.com:70000?type=ws",
  "trojan://secret@:443",
  "vmess://%%%%",
  vmess({ ps: "no-address", port: 443 }),
  vmess({ add: "a.example", port: "x" }),
  "hysteria2://letmein@:443#no-host",
  "hysteria2://letmein@hy.example.com:443,abc#bad-ports",
  "hy2://letmein@hy.example.com:443?mport=20000-70000#bad-mport",
  "hysteria2://letmein@hy.example.com:443?obfs=gecko&obfs-password=x#gecko",
  "hysteria2://letmein@hy.example.com:443?obfs=salamander#no-obfs-password",
  "hysteria2://letmein@hy.example.com:443?pinSHA256=not-a-hash#bad-pin",
  "hysteria2://letmein@hy.example.com:443?fm=%7Bbroken#bad-fm",
  "hysteria2://letmein@hy.example.com:443?fm=%7B%22udp%22%3A%5B%7B%22type%22%3A%22noise%22%7D%5D%7D#fm-noise",
  "hysteria2://letmein@[2001:db8::7#bad-v6",
  `hysteria2://letmein@hy.example.com:${TOO_MANY_RANGES}#too-many-ranges`,
  `hysteria2://letmein@${"a".repeat(254)}:443#long-host`,
  // ech as a DNS server: Xray would query it outside the tunnel.
  "hysteria2://pw@example.com:443?ech=udp%3A%2F%2F1.1.1.1%3A53#ech-dns",
  "hysteria2://pw@example.com:443?ech=https%3A%2F%2Fdns.example%2Fdns-query#ech-doh",
  `hysteria2://letmein@hy.example.com:443?fm=${FM_PACKET_SIZE}#fm-packet-size`,
  "hysteria://hy1.example.com:443?auth=letmein&upmbps=50#hysteria-v1",
  "hysteria2+realm://token@realm.example.com/room#realm"
];

describe("renderer share-link preview", () => {
  it.each(LINKS)("reads %s like the core parser", async (link) => {
    const preview = previewShareLink(link);
    let core: ReturnType<typeof parseProxyShareLink> | undefined;
    let coreError: string | undefined;
    try {
      core = parseProxyShareLink(link);
    } catch (error) {
      coreError = (error as Error).message;
    }
    if (!core) {
      expect(preview).toEqual({ status: "error", message: coreError });
      return;
    }
    expect(preview.status).toBe("ok");
    if (preview.status !== "ok") {
      return;
    }
    expect({
      name: preview.link.name,
      protocol: preview.link.protocol,
      host: preview.link.host,
      port: preview.link.port,
      hopPorts: preview.link.hopPorts,
      insecureWithoutPin: preview.link.insecureWithoutPin,
      transport: preview.link.transport,
      security: preview.link.security
    }).toEqual({
      name: core.name,
      protocol: core.protocol,
      host: core.host,
      port: core.port,
      hopPorts: core.hopPorts,
      insecureWithoutPin: core.insecureWithoutPin,
      transport: core.transport,
      security: core.security
    });
    await expect(linkFingerprint(preview.link)).resolves.toBe(core.fingerprint);
  });

  it("treats blank input as empty, not as an error", () => {
    expect(previewShareLink("   ")).toEqual({ status: "empty" });
  });

  it("uses the core's unsupported-scheme text", () => {
    expect(UNSUPPORTED_SCHEME_MESSAGE).toBe(UNSUPPORTED_PROXY_SCHEME_MESSAGE);
  });

  it("reads Hysteria 2 links as QUIC + TLS with their hop ports, and hy2:// as the same link", async () => {
    const preview = (link: string) => {
      const result = previewShareLink(link);
      if (result.status !== "ok") {
        throw new Error(`expected ${link} to read`);
      }
      return result.link;
    };
    expect(preview("hy2://letmein@hy.example.com:443,20000-30000#fi-hel-hy2")).toMatchObject({
      name: "fi-hel-hy2",
      protocol: "hysteria2",
      host: "hy.example.com",
      port: 443,
      hopPorts: "443,20000-30000",
      transport: "hysteria",
      security: "tls"
    });
    expect(preview("hy2://letmein@hy.example.com:443?mport=20000:30000").hopPorts).toBe("20000-30000");
    // Overlapping ranges are merged and sorted; `port` stays the first one written.
    expect(preview("hysteria2://pw@example.com:20000-30000,443,25000-35000")).toMatchObject({ port: 20000, hopPorts: "443,20000-35000" });
    expect(preview("hysteria2://letmein@hy.example.com").port).toBe(443);
    expect(preview("hysteria2://letmein@hy.example.com:443#plain")).not.toHaveProperty("hopPorts");
    const short = await linkFingerprint(preview("hy2://letmein@hy.example.com:443?sni=a.example#same"));
    const long = await linkFingerprint(preview("hysteria2://letmein@hy.example.com:443?sni=a.example#same"));
    expect(short).toBe(long);
  });

  it("warns when a Hysteria 2 link asks to skip certificate checks without a pin", () => {
    const warnings = (link: string): string[] | undefined => {
      const result = previewShareLink(link);
      return result.status === "ok" ? result.link.warnings : ["not read"];
    };
    expect(HYSTERIA2_INSECURE_WARNING).toBe(
      "This link asks to skip certificate checks (insecure=1), which the bundled Xray can’t do, so the server’s certificate is checked as usual. If the server uses a self-signed certificate, add its pinSHA256 to the link."
    );
    expect(warnings("hysteria2://letmein@hy.example.com:443?insecure=1#self-signed")).toEqual([HYSTERIA2_INSECURE_WARNING]);
    expect(warnings("hy2://letmein@hy.example.com:443?allowInsecure=true#self-signed")).toEqual([HYSTERIA2_INSECURE_WARNING]);
    expect(warnings(`hysteria2://letmein@hy.example.com:443?insecure=1&pinSHA256=${PIN}#pinned`)).toBeUndefined();
    expect(warnings("hysteria2://letmein@hy.example.com:443?insecure=0#checked")).toBeUndefined();
    expect(warnings("vless://u@example.com:443?security=tls&allowInsecure=1#vless")).toBeUndefined();
  });

  it("marks the same links the way the saved profile will", () => {
    const read = (link: string) => {
      const result = previewShareLink(link);
      return result.status === "ok" ? result.link : undefined;
    };
    expect(read("hy2://letmein@hy.example.com:443?allow_insecure=1#self-signed")).toMatchObject({ insecureWithoutPin: true });
    expect(read(`hysteria2://letmein@hy.example.com:443?insecure=1&pinSHA256=${PIN}#pinned`)).not.toHaveProperty("insecureWithoutPin");
    expect(read("hysteria2://letmein@hy.example.com:443#plain")).not.toHaveProperty("insecureWithoutPin");
    expect(read(`hysteria2://letmein@hy.example.com:443?insecure=1&pinSHA256=${PIN}#pinned`)).toMatchObject({ certificatePinned: true });
    expect(read("hysteria2://letmein@hy.example.com:443?insecure=1#self-signed")).not.toHaveProperty("certificatePinned");
  });

  it("explains rejected links in plain words", () => {
    const problem = (link: string): string => {
      const preview = previewShareLink(link);
      return preview.status === "error" ? describeLinkProblem(link, preview.message) : "";
    };
    expect(problem("ss://YWVz@198.51.100.7:8388#home-ss")).toBe(
      "This is an ss:// (Shadowsocks) link, which Shadow SSH can’t run. Paste a vless://, vmess://, trojan:// or hysteria2:// link instead."
    );
    expect(problem("tuic://uuid:pw@198.51.100.7:443#tuic")).toBe(
      "This is a tuic:// (TUIC) link, which Shadow SSH can’t run. Paste a vless://, vmess://, trojan:// or hysteria2:// link instead."
    );
    expect(problem("vles://id@203.0.113.91:443#jp")).toBe("Looks like a typo: vles:// instead of vless://.");
    expect(problem("hysteira2://pw@203.0.113.91:443#jp")).toBe("Looks like a typo: hysteira2:// instead of hysteria2://.");
    expect(problem("https://example.com/sub")).toBe(
      "That’s a web address, not a share link. Subscription URLs aren’t supported, so paste the vless://, vmess://, trojan:// or hysteria2:// links themselves."
    );
    expect(problem("hello there")).toBe("This isn’t a share link. Paste one that starts with vless://, vmess://, trojan:// or hysteria2://.");
    expect(problem("naive://x@y:1")).toBe("naive:// links can’t run in Shadow SSH. Paste a vless://, vmess://, trojan:// or hysteria2:// link instead.");
    expect(problem("vless://u@example.com?type=ws")).toBe("This vless:// link has no server address or a wrong port. Copy it again from your provider.");
    expect(problem("vmess://%%%%")).toBe("This vmess:// link is damaged: its encoded part can’t be read. Copy it again from your provider.");
  });

  it("explains rejected Hysteria links in plain words", () => {
    const problem = (link: string): string => {
      const preview = previewShareLink(link);
      return preview.status === "error" ? describeLinkProblem(link, preview.message) : "";
    };
    expect(problem("hysteria://hy1.example.com:443?auth=letmein#v1")).toBe(
      "This is a hysteria:// (Hysteria v1) link, which Shadow SSH can’t run. Hysteria 2 links work, so paste a hysteria2:// or hy2:// link instead."
    );
    expect(problem("hysteria2+realm://token@realm.example.com/room")).toBe(
      "This is a hysteria2+realm:// (Hysteria 2 Realm) link, which Shadow SSH can’t run. Paste a vless://, vmess://, trojan:// or hysteria2:// link instead."
    );
    expect(problem("hysteria2://letmein@:443#no-host")).toBe("This hysteria2:// link has no server address. Copy it again from your provider.");
    const ports = "link’s ports can’t be read. Ports look like 443 or 443,20000-30000, with at most 64 ranges. Copy it again from your provider.";
    expect(problem("hy2://letmein@hy.example.com:443,abc")).toBe(`This hy2:// ${ports}`);
    expect(problem("hy2://letmein@hy.example.com:443?mport=20000-70000")).toBe(`This hy2:// ${ports}`);
    expect(problem(`hysteria2://letmein@hy.example.com:${TOO_MANY_RANGES}`)).toBe(`This hysteria2:// ${ports}`);
    // 66 written ranges that merge into one are fine.
    expect(problem(`hysteria2://letmein@hy.example.com:${Array.from({ length: 66 }, (_, index) => 1000 + index).join(",")}`)).toBe("");
    const damaged = "link is damaged, so it can’t be read. Copy it again from your provider.";
    expect(problem("hysteria2://letmein@[2001:db8::7#bad-v6")).toBe(`This hysteria2:// ${damaged}`);
    expect(problem(`hy2://letmein@${"a".repeat(254)}:443`)).toBe(`This hy2:// ${damaged}`);
    const ech = "The ech value in this link isn’t an ECH config list, so it can’t be used. Copy the link again from your provider.";
    expect(problem("hysteria2://pw@example.com:443?ech=udp%3A%2F%2F1.1.1.1%3A53")).toBe(ech);
    expect(problem("hysteria2://pw@example.com:443?ech=https%3A%2F%2Fdns.example%2Fdns-query")).toBe(ech);
    expect(problem(`hysteria2://pw@example.com:443?ech=${ECH_CONFIG_LIST}`)).toBe("");
    expect(problem("hysteria2://letmein@hy.example.com:443?obfs=gecko&obfs-password=x")).toBe(
      "This link hides its traffic with gecko obfuscation, which the bundled Xray can’t run. Only salamander works, so ask your provider for a link that uses it."
    );
    expect(problem("hysteria2://letmein@hy.example.com:443?obfs=salamander")).toBe(
      "This link turns on salamander obfuscation but has no obfs-password, so it can’t connect. Copy it again from your provider."
    );
    expect(problem("hysteria2://letmein@hy.example.com:443?pinSHA256=not-a-hash")).toBe(
      "The pinSHA256 in this link isn’t a certificate hash (64 hex characters), so the server can’t be checked. Copy it again from your provider."
    );
    expect(problem("hysteria2://letmein@hy.example.com:443?fm=%7Bbroken")).toBe(
      "The fm settings in this link (Xray finalmask JSON) can’t be read. Remove the fm part or copy the link again from your provider."
    );
    // Shadow SSH's choice: the bundled Xray could run these masks.
    expect(problem("hysteria2://letmein@hy.example.com:443?fm=%7B%22udp%22%3A%5B%7B%22type%22%3A%22noise%22%7D%5D%7D")).toBe(
      "The fm settings in this link use noise, which Shadow SSH doesn’t support with Hysteria 2 (only salamander and port hopping). Remove the fm part or ask your provider for another link."
    );
    expect(problem(`hysteria2://letmein@hy.example.com:443?fm=${FM_PACKET_SIZE}`)).toBe(
      "The fm settings in this link use a salamander packetSize, which Shadow SSH doesn’t support with Hysteria 2 (only salamander and port hopping). Remove the fm part or ask your provider for another link."
    );
  });

  it("maps every Hysteria 2 parser message to its own explanation", () => {
    expect(describeLinkProblem("hy2://x", HYSTERIA2_HOST_MESSAGE)).toBe("This hy2:// link has no server address. Copy it again from your provider.");
    expect(describeLinkProblem("hysteria2://x", HYSTERIA2_PORTS_MESSAGE)).toBe(
      "This hysteria2:// link’s ports can’t be read. Ports look like 443 or 443,20000-30000, with at most 64 ranges. Copy it again from your provider."
    );
    expect(describeLinkProblem("hy2://x", INVALID_HYSTERIA2_URI_MESSAGE)).toBe("This hy2:// link is damaged, so it can’t be read. Copy it again from your provider.");
    expect(describeLinkProblem("hy2://x", HYSTERIA2_ECH_MESSAGE)).toBe(
      "The ech value in this link isn’t an ECH config list, so it can’t be used. Copy the link again from your provider."
    );
    for (const message of [HYSTERIA2_HOST_MESSAGE, HYSTERIA2_PORTS_MESSAGE, INVALID_HYSTERIA2_URI_MESSAGE, HYSTERIA2_ECH_MESSAGE]) {
      expect(describeLinkProblem("hysteria2://x", message)).not.toBe(message);
    }
  });

  it("suggests a fix only for a clear typo of a supported scheme", () => {
    expect(suggestScheme("vles://x")).toEqual({ from: "vles", to: "vless" });
    expect(suggestScheme("vlesss://x")).toEqual({ from: "vlesss", to: "vless" });
    expect(suggestScheme("vmes://x")).toEqual({ from: "vmes", to: "vmess" });
    expect(suggestScheme("trojen://x")).toEqual({ from: "trojen", to: "trojan" });
    expect(suggestScheme("vlses://x")).toEqual({ from: "vlses", to: "vless" });
    expect(suggestScheme("hysteri2://x")).toEqual({ from: "hysteri2", to: "hysteria2" });
    expect(suggestScheme("HYSTERIA22://x")).toEqual({ from: "hysteria22", to: "hysteria2" });
    expect(suggestScheme("hysteria://x")).toBeUndefined();
    expect(suggestScheme("hy2://x")).toBeUndefined();
    expect(suggestScheme("hy3://x")).toBeUndefined();
    expect(suggestScheme("h2c://x")).toBeUndefined();
    expect(suggestScheme("ss://x")).toBeUndefined();
    expect(suggestScheme("https://x")).toBeUndefined();
    expect(suggestScheme("vless://x")).toBeUndefined();
    expect(applySchemeFix("  vles://id@host:443#a", "vless")).toBe("  vless://id@host:443#a");
  });

  it("labels import failures and hints at fixes", () => {
    expect(importFailureMessage(UNSUPPORTED_SCHEME_MESSAGE)).toBe("Only vless://, vmess://, trojan:// and hysteria2:// links are supported.");
    expect(importFailureMessage("Invalid VLESS URI.")).toBe("Invalid VLESS URI.");
    expect(importFailureHint("vles://x@y:1")).toEqual({
      hint: "Looks like a typo: vles:// instead of vless://",
      fix: { from: "vles", to: "vless" }
    });
    expect(importFailureHint("ss://abc")).toEqual({ hint: "Shadowsocks links can’t run in Shadow SSH." });
    expect(importFailureHint("hysteria://hy1.example.com:443?auth=x")).toEqual({
      hint: "Hysteria v1 links can’t run in Shadow SSH. Hysteria 2 links (hysteria2:// or hy2://) work."
    });
    expect(importFailureHint("hysteira2://pw@hy.example.com:443")).toEqual({
      hint: "Looks like a typo: hysteira2:// instead of hysteria2://",
      fix: { from: "hysteira2", to: "hysteria2" }
    });
    expect(importFailureHint("hy2://pw@hy.example.com:443?obfs=gecko&obfs-password=x")).toBeUndefined();
    expect(importFailureHint("vless://u@h")).toBeUndefined();
    expect(importFailureHint("vless://u@example.com:443")).toBeUndefined();
    expect(proxyProtocolMark("vless")).toBe("VL");
    expect(proxyProtocolMark("vmess")).toBe("VM");
    expect(proxyProtocolMark("trojan")).toBe("TR");
    expect(proxyProtocolMark("hysteria2")).toBe("HY");
  });
});
