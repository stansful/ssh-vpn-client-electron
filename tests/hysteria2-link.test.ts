import { describe, expect, it } from "vitest";
import {
  HYSTERIA2_ECH_MESSAGE,
  HYSTERIA2_FINALMASK_MESSAGE,
  HYSTERIA2_HOST_MESSAGE,
  HYSTERIA2_OBFS_PASSWORD_MESSAGE,
  HYSTERIA2_PIN_MESSAGE,
  HYSTERIA2_PORTS_MESSAGE,
  INVALID_HYSTERIA2_URI_MESSAGE,
  parseHysteria2Link,
  parseHysteriaBandwidth
} from "../src/core/proxy/hysteria2-link.js";

const PIN = "ba88452f1b0c1a3c4d7e6f5a49382716ba88452f1b0c1a3c4d7e6f5a49382716";

describe("Hysteria 2 share links", () => {
  it("reads the official link format", () => {
    const link = parseHysteria2Link(
      "hysteria2://letmein@example.com:8443/?sni=real.example.com&obfs=salamander&obfs-password=gawrgura&pinSHA256=" + PIN + "#Helsinki%20QUIC"
    );

    expect(link).toMatchObject({
      name: "Helsinki QUIC",
      auth: "letmein",
      host: "example.com",
      port: 8443,
      sni: "real.example.com",
      obfsPassword: "gawrgura",
      pinnedCertSha256: [PIN],
      insecure: false
    });
    expect(link.hopPorts).toBeUndefined();
    expect(link.hopInterval).toBeUndefined();
  });

  it("defaults the port to 443, the SNI to the host and the name to the address", () => {
    expect(parseHysteria2Link("hy2://secret@Node.Example.com")).toMatchObject({
      name: "hysteria2-node.example.com:443",
      host: "node.example.com",
      port: 443,
      sni: "node.example.com",
      obfsPassword: undefined,
      pinnedCertSha256: []
    });
  });

  it("decodes userpass auth as one string and keeps an unescaped slash or @ in it", () => {
    expect(parseHysteria2Link("hysteria2://user%40mail:p%40ss@example.com:443").auth).toBe("user@mail:p@ss");
    expect(parseHysteria2Link("hysteria2://user:pass@example.com").auth).toBe("user:pass");
    expect(parseHysteria2Link("hysteria2://a/b@c@example.com:443/?sni=x").auth).toBe("a/b@c");
    expect(parseHysteria2Link("hysteria2://example.com:443").auth).toBe("");
  });

  it("brackets nothing and lower-cases IPv6 hosts, and converts IDNs to punycode", () => {
    expect(parseHysteria2Link("hysteria2://pw@[2001:DB8::1]:443")).toMatchObject({ host: "2001:db8::1", port: 443, sni: "2001:db8::1" });
    expect(parseHysteria2Link("hysteria2://pw@[2001:db8::1]")).toMatchObject({ host: "2001:db8::1", port: 443 });
    expect(parseHysteria2Link("hysteria2://pw@пример.рф:443").host).toBe("xn--e1afmkfd.xn--p1ai");
  });

  it("reads port hopping from the authority, mport and a panel's fm JSON", () => {
    expect(parseHysteria2Link("hysteria2://pw@example.com:443,20000-30000/")).toMatchObject({
      port: 443,
      hopPorts: "443,20000-30000",
      hopInterval: 30
    });
    // Throne writes only the range; reversed ranges are put in order.
    expect(parseHysteria2Link("hysteria2://pw@example.com:30000-20000")).toMatchObject({ port: 20000, hopPorts: "20000-30000" });
    // v2rayN, NekoBox and 3x-ui put the list in mport; sing-box style ":" ranges are accepted.
    expect(parseHysteria2Link("hy2://pw@example.com:443?mport=20000:30000&mportHopInt=10")).toMatchObject({
      port: 443,
      hopPorts: "20000-30000",
      hopInterval: 10
    });
    const fm = encodeURIComponent(JSON.stringify({ quicParams: { udpHop: { ports: "40000-50000", interval: "5-15" } } }));
    expect(parseHysteria2Link(`hysteria2://pw@example.com:443?fm=${fm}`)).toMatchObject({ hopPorts: "40000-50000", hopInterval: "5-15" });
    // A single port is not hopping, even when repeated.
    expect(parseHysteria2Link("hysteria2://pw@example.com:443,443").hopPorts).toBeUndefined();
  });

  it("keeps hop intervals at Xray's minimum of 5 seconds and reads duration suffixes", () => {
    expect(parseHysteria2Link("hysteria2://pw@example.com:1000-2000?hop_interval=2s").hopInterval).toBe(5);
    expect(parseHysteria2Link("hysteria2://pw@example.com:1000-2000?hop_interval=30s&hop_interval_max=60s").hopInterval).toBe("30-60");
    expect(parseHysteria2Link("hysteria2://pw@example.com:1000-2000?hopInterval=bogus").hopInterval).toBe(30);
  });

  it("rejects links without a host or with a broken port list", () => {
    expect(() => parseHysteria2Link("hysteria2://pw@:443")).toThrow(HYSTERIA2_HOST_MESSAGE);
    expect(() => parseHysteria2Link("hysteria2://pw@example.com:0")).toThrow(HYSTERIA2_PORTS_MESSAGE);
    expect(() => parseHysteria2Link("hysteria2://pw@example.com:443,")).toThrow(HYSTERIA2_PORTS_MESSAGE);
    expect(() => parseHysteria2Link("hysteria2://pw@example.com:70000")).toThrow(HYSTERIA2_PORTS_MESSAGE);
    expect(() => parseHysteria2Link("hysteria2://pw@example.com:abc")).toThrow(HYSTERIA2_PORTS_MESSAGE);
    expect(() => parseHysteria2Link("hysteria2://pw@example.com:443?mport=20000-70000")).toThrow(HYSTERIA2_PORTS_MESSAGE);
    expect(() => parseHysteria2Link(`hysteria2://pw@${"a".repeat(254)}:443`)).toThrow(INVALID_HYSTERIA2_URI_MESSAGE);
    expect(() => parseHysteria2Link("hysteria2://pw@[2001:db8::1")).toThrow(INVALID_HYSTERIA2_URI_MESSAGE);
    expect(() => parseHysteria2Link("hysteria2://pw@exa mple.com")).toThrow(INVALID_HYSTERIA2_URI_MESSAGE);
    expect(() => parseHysteria2Link("vless://pw@example.com:443")).toThrow(INVALID_HYSTERIA2_URI_MESSAGE);
  });

  it("only accepts salamander obfuscation, with a password", () => {
    expect(parseHysteria2Link("hysteria2://pw@example.com?obfs-password=nekobox").obfsPassword).toBe("nekobox");
    expect(parseHysteria2Link("hysteria2://pw@example.com?obfs=none&obfs-password=x").obfsPassword).toBeUndefined();
    expect(() => parseHysteria2Link("hysteria2://pw@example.com?obfs=salamander")).toThrow(HYSTERIA2_OBFS_PASSWORD_MESSAGE);
    expect(() => parseHysteria2Link("hysteria2://pw@example.com?obfs=gecko&obfs-password=x")).toThrow(
      "Unsupported Hysteria 2 obfuscation: gecko. Only salamander works."
    );
    // The message repeats the link's value, but never a whole hostile line of it.
    expect(() => parseHysteria2Link(`hysteria2://pw@example.com?obfs=${"x".repeat(60_000)}&obfs-password=x`)).toThrow(
      `Unsupported Hysteria 2 obfuscation: ${"x".repeat(40)}…. Only salamander works.`
    );
  });

  it("normalises certificate pins written as openssl hex, base64 or a list", () => {
    const opensslForm = PIN.toUpperCase().match(/../gu)?.join(":") ?? "";
    const base64 = btoa(String.fromCharCode(...(PIN.match(/../gu) ?? []).map((byte) => parseInt(byte, 16))));
    const other = "1".repeat(64);
    expect(parseHysteria2Link(`hysteria2://pw@example.com?pinSHA256=${opensslForm}`).pinnedCertSha256).toEqual([PIN]);
    expect(parseHysteria2Link(`hysteria2://pw@example.com?pinSHA256=${encodeURIComponent(base64)}`).pinnedCertSha256).toEqual([PIN]);
    expect(parseHysteria2Link(`hysteria2://pw@example.com?pinSHA256=${PIN},${other}&pcs=${PIN}`).pinnedCertSha256).toEqual([PIN, other]);
    expect(() => parseHysteria2Link("hysteria2://pw@example.com?pinSHA256=deadbeef")).toThrow(HYSTERIA2_PIN_MESSAGE);
  });

  it("records insecure=1 without pretending it can be honoured", () => {
    expect(parseHysteria2Link("hysteria2://pw@example.com?insecure=1").insecure).toBe(true);
    expect(parseHysteria2Link("hysteria2://pw@example.com?allowInsecure=true").insecure).toBe(true);
    expect(parseHysteria2Link("hysteria2://pw@example.com?insecure=0").insecure).toBe(false);
  });

  it("reads Hysteria bandwidth: bare numbers are Mbps, units are decimal, tiny rates mean BBR", () => {
    expect(parseHysteriaBandwidth("100")).toBe("100000000 bps");
    expect(parseHysteriaBandwidth("30 Mbps")).toBe("30000000 bps");
    expect(parseHysteriaBandwidth("1gbps")).toBe("1000000000 bps");
    expect(parseHysteriaBandwidth("0")).toBeUndefined();
    expect(parseHysteriaBandwidth("100 kbps")).toBeUndefined();
    expect(parseHysteriaBandwidth("fast")).toBeUndefined();
    expect(parseHysteria2Link("hysteria2://pw@example.com?up=50&downmbps=100")).toMatchObject({
      brutalUp: "50000000 bps",
      brutalDown: "100000000 bps"
    });
  });

  it("takes salamander, congestion and QUIC tuning from fm, letting link keys win", () => {
    const fm = encodeURIComponent(JSON.stringify({
      udp: [{ type: "salamander", settings: { password: "from-fm" } }],
      quicParams: { congestion: "BBR", brutalUp: "60 mbps", maxIdleTimeout: 60, keepAlivePeriod: 1, debug: true }
    }));
    expect(parseHysteria2Link(`hysteria2://pw@example.com?fm=${fm}`)).toMatchObject({
      obfsPassword: "from-fm",
      congestion: "bbr",
      brutalUp: "60 mbps",
      quic: { maxIdleTimeout: 60 }
    });
    expect(parseHysteria2Link(`hysteria2://pw@example.com?fm=${fm}`).quic).not.toHaveProperty("keepAlivePeriod");
    expect(parseHysteria2Link(`hysteria2://pw@example.com?obfs-password=link&up=10&fm=${fm}`)).toMatchObject({
      obfsPassword: "link",
      brutalUp: "10000000 bps"
    });
  });

  it("drops force-brutal without an upload rate and rejects fm it can't run", () => {
    const forceBrutal = encodeURIComponent(JSON.stringify({ quicParams: { congestion: "force-brutal" } }));
    expect(parseHysteria2Link(`hysteria2://pw@example.com?fm=${forceBrutal}`).congestion).toBeUndefined();
    expect(() => parseHysteria2Link("hysteria2://pw@example.com?fm=%7Bnot-json")).toThrow(HYSTERIA2_FINALMASK_MESSAGE);
    expect(() => parseHysteria2Link(`hysteria2://pw@example.com?fm=${encodeURIComponent('{"udp":[{"type":"noise"}]}')}`)).toThrow(
      "Unsupported Hysteria 2 finalmask type: noise."
    );
    expect(() => parseHysteria2Link(
      `hysteria2://pw@example.com?fm=${encodeURIComponent('{"udp":[{"type":"salamander","settings":{"password":"x","packetSize":"512-1200"}}]}')}`
    )).toThrow("Unsupported Hysteria 2 finalmask type: salamander with packetSize.");
  });

  it("gives hysteria2:// and hy2:// spellings of one server the same canonical form", () => {
    const canonical = (link: string) => parseHysteria2Link(link).canonical;
    expect(canonical("hy2://pw@example.com?sni=a&obfs-password=b#n")).toBe(canonical("HYSTERIA2://pw@Example.com:443/?obfs-password=b&sni=a#n"));
    expect(canonical("hysteria2://user:one@example.com")).not.toBe(canonical("hysteria2://user:two@example.com"));
    expect(canonical("hysteria2://pw@example.com:443,5000-6000")).not.toBe(canonical("hysteria2://pw@example.com:443"));
  });

  it("drops INCY's server description from the name", () => {
    expect(parseHysteria2Link("hysteria2://pw@example.com#Tokyo%201?serverDescription=aGVsbG8=").name).toBe("Tokyo 1");
  });

  it("sorts and merges hop ranges, and refuses lists Xray would expand into gigabytes", () => {
    expect(parseHysteria2Link("hysteria2://pw@example.com:20000-30000,443,25000-35000,35001-36000,443").hopPorts).toBe("443,20000-36000");
    // The dial port is the first one written, not the lowest.
    expect(parseHysteria2Link("hysteria2://pw@example.com:20000-30000,443").port).toBe(20000);
    const repeated = (count: number) => Array.from({ length: count }, () => "1-65535").join(",");
    expect(parseHysteria2Link(`hy2://pw@example.com:443?mport=${repeated(250)}`).hopPorts).toBe("1-65535");
    expect(() => parseHysteria2Link(`hy2://pw@example.com:443?mport=${repeated(8000)}`)).toThrow(HYSTERIA2_PORTS_MESSAGE);
    const scattered = Array.from({ length: 65 }, (_, index) => String(1000 + index * 2)).join(",");
    expect(() => parseHysteria2Link(`hy2://pw@example.com:443?mport=${scattered}`)).toThrow(HYSTERIA2_PORTS_MESSAGE);
  });

  it("reads hopping from a newer Xray udphop mask in fm, after the link's own lists", () => {
    const fm = (mask: unknown) => encodeURIComponent(JSON.stringify({ udp: [mask, { type: "salamander", settings: { password: "s" } }] }));
    const udphop = { type: "UDPHOP", settings: { mode: "intervallocal", interval: "10-20", remotePorts: "20000:30000" } };
    expect(parseHysteria2Link(`hy2://pw@example.com:443?fm=${fm(udphop)}`)).toMatchObject({
      hopPorts: "20000-30000",
      hopInterval: "10-20",
      obfsPassword: "s"
    });
    expect(parseHysteria2Link(`hy2://pw@example.com:443,5000-6000?fm=${fm(udphop)}`).hopPorts).toBe("443,5000-6000");
    expect(parseHysteria2Link(`hy2://pw@example.com:443?mport=7000-8000&fm=${fm(udphop)}`)).toMatchObject({ hopPorts: "7000-8000", hopInterval: "10-20" });
  });

  it("only passes a base64 ECHConfigList as ech, never a DNS server for Xray to query", () => {
    const list = btoa(String.fromCharCode(0, 3, 0xfe, 0x0d, 0));
    expect(parseHysteria2Link(`hy2://pw@example.com?ech=${encodeURIComponent(list)}`).echConfigList).toBe(list);
    for (const ech of ["udp://127.0.0.1:53", "https://1.1.1.1/dns-query", "probe.example+https://1.1.1.1/dns-query", "AAAA"]) {
      expect(() => parseHysteria2Link(`hy2://pw@example.com?ech=${encodeURIComponent(ech)}`)).toThrow(HYSTERIA2_ECH_MESSAGE);
    }
  });

  it("stays fast on hostile 64 KB values from untrusted lists", () => {
    const filler = "+".repeat(32_000);
    const links = [
      `hy2://pw@example.com:443,5000-6000?hop_interval=1${filler}-1${filler}!`,
      `hy2://pw@example.com?up=1${"+".repeat(64_000)}!`,
      `hy2://pw@example.com?down=1${" ".repeat(64_000)}x`,
      `hy2://pw@example.com:1-2?fm=${encodeURIComponent(JSON.stringify({ quicParams: { brutalUp: `1${" ".repeat(60_000)}!`, udpHop: { interval: `1${" ".repeat(30_000)}-${" ".repeat(30_000)}x` } } }))}`,
      `hy2://pw@example.com?mport=1${" ".repeat(64_000)}x`,
      `hy2://pw@example.com:443,${"1 ".repeat(30_000)}x`
    ];
    for (const link of links) {
      const started = performance.now();
      try {
        parseHysteria2Link(link);
      } catch {
        // Rejecting is fine; hanging is not.
      }
      expect(performance.now() - started).toBeLessThan(200);
    }
    const started = performance.now();
    expect(() => parseHysteria2Link(`hy2://pw@example.com?pinSHA256=${"=".repeat(64_000)}x`)).toThrow(HYSTERIA2_PIN_MESSAGE);
    expect(performance.now() - started).toBeLessThan(200);
  });
});
