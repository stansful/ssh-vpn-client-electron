import { describe, expect, it } from "vitest";
import { withShareLinkName } from "../src/core/proxy/share-link-name.js";
import { parseProxyShareLink } from "../src/core/proxy/share-link-parser.js";

const VLESS = "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&security=tls&path=%2Fws&flow=xtls-rprx-vision#Netherlands";
const TROJAN = "trojan://secret@trojan.example.com:443?security=tls&type=grpc#trojan-demo";
const HYSTERIA2 = "hysteria2://letmein@example.com:443,20000-30000/?sni=real.example.com&insecure=1#Helsinki";
const HY2 = "hy2://pw@example.com?sni=a#Old%20name?serverDescription=Fast%20node%20%231";

const VMESS_PAYLOAD = {
  v: "2",
  ps: "🚀 Fast",
  add: "vmess.example.com",
  port: "8443",
  id: "22222222-2222-4222-8222-222222222222",
  aid: "0",
  net: "ws",
  host: "cdn.example.com",
  path: "/ray?ed=2048",
  tls: "tls",
  sni: "cdn.example.com"
};

const NAMES = ["Home office", "Москва 1", "🚀 Tokyo 🗼", "a#b", "100% up", "who? me", "R&D", "eu/west"];

/** The parsed profile minus what a rename is meant to change. */
function parsedWithoutName(link: string): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(parseProxyShareLink(link)).filter(([key]) => key !== "name" && key !== "rawUri" && key !== "fingerprint")
  );
}

function vmessLink(payload: Record<string, unknown>, flavour: { urlSafe: boolean; padded: boolean }, scheme = "vmess://"): string {
  let body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
  if (flavour.urlSafe) {
    body = body.replace(/\+/gu, "-").replace(/\//gu, "_");
  }
  return `${scheme}${flavour.padded ? body : body.replace(/=+$/u, "")}`;
}

function vmessBody(link: string): string {
  return link.replace(/^vmess:\/\//iu, "");
}

function vmessJson(link: string): string {
  return Buffer.from(vmessBody(link).replace(/-/gu, "+").replace(/_/gu, "/"), "base64").toString("utf8");
}

describe("share-link name rewriter", () => {
  it.each([
    ["vless", VLESS],
    ["trojan", TROJAN],
    ["hysteria2", HYSTERIA2],
    ["hy2", HY2],
    ["vmess", vmessLink(VMESS_PAYLOAD, { urlSafe: false, padded: true })]
  ])("writes any name into a %s link and changes nothing else the parser reads", (_scheme, link) => {
    for (const name of NAMES) {
      const renamed = withShareLinkName(link, name);

      expect(parseProxyShareLink(renamed).name).toBe(name);
      expect(parsedWithoutName(renamed)).toEqual(parsedWithoutName(link));
    }
  });

  it("replaces the vless and trojan fragment with the encoded name", () => {
    expect(withShareLinkName(VLESS, "Home office")).toBe(VLESS.replace("#Netherlands", "#Home%20office"));
    expect(withShareLinkName(TROJAN, "a#b?c&d/e 100%")).toBe(TROJAN.replace("#trojan-demo", "#a%23b%3Fc%26d%2Fe%20100%25"));
    // Everything after the first "#" is the name, a second "#" included.
    expect(withShareLinkName("trojan://secret@example.com:443#one#two", "Москва")).toBe(
      "trojan://secret@example.com:443#%D0%9C%D0%BE%D1%81%D0%BA%D0%B2%D0%B0"
    );
  });

  it("adds a fragment to links that have none", () => {
    expect(withShareLinkName("vless://id@example.com:443?security=tls", "Netherlands")).toBe("vless://id@example.com:443?security=tls#Netherlands");
    expect(withShareLinkName("trojan://secret@example.com:443#", "R&D")).toBe("trojan://secret@example.com:443#R%26D");
    expect(withShareLinkName("hy2://pw@example.com", "🚀 Fast")).toBe("hy2://pw@example.com#%F0%9F%9A%80%20Fast");
  });

  it("keeps the Hysteria 2 scheme and a ?serverDescription= tail exactly", () => {
    expect(withShareLinkName(HY2, "New name")).toBe("hy2://pw@example.com?sni=a#New%20name?serverDescription=Fast%20node%20%231");
    expect(withShareLinkName(HYSTERIA2, "Home office")).toBe(HYSTERIA2.replace("#Helsinki", "#Home%20office"));
    expect(withShareLinkName("hysteria2://pw@example.com#?serverDescription=x", "Riga")).toBe("hysteria2://pw@example.com#Riga?serverDescription=x");
    // A name that looks like the tail is encoded, so it can't split.
    const tricky = withShareLinkName(HY2, "a?serverDescription=b");
    expect(tricky).toBe("hy2://pw@example.com?sni=a#a%3FserverDescription%3Db?serverDescription=Fast%20node%20%231");
    expect(parseProxyShareLink(tricky).name).toBe("a?serverDescription=b");
  });

  it.each([
    { urlSafe: false, padded: true },
    { urlSafe: false, padded: false },
    { urlSafe: true, padded: true },
    { urlSafe: true, padded: false }
  ])("sets vmess ps and keeps the base64 flavour %o and the key order", (flavour) => {
    // Both payloads need padding and use "+" or "/", so every flavour shows in the output.
    expect(Buffer.from(JSON.stringify(VMESS_PAYLOAD)).toString("base64")).toMatch(/[+/].*=$/u);
    expect(Buffer.from(JSON.stringify({ ...VMESS_PAYLOAD, ps: "Tokyo 🗼" })).toString("base64")).toMatch(/[+/].*=$/u);
    const link = vmessLink(VMESS_PAYLOAD, flavour);

    const renamed = withShareLinkName(link, "Tokyo 🗼");

    expect(renamed).toBe(vmessLink({ ...VMESS_PAYLOAD, ps: "Tokyo 🗼" }, flavour));
    expect(vmessBody(renamed)).toMatch(flavour.urlSafe ? /^[A-Za-z0-9_-]+=*$/u : /^[A-Za-z0-9+/]+=*$/u);
    expect(vmessBody(renamed).includes("=")).toBe(flavour.padded);
    expect(Object.keys(JSON.parse(vmessJson(renamed)))).toEqual(Object.keys(VMESS_PAYLOAD));
  });

  it("adds ps last to a vmess payload without one, and keeps the scheme's spelling", () => {
    const withoutPs: Record<string, unknown> = { ...VMESS_PAYLOAD };
    delete withoutPs.ps;
    const link = vmessLink(withoutPs, { urlSafe: false, padded: true }, "VMess://");

    const renamed = withShareLinkName(link, "Riga");

    expect(renamed.startsWith("VMess://")).toBe(true);
    expect(JSON.parse(vmessJson(renamed))).toEqual({ ...withoutPs, ps: "Riga" });
    expect(Object.keys(JSON.parse(vmessJson(renamed))).at(-1)).toBe("ps");
  });

  it("drops whitespace the parser ignores in a vmess payload and pads one that needed none", () => {
    const body = vmessBody(vmessLink({ ...VMESS_PAYLOAD, ps: "Helsinki" }, { urlSafe: false, padded: true }));
    expect(body.length % 4).toBe(0);
    const link = `vmess://${body.slice(0, 20)} ${body.slice(20)} `;

    const renamed = withShareLinkName(link, "Tokyo 🗼");

    expect(renamed).toBe(vmessLink({ ...VMESS_PAYLOAD, ps: "Tokyo 🗼" }, { urlSafe: false, padded: true }));
    expect(parsedWithoutName(renamed)).toEqual(parsedWithoutName(link));
  });

  it("returns the link byte for byte when it already carries the name", () => {
    const vmess = `${vmessLink(VMESS_PAYLOAD, { urlSafe: true, padded: false })} `;
    expect(withShareLinkName(vmess, "🚀 Fast")).toBe(vmess);
    expect(withShareLinkName("vless://id@example.com:443#Caf%C3%A9", "Café")).toBe("vless://id@example.com:443#Caf%C3%A9");
    expect(withShareLinkName(HY2, "Old name")).toBe(HY2);
    // The parser's fallback name counts: a nameless link stays nameless.
    expect(withShareLinkName("vless://id@example.com:443", "vless-example.com:443")).toBe("vless://id@example.com:443");
  });

  it("changes the fingerprint with the name, so only the original link is ever stored", () => {
    for (const link of [VLESS, TROJAN, HYSTERIA2, HY2, vmessLink(VMESS_PAYLOAD, { urlSafe: false, padded: true })]) {
      expect(parseProxyShareLink(withShareLinkName(link, "Home office")).fingerprint).not.toBe(parseProxyShareLink(link).fingerprint);
    }
  });

  it("throws for an empty name, an unreadable link and a name the parser would read back differently", () => {
    expect(() => withShareLinkName(VLESS, "")).toThrow("Profile name is empty.");
    expect(() => withShareLinkName(VLESS, "   ")).toThrow("Profile name is empty.");
    expect(() => withShareLinkName("tuic://x@example.com:443", "Riga")).toThrow(/Only vless/u);
    expect(() => withShareLinkName(VLESS, " Riga ")).toThrow("Couldn’t write the name into the vless link.");
  });
});
