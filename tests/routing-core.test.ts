import { describe, expect, it } from "vitest";
import {
  ipMatchesCidr,
  isLocalDestinationHost,
  isLocalDestinationIp,
  parseCidrRange,
  parseIpAddress,
  parseIpAddressUnmapped,
  unmapIpv4MappedAddress
} from "../src/core/routing/ip-address.js";
import { RoutingMatcher } from "../src/core/routing/routing-matcher.js";
import type { RoutingRule } from "../src/shared/types.js";

describe("routing matcher core", () => {
  it("matches plain and wildcard domains", () => {
    const matcher = new RoutingMatcher("selected-rules", [
      rule("domain", "youtube.com"),
      rule("domain", "*.googlevideo.com")
    ]);

    expect(matcher.match({ destinationDomain: "youtube.com" })).toMatchObject({ shouldProxy: true, reason: "domain" });
    expect(matcher.match({ destinationDomain: "r1---sn.googlevideo.com" })).toMatchObject({ shouldProxy: true, reason: "domain" });
    // A `*.` rule stays subdomain-only so an apex can be excluded deliberately.
    expect(matcher.match({ destinationDomain: "googlevideo.com" })).toMatchObject({ shouldProxy: false, reason: "no-match" });
  });

  // A plain rule used to match the literal host only, so it silently missed
  // `www.` and the API/CDN subdomains nearly every site depends on. That made
  // custom rules look inert next to the curated lists, which always matched
  // a domain together with its subdomains.
  it("covers subdomains of a plain domain rule without matching lookalikes", () => {
    const matcher = new RoutingMatcher("selected-rules", [rule("domain", "godotengine.org")]);

    for (const host of ["godotengine.org", "www.godotengine.org", "docs.godotengine.org", "a.b.godotengine.org"]) {
      expect(matcher.match({ destinationDomain: host })).toMatchObject({ shouldProxy: true, reason: "domain" });
    }
    for (const host of ["notgodotengine.org", "godotengine.org.evil.test", "org", "example.com"]) {
      expect(matcher.match({ destinationDomain: host })).toMatchObject({ shouldProxy: false });
    }
  });

  it("preserves first-rule precedence across exact, wildcard, and duplicate indexed rules", () => {
    const wildcardFirst = rule("domain", "*.example.com", "wildcard-first");
    const exactLater = rule("domain", "api.example.com", "exact-later");
    const duplicateLater = rule("domain", "*.example.com", "duplicate-later");
    const matcher = new RoutingMatcher("selected-rules", [wildcardFirst, exactLater, duplicateLater]);

    expect(matcher.match({ destinationDomain: "api.example.com" }).ruleId).toBe("wildcard-first");
    expect(matcher.summary()).toMatchObject({ enabledRules: 3, domainRules: 3 });

    const exactFirst = new RoutingMatcher("selected-rules", [exactLater, wildcardFirst]);
    expect(exactFirst.match({ destinationDomain: "api.example.com" }).ruleId).toBe("exact-later");
  });

  it("matches a hot exact-domain target in a 10k-rule index", () => {
    const rules = Array.from({ length: 10_000 }, (_, index) =>
      rule("domain", `host-${index}.example.com`, `domain-${index}`)
    );
    const matcher = new RoutingMatcher("selected-rules", rules);

    for (let iteration = 0; iteration < 1000; iteration += 1) {
      expect(matcher.match({ destinationDomain: "host-9999.example.com" }).ruleId).toBe("domain-9999");
    }
  });

  it("matches IPv4 and IPv6 CIDR ranges", () => {
    const matcher = new RoutingMatcher("selected-rules", [
      rule("ip", "142.250.0.0/15"),
      rule("ip", "2a00:1450::/32")
    ]);

    expect(matcher.match({ destinationIp: "142.250.72.14" })).toMatchObject({ shouldProxy: true, reason: "ip" });
    expect(matcher.match({ destinationIp: "142.252.1.1" })).toMatchObject({ shouldProxy: false, reason: "no-match" });
    expect(matcher.match({ destinationIp: "2a00:1450:400f:80d::200e" })).toMatchObject({ shouldProxy: true, reason: "ip" });
  });

  it("matches process names case-insensitively", () => {
    const matcher = new RoutingMatcher("selected-rules", [rule("process.name", "chrome.exe")]);

    expect(matcher.match({ processName: "CHROME.EXE" })).toMatchObject({ shouldProxy: true, reason: "process.name" });
    expect(matcher.match({ processName: "msedge.exe" })).toMatchObject({ shouldProxy: false, reason: "no-match" });
  });

  it("proxies all traffic in proxy-all mode", () => {
    const matcher = new RoutingMatcher("proxy-all", []);

    expect(matcher.match({})).toEqual({ shouldProxy: true, reason: "proxy-all" });
  });

  it("filters invalid enabled rules from matching and reports them separately", () => {
    const matcher = new RoutingMatcher("selected-rules", [
      rule("domain", "valid.example"),
      rule("domain", "not-a-domain"),
      rule("ip", "999.1.1.1/24"),
      rule("process.name", "C:\\Apps\\browser.exe")
    ]);

    expect(matcher.summary()).toMatchObject({
      enabledRules: 1,
      domainRules: 1,
      ipRules: 0,
      processRules: 0,
      invalidRules: 3
    });
    expect(matcher.match({ destinationDomain: "not-a-domain", processName: "C:\\Apps\\browser.exe" })).toMatchObject({
      shouldProxy: false,
      reason: "no-match"
    });
  });

  // The shared routing order puts domain and IP rules first, the local
  // network after them and process rules after that, so a caller can rank the
  // local network and the direct list between the steps.
  it("reports a matching rule ahead of proxy-all, domain and IP rules first", () => {
    const matcher = new RoutingMatcher("proxy-all", [
      rule("domain", "example.com", "domain"),
      rule("ip", "10.0.0.0/8", "lan"),
      rule("process.name", "chrome.exe", "process")
    ]);

    expect(matcher.match({ destinationDomain: "www.example.com", processName: "chrome.exe" })).toEqual({
      shouldProxy: true,
      reason: "domain",
      ruleId: "domain"
    });
    expect(matcher.match({ destinationIp: "10.1.2.3", processName: "chrome.exe" })).toMatchObject({ reason: "ip", ruleId: "lan" });
    expect(matcher.match({ destinationDomain: "other.example", processName: "Chrome.exe" })).toMatchObject({ reason: "process.name" });
    expect(matcher.match({ destinationDomain: "other.example" })).toEqual({ shouldProxy: true, reason: "proxy-all" });
    // The steps on their own, for callers that put something between them.
    expect(matcher.matchDestination({ destinationIp: "10.1.2.3" })).toMatchObject({ reason: "ip", ruleId: "lan" });
    expect(matcher.matchDestination({ destinationIp: "192.168.1.1" })).toBeUndefined();
    expect(matcher.matchProcess("CHROME.EXE")).toMatchObject({ reason: "process.name", ruleId: "process" });
    expect(matcher.matchProcess(undefined)).toBeUndefined();
    expect(matcher.unmatched()).toEqual({ shouldProxy: true, reason: "proxy-all" });
    expect(new RoutingMatcher("selected-rules", []).unmatched()).toEqual({ shouldProxy: false, reason: "no-enabled-rules" });
    expect(new RoutingMatcher("selected-rules", [rule("ip", "10.0.0.0/8")]).unmatched()).toEqual({ shouldProxy: false, reason: "no-match" });
  });

  it("matches an IPv4-mapped IPv6 destination against IPv4 ranges", () => {
    const matcher = new RoutingMatcher("selected-rules", [rule("ip", "142.250.0.0/15")]);

    expect(matcher.match({ destinationIp: "::ffff:142.250.72.14" })).toMatchObject({ shouldProxy: true, reason: "ip" });
    expect(matcher.match({ destinationIp: "[::ffff:8efa:480e]" })).toMatchObject({ shouldProxy: true, reason: "ip" });
    expect(matcher.match({ destinationIp: "::ffff:8.8.8.8" })).toMatchObject({ shouldProxy: false, reason: "no-match" });
  });

  it("reads IPv4-mapped addresses as IPv4 and recognises local destinations", () => {
    expect(parseIpAddressUnmapped("::ffff:192.0.2.7")).toEqual({ version: 4, value: 0xc0000207n });
    expect(parseIpAddressUnmapped("0:0:0:0:0:ffff:c000:207")).toEqual({ version: 4, value: 0xc0000207n });
    expect(parseIpAddressUnmapped("::192.0.2.7")?.version).toBe(6);
    expect(parseIpAddressUnmapped("::ffff:999.0.2.7")).toBeUndefined();
    expect(unmapIpv4MappedAddress("::ffff:c000:207")).toBe("192.0.2.7");
    expect(unmapIpv4MappedAddress("2001:db8::1")).toBe("2001:db8::1");
    expect(unmapIpv4MappedAddress("example.com")).toBe("example.com");

    for (const host of [
      "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.10", "169.254.1.1", "100.64.0.1",
      "100.127.255.255", "0.0.0.0", "::1", "[::1]", "fe80::1", "febf::1", "fc00::1", "fdab:1::2",
      "::ffff:10.0.0.1", "localhost", "LOCALHOST.", "intranet", "printer.local", "nas.home.local"
    ]) {
      expect(isLocalDestinationHost(host), host).toBe(true);
    }
    for (const host of [
      "8.8.8.8", "172.15.0.1", "172.32.0.1", "100.63.255.255", "100.128.0.1", "192.169.0.1", "2001:db8::1",
      "fd::1", "fec0::1", "::ffff:8.8.8.8", "example.com", "local.example.com", ""
    ]) {
      expect(isLocalDestinationHost(host), host).toBe(false);
    }
    expect(isLocalDestinationIp("printer.local")).toBe(false);
  });

  it("parses CIDR ranges to network masks", () => {
    const ip = parseIpAddress("192.168.1.10");
    const cidr = parseCidrRange("192.168.1.0/24");

    expect(ip && cidr ? ipMatchesCidr(ip, cidr) : false).toBe(true);
    expect(parseCidrRange("2a00:1450::/129")).toBeUndefined();
  });
});

function rule(type: RoutingRule["type"], value: string, id = `${type}:${value}`): RoutingRule {
  return {
    id,
    type,
    value,
    enabled: true,
    createdAt: "2026-06-09T00:00:00.000Z",
    updatedAt: "2026-06-09T00:00:00.000Z"
  };
}
