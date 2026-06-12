import { describe, expect, it } from "vitest";
import { parseCidrRange, parseIpAddress, ipMatchesCidr } from "../src/core/routing/ip-address.js";
import { RoutingMatcher } from "../src/core/routing/routing-matcher.js";
import type { RoutingRule } from "../src/shared/types.js";

describe("routing matcher core", () => {
  it("matches exact and wildcard domains", () => {
    const matcher = new RoutingMatcher("selected-rules", [
      rule("domain", "youtube.com"),
      rule("domain", "*.googlevideo.com")
    ]);

    expect(matcher.match({ destinationDomain: "youtube.com" })).toMatchObject({ shouldProxy: true, reason: "domain" });
    expect(matcher.match({ destinationDomain: "r1---sn.googlevideo.com" })).toMatchObject({ shouldProxy: true, reason: "domain" });
    expect(matcher.match({ destinationDomain: "googlevideo.com" })).toMatchObject({ shouldProxy: false, reason: "no-match" });
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

  it("parses CIDR ranges to network masks", () => {
    const ip = parseIpAddress("192.168.1.10");
    const cidr = parseCidrRange("192.168.1.0/24");

    expect(ip && cidr ? ipMatchesCidr(ip, cidr) : false).toBe(true);
    expect(parseCidrRange("2a00:1450::/129")).toBeUndefined();
  });
});

function rule(type: RoutingRule["type"], value: string): RoutingRule {
  return {
    id: `${type}:${value}`,
    type,
    value,
    enabled: true,
    createdAt: "2026-06-09T00:00:00.000Z",
    updatedAt: "2026-06-09T00:00:00.000Z"
  };
}
