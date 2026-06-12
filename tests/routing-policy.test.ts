import { describe, expect, it } from "vitest";
import { DomainIpCache } from "../src/core/routing/dns-cache.js";
import { TrafficPolicy } from "../src/core/routing/traffic-policy.js";
import type { RoutingRule } from "../src/shared/types.js";

describe("DNS cache and traffic policy", () => {
  it("stores domain-to-IP entries with TTL and reverse lookup", () => {
    const cache = new DomainIpCache();
    cache.set("YouTube.com.", ["1.1.1.1", "1.1.1.1", "2a00:1450::1"], 1000, 10);

    expect(cache.get("youtube.com", 20)).toEqual(["1.1.1.1", "2a00:1450::1"]);
    expect(cache.findDomainsForIp("1.1.1.1", 20)).toEqual(["youtube.com"]);
    expect(cache.get("youtube.com", 1011)).toEqual([]);
  });

  it("blocks UDP when TCP-only policy is configured", () => {
    const policy = new TrafficPolicy("proxy-all", [], false);

    expect(policy.decide("tcp", {})).toMatchObject({ shouldProxy: true, reason: "proxy-all" });
    expect(policy.decide("udp", {})).toMatchObject({ shouldProxy: false, blockedReason: "udp-not-supported" });
  });

  it("applies selected routing rules for TCP", () => {
    const rules: RoutingRule[] = [
      {
        id: "domain",
        type: "domain",
        value: "*.example.com",
        enabled: true,
        createdAt: "2026-06-12T00:00:00.000Z",
        updatedAt: "2026-06-12T00:00:00.000Z"
      }
    ];
    const policy = new TrafficPolicy("selected-rules", rules);

    expect(policy.decide("tcp", { destinationDomain: "api.example.com" })).toMatchObject({ shouldProxy: true, reason: "domain" });
    expect(policy.decide("tcp", { destinationDomain: "example.com" })).toMatchObject({ shouldProxy: false, reason: "no-match" });
  });

  it("bypasses the protected SSH connection to prevent tunnel loops", () => {
    const policy = new TrafficPolicy("proxy-all", [], {
      protectedSshEndpoint: {
        host: "ssh.example.com",
        port: 22
      }
    });

    expect(policy.decide("tcp", { destinationDomain: "ssh.example.com", destinationPort: 22 })).toMatchObject({
      shouldProxy: false,
      blockedReason: "protected-ssh-connection"
    });
    expect(policy.decide("tcp", { destinationDomain: "ssh.example.com", destinationPort: 443 })).toMatchObject({
      shouldProxy: true,
      reason: "proxy-all"
    });
  });
});
