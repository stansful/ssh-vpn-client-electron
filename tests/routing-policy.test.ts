import { describe, expect, it } from "vitest";
import { TrafficPolicy } from "../src/core/routing/traffic-policy.js";
import type { RoutingRule } from "../src/shared/types.js";

describe("traffic policy", () => {
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

  it("applies the shared routing order: rules, local, process, direct list, proxy-all, proxy list", () => {
    const rules: RoutingRule[] = [
      ruleOf("domain", "mail.service.ru"),
      ruleOf("ip", "10.0.0.0/8"),
      ruleOf("domain", "corp.local"),
      ruleOf("process.name", "telegram.exe")
    ];
    const lists = { proxyListDomains: [".ru", "blocked.example"], directListDomains: [".ru"] };
    const split = new TrafficPolicy("selected-rules", rules, lists);
    const full = new TrafficPolicy("proxy-all", rules, lists);

    for (const policy of [split, full]) {
      // 2. A domain or IP rule wins, for the local network too: 10.0.0.0/8 is
      // how a user reaches the network behind the server.
      expect(policy.decide("tcp", { destinationIp: "10.1.2.3" })).toMatchObject({ shouldProxy: true, reason: "ip" });
      expect(policy.decide("tcp", { destinationIp: "::ffff:10.1.2.3", processName: "telegram.exe" })).toMatchObject({ reason: "ip" });
      expect(policy.decide("tcp", { destinationDomain: "wiki.corp.local" })).toMatchObject({ shouldProxy: true, reason: "domain" });
      // ...and beats the direct list.
      expect(policy.decide("tcp", { destinationDomain: "mail.service.ru" })).toMatchObject({ shouldProxy: true, reason: "domain" });
      // 3. A local destination no rule names stays direct, even for a selected process.
      expect(policy.decide("tcp", { destinationIp: "192.168.1.1", processName: "telegram.exe" })).toMatchObject({
        shouldProxy: false,
        blockedReason: "local-destination"
      });
      expect(policy.decide("tcp", { destinationDomain: "nas.local", processName: "telegram.exe" })).toMatchObject({
        shouldProxy: false,
        blockedReason: "local-destination"
      });
      expect(policy.decide("tcp", { destinationIp: "::ffff:192.168.1.1" })).toMatchObject({ blockedReason: "local-destination" });
      // 4. A process rule beats the direct list.
      expect(policy.decide("tcp", { destinationDomain: "news.service.ru", processName: "Telegram.exe" })).toMatchObject({
        shouldProxy: true,
        reason: "process.name"
      });
      // 5. The direct list beats proxy-all and the proxy list.
      expect(policy.decide("tcp", { destinationDomain: "news.service.ru" })).toEqual({
        protocol: "tcp",
        shouldProxy: false,
        reason: "direct-list"
      });
      // 7. The proxy list proxies what nothing else claimed.
      expect(policy.decide("tcp", { destinationDomain: "cdn.blocked.example" })).toMatchObject({ shouldProxy: true });
    }

    // 6 and 8: proxy-all proxies the rest, split routing leaves it direct.
    expect(full.decide("tcp", { destinationDomain: "example.com" })).toMatchObject({ shouldProxy: true, reason: "proxy-all" });
    expect(split.decide("tcp", { destinationDomain: "example.com" })).toMatchObject({ shouldProxy: false, reason: "no-match" });
    expect(split.decide("tcp", { destinationDomain: "cdn.blocked.example" })).toMatchObject({ reason: "proxy-list" });

    // Without a rule for it, the same private address stays direct.
    for (const mode of ["selected-rules", "proxy-all"] as const) {
      const noLanRule = new TrafficPolicy(mode, [ruleOf("process.name", "telegram.exe")], lists);
      expect(noLanRule.decide("tcp", { destinationIp: "10.1.2.3" })).toMatchObject({ shouldProxy: false, blockedReason: "local-destination" });
      expect(noLanRule.decide("tcp", { destinationIp: "10.1.2.3", processName: "telegram.exe" })).toMatchObject({
        shouldProxy: false,
        blockedReason: "local-destination"
      });
    }
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

function ruleOf(type: RoutingRule["type"], value: string): RoutingRule {
  return {
    id: `${type}:${value}`,
    type,
    value,
    enabled: true,
    createdAt: "2026-06-12T00:00:00.000Z",
    updatedAt: "2026-06-12T00:00:00.000Z"
  };
}
