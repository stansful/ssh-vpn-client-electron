import { describe, expect, it } from "vitest";
import {
  hasSelectedRoutingTargets,
  routingMutationAction,
  type RoutingMutationState,
  type SelectedRoutingTargetState
} from "../src/main/app/routing-targets.js";

describe("selected routing targets", () => {
  it("accepts an enabled routing rule", () => {
    expect(
      hasSelectedRoutingTargets(
        state({
          rules: [{ id: "domain", type: "domain", value: "example.com", enabled: true, createdAt: "", updatedAt: "" }]
        })
      )
    ).toBe(true);
  });

  it("accepts enabled proxy-list domains when no explicit rule is enabled", () => {
    expect(hasSelectedRoutingTargets(state({ proxyListEnabled: true, proxyDomains: ["example.com"] }))).toBe(true);
  });

  it("counts a rule for the local network like any other, since it tunnels the network behind the server", () => {
    const lan = [
      { id: "lan", type: "ip" as const, value: "10.8.0.0/16", enabled: true, createdAt: "", updatedAt: "" },
      { id: "nas", type: "domain" as const, value: "nas.local", enabled: true, createdAt: "", updatedAt: "" }
    ];
    for (const rules of [lan, lan.slice(0, 1), lan.slice(1)]) {
      expect(hasSelectedRoutingTargets(state({ rules }))).toBe(true);
      expect(routingMutationAction(mutationState({ rules }), "Connected")).toBe("apply");
    }
    const off = [{ id: "off", type: "ip" as const, value: "192.168.0.0/16", enabled: false, createdAt: "", updatedAt: "" }];
    expect(hasSelectedRoutingTargets(state({ rules: off }))).toBe(false);
  });

  it("rejects disabled or empty targets", () => {
    expect(
      hasSelectedRoutingTargets(
        state({
          rules: [{ id: "disabled", type: "domain", value: "example.com", enabled: false, createdAt: "", updatedAt: "" }],
          proxyListEnabled: false,
          proxyDomains: ["example.org"]
        })
      )
    ).toBe(false);
    expect(hasSelectedRoutingTargets(state({ proxyListEnabled: true, proxyDomains: [] }))).toBe(false);
  });

  it.each([
    ["domain", "not-a-domain"],
    ["ip", "999.1.1.1"],
    ["process.name", "C:\\full\\path.exe"]
  ] as const)("rejects an enabled but invalid %s rule", (type, value) => {
    expect(
      hasSelectedRoutingTargets(
        state({ rules: [{ id: type, type, value, enabled: true, createdAt: "", updatedAt: "" }] })
      )
    ).toBe(false);
  });

  it("rejects invalid proxy-list domains but accepts a later valid domain", () => {
    expect(hasSelectedRoutingTargets(state({ proxyListEnabled: true, proxyDomains: ["http://invalid"] }))).toBe(false);
    expect(
      hasSelectedRoutingTargets(state({ proxyListEnabled: true, proxyDomains: ["http://invalid", ".ru"] }))
    ).toBe(true);
  });

  it.each(["aa..bb", "aa.-bad.com", "aa.bad-.com", "localhost"])(
    "does not treat invalid proxy-list domain %s as a selected target",
    (domain) => {
      expect(hasSelectedRoutingTargets(state({ proxyListEnabled: true, proxyDomains: [domain] }))).toBe(false);
    }
  );

  it("disconnects a connected selected-rules tunnel after the last rule or proxy-list target is removed", () => {
    expect(routingMutationAction(mutationState(), "Connected")).toBe("disconnect");
    expect(routingMutationAction(mutationState(), "Reconnecting")).toBe("disconnect");
  });

  it("does not treat direct-list domains as proxy targets", () => {
    expect(
      routingMutationAction(
        mutationState({
          directListEnabled: true,
          directDomains: ["direct.example.com"]
        }),
        "Connected"
      )
    ).toBe("disconnect");
  });

  it("keeps an already disconnected invalid selection idle and applies valid configurations", () => {
    expect(routingMutationAction(mutationState(), "Disconnected")).toBe("idle");
    expect(routingMutationAction(mutationState({ proxyListEnabled: true, proxyDomains: ["proxy.example.com"] }), "Connected")).toBe("apply");
    expect(routingMutationAction(mutationState({ routingMode: "proxy-all" }), "Connected")).toBe("apply");
  });
});

function state(
  options: {
    rules?: SelectedRoutingTargetState["routingRules"];
    proxyListEnabled?: boolean;
    proxyDomains?: string[];
  } = {}
): SelectedRoutingTargetState {
  return {
    routingRules: options.rules ?? [],
    routingProxyList: {
      enabled: options.proxyListEnabled ?? false,
      sourceUrl: "https://example.com/list.txt",
      domains: options.proxyDomains ?? []
    }
  };
}

function mutationState(
  options: {
    routingMode?: RoutingMutationState["routingMode"];
    rules?: RoutingMutationState["routingRules"];
    proxyListEnabled?: boolean;
    proxyDomains?: string[];
    directListEnabled?: boolean;
    directDomains?: string[];
  } = {}
): RoutingMutationState {
  return {
    routingMode: options.routingMode ?? "selected-rules",
    routingRules: options.rules ?? [],
    routingProxyList: {
      enabled: options.proxyListEnabled ?? false,
      sourceUrl: "https://example.com/proxy.txt",
      domains: options.proxyDomains ?? []
    },
    routingDirectList: {
      enabled: options.directListEnabled ?? false,
      sourceUrl: "https://example.com/direct.txt",
      domains: options.directDomains ?? []
    }
  };
}
