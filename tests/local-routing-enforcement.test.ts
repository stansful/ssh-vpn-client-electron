import { describe, expect, it, vi } from "vitest";
import {
  HOST_RESOLUTION_TIMEOUT_MS,
  LocalRoutingEnforcer,
  MAX_LOGGED_DECISIONS_PER_DIRECTION,
  RoutingDecisionLog,
  describeDestination,
  describeRoutingDecision,
  type LocalRoutingContext,
  type LocalRoutingEnforcerOptions
} from "../src/service/local-routing-enforcement.js";
import type { ProcessAttribution } from "../src/service/process-attribution.js";
import type { RoutingRule } from "../src/shared/types.js";

const TARGET_APP_PORT = 41_001;
const OTHER_APP_PORT = 41_002;

describe("local routing enforcement", () => {
  // A process rule means "route everything this application sends". Anything
  // that can quietly carve a hole in that - most easily the curated direct
  // list, which the PAC would otherwise apply before the listener ever sees
  // the connection - defeats the point of the rule.
  it("routes every destination of a selected process into the tunnel", async () => {
    const enforcer = createEnforcer();
    const context = createContext();

    for (const host of [
      "cdn.telegram-cdn.test",
      "gosuslugi.ru",
      "lk.gosuslugi.ru",
      "yandex.net",
      "8.8.8.8",
      "some.random.example"
    ]) {
      const decision = await enforcer.decide(context, { host, port: 443 }, originator(TARGET_APP_PORT));
      expect(decision, `${host} must be tunnelled`).toMatchObject({ shouldProxy: true, reason: "process.name" });
    }
  });

  it("still excludes the transport's own endpoint from a selected process", async () => {
    const enforcer = createEnforcer();
    const context = createContext();

    // Routing the transport into the tunnel it carries would deadlock it.
    const decision = await enforcer.decide(context, { host: "srv.example.com", port: 22 }, originator(TARGET_APP_PORT));
    expect(decision).toMatchObject({ shouldProxy: false, reason: "protected-ssh-connection" });
  });

  it("keeps the normal rule precedence for every other process", async () => {
    const enforcer = createEnforcer();
    const context = createContext();
    const decide = (host: string): Promise<{ shouldProxy: boolean; reason: string }> =>
      enforcer.decide(context, { host, port: 443 }, originator(OTHER_APP_PORT));

    await expect(decide("www.youtube.com")).resolves.toMatchObject({ shouldProxy: true, reason: "domain" });
    await expect(decide("static.rutracker.org")).resolves.toMatchObject({ shouldProxy: true, reason: "proxy-list" });
    await expect(decide("lk.gosuslugi.ru")).resolves.toMatchObject({ shouldProxy: false, reason: "direct-list" });
    await expect(decide("unrelated.example")).resolves.toMatchObject({ shouldProxy: false, reason: "no-match" });
  });

  it("only enforces locally when a process rule and attribution are both present", async () => {
    const withoutProcessRule: LocalRoutingContext = {
      ...createContext(),
      routingRules: [domainRule()]
    };
    await expect(createEnforcer().isEnforceable(withoutProcessRule, "win32")).resolves.toBe(false);
    await expect(createEnforcer().isEnforceable(createContext(), "win32")).resolves.toBe(true);
    // The PAC-learning fallback stays in charge where attribution cannot run.
    await expect(createEnforcer().isEnforceable(createContext(), "darwin")).resolves.toBe(false);
    await expect(createEnforcer({ available: false }).isEnforceable(createContext(), "win32")).resolves.toBe(false);
  });
});

describe("local routing enforcement follows the shared routing order", () => {
  it("keeps local and private destinations direct, even for a selected process", async () => {
    const enforcer = createEnforcer();
    const context = createContext();

    for (const host of [
      "10.0.0.5",
      "192.168.1.1",
      "172.20.3.4",
      "100.100.1.1",
      "169.254.10.10",
      "127.0.0.1",
      "[::1]",
      "[fe80::1]",
      "[fd00::5]",
      "::ffff:192.168.1.1",
      "localhost",
      "intranet",
      "printer.local"
    ]) {
      const decision = await enforcer.decide(context, { host, port: 443 }, originator(TARGET_APP_PORT));
      expect(decision, `${host} must stay direct`).toMatchObject({ shouldProxy: false, reason: "local-destination" });
    }
  });

  it("lets a user rule for the local network win over it, for every process", async () => {
    // 10.0.0.0/8 reaches the network behind the server: an explicit rule wins.
    const lookups: string[] = [];
    const enforcer = createEnforcer({
      resolveHost: async (host) => {
        lookups.push(host);
        return host === "nas" ? ["10.1.2.3"] : ["192.168.1.5"];
      }
    });
    const context: LocalRoutingContext = {
      ...createContext(),
      routingRules: [
        ...createContext().routingRules,
        { id: "lan", type: "ip", value: "10.0.0.0/8", enabled: true, createdAt: "", updatedAt: "" },
        { id: "corp", type: "domain", value: "corp.local", enabled: true, createdAt: "", updatedAt: "" }
      ]
    };
    for (const port of [OTHER_APP_PORT, TARGET_APP_PORT]) {
      const decide = (host: string): Promise<{ shouldProxy: boolean; reason: string }> =>
        enforcer.decide(context, { host, port: 445 }, originator(port));
      await expect(decide("10.1.2.3")).resolves.toMatchObject({ shouldProxy: true, reason: "ip" });
      await expect(decide("::ffff:10.1.2.3")).resolves.toMatchObject({ shouldProxy: true, reason: "ip" });
      await expect(decide("wiki.corp.local")).resolves.toMatchObject({ shouldProxy: true, reason: "domain" });
      // A local name the rule covers by the address it resolves to.
      await expect(decide("nas")).resolves.toMatchObject({ shouldProxy: true, reason: "ip" });
      // The rest of the local network stays direct, the selected process's too.
      await expect(decide("192.168.1.1")).resolves.toMatchObject({ shouldProxy: false, reason: "local-destination" });
      await expect(decide("printer.local")).resolves.toMatchObject({ shouldProxy: false, reason: "local-destination" });
    }
    expect(lookups).toEqual(["nas", "printer.local"]);

    // Without the rule, 10.1.2.3 stays direct.
    await expect(createEnforcer().decide(createContext(), { host: "10.1.2.3", port: 445 }, originator(TARGET_APP_PORT))).resolves.toMatchObject({
      shouldProxy: false,
      reason: "local-destination"
    });
  });

  it("tells the plain SSH listener which local destinations a user rule names", async () => {
    const enforcer = createEnforcer({ resolveHost: async (host) => (host === "nas" ? ["10.1.2.3"] : ["192.168.1.5"]) });
    const rules: RoutingRule[] = [
      { id: "lan", type: "ip", value: "10.0.0.0/8", enabled: true, createdAt: "", updatedAt: "" },
      { id: "corp", type: "domain", value: "corp.local", enabled: true, createdAt: "", updatedAt: "" },
      { id: "p", type: "process.name", value: "telegram.exe", enabled: true, createdAt: "", updatedAt: "" }
    ];
    for (const host of ["10.1.2.3", "[::ffff:10.1.2.3]", "wiki.corp.local", "nas"]) {
      await expect(enforcer.matchesUserRule(rules, host), host).resolves.toBe(true);
    }
    for (const host of ["192.168.1.1", "printer.local", "localhost"]) {
      await expect(enforcer.matchesUserRule(rules, host), host).resolves.toBe(false);
    }
    await expect(enforcer.matchesUserRule([], "10.1.2.3")).resolves.toBe(false);
  });

  it("lets a user rule beat the direct list, and the direct list beat the proxy list", async () => {
    const enforcer = createEnforcer();
    const context: LocalRoutingContext = {
      ...createContext(),
      routingRules: [
        ...createContext().routingRules,
        { id: "d2", type: "domain", value: "ozon.ru", enabled: true, createdAt: "", updatedAt: "" }
      ],
      // A name on both lists: "Russian services" is consulted first.
      routingProxyDomains: ["rutracker.org", "both.example"],
      routingDirectDomains: ["gosuslugi.ru", "ozon.ru", "both.example"]
    };
    const decide = (host: string): Promise<{ shouldProxy: boolean; reason: string }> =>
      enforcer.decide(context, { host, port: 443 }, originator(OTHER_APP_PORT));

    await expect(decide("www.ozon.ru")).resolves.toMatchObject({ shouldProxy: true, reason: "domain" });
    await expect(decide("cdn.both.example")).resolves.toMatchObject({ shouldProxy: false, reason: "direct-list" });
  });

  it("keeps the direct list direct in full tunnel", async () => {
    const enforcer = createEnforcer();
    const context: LocalRoutingContext = { ...createContext(), routingMode: "proxy-all" };
    const decide = (host: string): Promise<{ shouldProxy: boolean; reason: string }> =>
      enforcer.decide(context, { host, port: 443 }, originator(OTHER_APP_PORT));

    await expect(decide("lk.gosuslugi.ru")).resolves.toMatchObject({ shouldProxy: false, reason: "direct-list" });
    await expect(decide("unrelated.example")).resolves.toMatchObject({ shouldProxy: true, reason: "proxy-all" });
    // The selected process still wins over the direct list.
    await expect(enforcer.decide(context, { host: "gosuslugi.ru", port: 443 }, originator(TARGET_APP_PORT))).resolves.toMatchObject({
      shouldProxy: true,
      reason: "process.name"
    });
  });
});

describe("local routing enforcement matches IP rules against hostnames", () => {
  // A connection reaches the listener by name. Matching IP rules against
  // literal addresses only meant that one app rule silently switched every
  // IP rule off for browser traffic, while the PAC and the TUN adapter kept
  // matching them.
  function ipContext(): LocalRoutingContext {
    return {
      ...createContext(),
      routingRules: [
        ...createContext().routingRules,
        { id: "i1", type: "ip", value: "142.250.0.0/15", enabled: true, createdAt: "", updatedAt: "" }
      ]
    };
  }

  it("tunnels a hostname whose address falls under an IP rule, ahead of the direct list", async () => {
    const lookups: string[] = [];
    const enforcer = createEnforcer({
      resolveHost: async (host) => {
        lookups.push(host);
        return host === "www.google.com" || host === "maps.gosuslugi.ru" ? ["2a00:1450::1", "142.250.74.36"] : ["203.0.113.80"];
      }
    });
    const context = ipContext();
    const decide = (host: string): Promise<{ shouldProxy: boolean; reason: string }> =>
      enforcer.decide(context, { host, port: 443 }, originator(OTHER_APP_PORT));

    await expect(decide("www.google.com")).resolves.toMatchObject({ shouldProxy: true, reason: "ip" });
    await expect(decide("maps.gosuslugi.ru")).resolves.toMatchObject({ shouldProxy: true, reason: "ip" });
    await expect(decide("unrelated.example")).resolves.toMatchObject({ shouldProxy: false, reason: "no-match" });
    // A name a rule already decides, or a selected process, needs no lookup.
    await expect(decide("www.youtube.com")).resolves.toMatchObject({ shouldProxy: true, reason: "domain" });
    await enforcer.decide(context, { host: "telegram.example", port: 443 }, originator(TARGET_APP_PORT));
    // Answers are reused for a while instead of asked per socket.
    await decide("www.google.com");
    expect(lookups).toEqual(["www.google.com", "maps.gosuslugi.ru", "unrelated.example"]);
  });

  it("asks again once the answer is old", async () => {
    let clock = 0;
    const resolveHost = vi.fn(async () => ["142.250.74.36"]);
    const enforcer = createEnforcer({ resolveHost, now: () => clock });
    const context = ipContext();
    await enforcer.decide(context, { host: "www.google.com", port: 443 }, originator(OTHER_APP_PORT));
    clock += 29_000;
    await enforcer.decide(context, { host: "www.google.com", port: 443 }, originator(OTHER_APP_PORT));
    expect(resolveHost).toHaveBeenCalledTimes(1);
    clock += 2_000;
    await enforcer.decide(context, { host: "www.google.com", port: 443 }, originator(OTHER_APP_PORT));
    expect(resolveHost).toHaveBeenCalledTimes(2);
  });

  it("does not keep a connection waiting on a resolver that does not answer", async () => {
    vi.useFakeTimers();
    try {
      const enforcer = createEnforcer({ resolveHost: () => new Promise<string[]>(() => undefined) });
      const decision = enforcer.decide(ipContext(), { host: "www.google.com", port: 443 }, originator(OTHER_APP_PORT));
      await vi.advanceTimersByTimeAsync(HOST_RESOLUTION_TIMEOUT_MS);
      await expect(decision).resolves.toMatchObject({ shouldProxy: false, reason: "no-match" });
    } finally {
      vi.useRealTimers();
    }
  });

  it("never resolves when no IP rule could match", async () => {
    const resolveHost = vi.fn(async () => ["142.250.74.36"]);
    const enforcer = createEnforcer({ resolveHost });
    await enforcer.decide(createContext(), { host: "unrelated.example", port: 443 }, originator(OTHER_APP_PORT));
    expect(resolveHost).not.toHaveBeenCalled();
  });

  it("reads an IPv4-mapped IPv6 target as the IPv4 address it carries", async () => {
    const enforcer = createEnforcer({ resolveHost: async () => [] });
    const decision = await enforcer.decide(ipContext(), { host: "[::ffff:142.250.74.36]", port: 443 }, originator(OTHER_APP_PORT));
    expect(decision).toMatchObject({ shouldProxy: true, reason: "ip" });
    expect(describeDestination("::ffff:142.250.74.36")).toEqual({ destinationIp: "142.250.74.36" });
    expect(describeDestination("[2001:db8::1]")).toEqual({ destinationIp: "2001:db8::1" });
    expect(describeDestination("example.com")).toEqual({ destinationDomain: "example.com" });
  });
});

describe("routing decision log", () => {
  const target = { host: "youtube.com", port: 443 };

  it("names both directions, so a log can tell an unmatched rule from a dead tunnel", () => {
    expect(describeRoutingDecision(target, { shouldProxy: true, reason: "process.name", processName: "Telegram.exe" }))
      .toBe("Tunnel egress for youtube.com:443 from Telegram.exe (process.name).");
    expect(describeRoutingDecision(target, { shouldProxy: false, reason: "no-match" }))
      .toBe("Direct egress for youtube.com:443 (no-match).");
  });

  // The budgets are separate on purpose: a browser opens hundreds of unmatched
  // sockets a minute, and a shared budget would spend itself on those before a
  // single tunnelled decision was ever written.
  it("does not let one direction spend the other's budget", () => {
    const messages: string[] = [];
    const log = new RoutingDecisionLog((message) => messages.push(message), { now: () => 0 });
    for (let index = 0; index < MAX_LOGGED_DECISIONS_PER_DIRECTION * 2; index += 1) {
      log.record(target, { shouldProxy: false, reason: "no-match" });
    }
    const afterDirect = messages.length;
    log.record(target, { shouldProxy: true, reason: "domain" });

    expect(afterDirect).toBe(MAX_LOGGED_DECISIONS_PER_DIRECTION);
    expect(messages[afterDirect - 1]).toBe("Further direct routing decisions are suppressed for up to 60s.");
    expect(messages[afterDirect]).toBe("Tunnel egress for youtube.com:443 (domain).");
  });

  // The whole point of the rework: an earlier version capped each direction for
  // the entire session, so the log went permanently silent after one busy
  // minute - exactly when a later stall most needed to be visible. The budget
  // must refill on its own as time passes.
  it("refills each direction's budget once the window elapses", () => {
    const messages: string[] = [];
    let clock = 1_000;
    const log = new RoutingDecisionLog((message) => messages.push(message), { limit: 2, windowMs: 60_000, now: () => clock });

    log.record(target, { shouldProxy: true, reason: "domain" });
    log.record(target, { shouldProxy: true, reason: "domain" }); // hits the limit, emits the suppression note
    log.record(target, { shouldProxy: true, reason: "domain" }); // silent, still in window
    expect(messages).toHaveLength(2);
    expect(messages[1]).toBe("Further tunnelled routing decisions are suppressed for up to 60s.");

    clock += 60_000;
    log.record(target, { shouldProxy: true, reason: "domain" });
    expect(messages).toHaveLength(3);
    expect(messages[2]).toBe("Tunnel egress for youtube.com:443 (domain).");
  });

  it("starts a fresh budget on reset", () => {
    const messages: string[] = [];
    const log = new RoutingDecisionLog((message) => messages.push(message), { limit: 2, now: () => 0 });
    log.record(target, { shouldProxy: true, reason: "domain" });
    log.record(target, { shouldProxy: true, reason: "domain" });
    log.record(target, { shouldProxy: true, reason: "domain" });
    expect(messages).toHaveLength(2);

    log.reset();
    log.record(target, { shouldProxy: true, reason: "domain" });
    expect(messages).toHaveLength(3);
  });
});

function createEnforcer({ available = true, ...options }: { available?: boolean } & LocalRoutingEnforcerOptions = {}): LocalRoutingEnforcer {
  const attribution: ProcessAttribution = {
    isAvailable: async () => available,
    // Mixed case on purpose: rule values are stored lowercase with an .exe
    // suffix, so the snapshot has to be normalized before it can match.
    resolveProcessName: async (localPort) => (localPort === TARGET_APP_PORT ? "Telegram.exe" : "chrome.exe"),
    dispose: async () => undefined
  };
  // Nothing here may reach the real resolver.
  return new LocalRoutingEnforcer(attribution, { resolveHost: async () => [], ...options });
}

function createContext(): LocalRoutingContext {
  return {
    routingMode: "selected-rules",
    routingRules: [domainRule(), { id: "p1", type: "process.name", value: "telegram.exe", enabled: true, createdAt: "", updatedAt: "" }],
    routingProxyDomains: ["rutracker.org"],
    routingDirectDomains: ["gosuslugi.ru", "ozon.ru", "yandex.net"],
    protectedEndpoint: { host: "srv.example.com", port: 22 }
  };
}

function domainRule(): RoutingRule {
  return { id: "d1", type: "domain", value: "youtube.com", enabled: true, createdAt: "", updatedAt: "" };
}

function originator(port: number): { address: string; port: number } {
  return { address: "127.0.0.1", port };
}
