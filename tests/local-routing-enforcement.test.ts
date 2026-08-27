import { describe, expect, it } from "vitest";
import {
  LocalRoutingEnforcer,
  MAX_LOGGED_DECISIONS_PER_DIRECTION,
  RoutingDecisionLog,
  describeRoutingDecision,
  type LocalRoutingContext
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
    const log = new RoutingDecisionLog((message) => messages.push(message));
    for (let index = 0; index < MAX_LOGGED_DECISIONS_PER_DIRECTION * 2; index += 1) {
      log.record(target, { shouldProxy: false, reason: "no-match" });
    }
    const afterDirect = messages.length;
    log.record(target, { shouldProxy: true, reason: "domain" });

    expect(afterDirect).toBe(MAX_LOGGED_DECISIONS_PER_DIRECTION);
    expect(messages[afterDirect - 1]).toBe("Further direct routing decisions are suppressed for this session.");
    expect(messages[afterDirect]).toBe("Tunnel egress for youtube.com:443 (domain).");
  });

  // A long-lived process used to go permanently silent after one busy session.
  it("restores both budgets on reset", () => {
    const messages: string[] = [];
    const log = new RoutingDecisionLog((message) => messages.push(message), 2);
    log.record(target, { shouldProxy: true, reason: "domain" });
    log.record(target, { shouldProxy: true, reason: "domain" });
    log.record(target, { shouldProxy: true, reason: "domain" });
    expect(messages).toHaveLength(2);

    log.reset();
    log.record(target, { shouldProxy: true, reason: "domain" });
    expect(messages).toHaveLength(3);
  });
});

function createEnforcer({ available = true }: { available?: boolean } = {}): LocalRoutingEnforcer {
  const attribution: ProcessAttribution = {
    isAvailable: async () => available,
    // Mixed case on purpose: rule values are stored lowercase with an .exe
    // suffix, so the snapshot has to be normalized before it can match.
    resolveProcessName: async (localPort) => (localPort === TARGET_APP_PORT ? "Telegram.exe" : "chrome.exe"),
    dispose: async () => undefined
  };
  return new LocalRoutingEnforcer(attribution);
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
