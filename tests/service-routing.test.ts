import { describe, expect, it } from "vitest";
import {
  buildProcessRouteSignature,
  buildSelectedRulesWithProcessIps,
  recordBoundedProcessRouteDomain,
  recordBoundedProcessRouteIp
} from "../src/service/process-route-learning.js";
import type { RoutingRule } from "../src/shared/types.js";

describe("live service process-route learning", () => {
  it("adds learned process IPs without dropping domain or process rules", () => {
    const rules: RoutingRule[] = [
      { id: "domain", type: "domain", value: "youtube.com", enabled: true, createdAt: "", updatedAt: "" },
      { id: "proc", type: "process.name", value: "Telegram.exe", enabled: true, createdAt: "", updatedAt: "" }
    ];

    const augmented = buildSelectedRulesWithProcessIps(rules, new Set(["149.154.167.41", "2a00:1450:4001:831::200e"]));

    expect(augmented.slice(0, 2)).toEqual(rules);
    expect(augmented).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: "ip", value: "149.154.167.41", enabled: true }),
        expect.objectContaining({ type: "ip", value: "2a00:1450:4001:831::200e", enabled: true })
      ])
    );
  });

  it("does not duplicate existing enabled IP rules when adding learned process IPs", () => {
    const rules: RoutingRule[] = [
      { id: "ip", type: "ip", value: "149.154.167.41", enabled: true, createdAt: "", updatedAt: "" },
      { id: "proc", type: "process.name", value: "telegram.exe", enabled: true, createdAt: "", updatedAt: "" }
    ];

    const augmented = buildSelectedRulesWithProcessIps(rules, new Set(["149.154.167.41", "149.154.167.50"]));

    expect(augmented.filter((rule) => rule.type === "ip" && rule.value === "149.154.167.41")).toHaveLength(1);
    expect(augmented).toEqual(expect.arrayContaining([expect.objectContaining({ type: "ip", value: "149.154.167.50" })]));
  });

  it("does not turn invalid learned endpoints into PAC IP rules", () => {
    const rules: RoutingRule[] = [
      { id: "proc", type: "process.name", value: "telegram.exe", enabled: true, createdAt: "", updatedAt: "" }
    ];

    const augmented = buildSelectedRulesWithProcessIps(rules, new Set(["*", "0", "999.1.1.1", "149.154.167.50"]));

    expect(augmented.filter((rule) => rule.type === "ip").map((rule) => rule.value)).toEqual(["149.154.167.50"]);
  });

  it("leaves a selected process's local-network destinations out of the PAC rules", () => {
    // A process rule comes after the local network; as PAC rules, learned
    // destinations would rank with the user's own, which win over it.
    const rules: RoutingRule[] = [
      { id: "proc", type: "process.name", value: "telegram.exe", enabled: true, createdAt: "", updatedAt: "" },
      { id: "lan", type: "ip", value: "10.0.0.0/8", enabled: true, createdAt: "", updatedAt: "" }
    ];

    const augmented = buildSelectedRulesWithProcessIps(
      rules,
      new Set(["192.168.1.5", "10.1.2.3", "100.64.0.7", "fd00::5", "149.154.167.50"]),
      new Set(["nas.local", "*.corp.local", "api.telegram.org"])
    );

    expect(augmented.slice(0, 2)).toEqual(rules);
    expect(augmented.slice(2).map((rule) => rule.value)).toEqual(["api.telegram.org", "149.154.167.50"]);
  });

  it("adds exact and wildcard process domains without duplicating user rules", () => {
    const rules: RoutingRule[] = [
      { id: "domain", type: "domain", value: "discord.com", enabled: true, createdAt: "", updatedAt: "" },
      { id: "proc", type: "process.name", value: "discord.exe", enabled: true, createdAt: "", updatedAt: "" }
    ];

    const augmented = buildSelectedRulesWithProcessIps(
      rules,
      new Set(),
      new Set(["discord.com", "*.discord.com", "gateway.discord.gg", "not-a-domain"])
    );

    expect(augmented.filter((rule) => rule.type === "domain" && rule.value === "discord.com")).toHaveLength(1);
    expect(augmented).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "process-domain:*.discord.com", type: "domain", value: "*.discord.com" }),
      expect.objectContaining({ id: "process-domain:gateway.discord.gg", type: "domain", value: "gateway.discord.gg" })
    ]));
    expect(augmented.some((rule) => rule.value === "not-a-domain")).toBe(false);
  });

  it("bounds learned process destinations and retains recently refreshed IPs", () => {
    const entries = new Map<string, number>();
    recordBoundedProcessRouteIp(entries, "1.1.1.1", 1, 2);
    recordBoundedProcessRouteIp(entries, "2.2.2.2", 2, 2);
    recordBoundedProcessRouteIp(entries, "1.1.1.1", 3, 2);
    recordBoundedProcessRouteIp(entries, "3.3.3.3", 4, 2);

    expect([...entries]).toEqual([
      ["1.1.1.1", 3],
      ["3.3.3.3", 4]
    ]);
  });

  it("bounds stable learned domains and includes them in the applied signature", () => {
    const entries = new Map<string, number>();
    recordBoundedProcessRouteDomain(entries, "API.Example.COM.", 1, 2);
    recordBoundedProcessRouteDomain(entries, "gateway.example.com", 2, 2);
    recordBoundedProcessRouteDomain(entries, "api.example.com", 3, 2);
    recordBoundedProcessRouteDomain(entries, "cdn.example.com", 4, 2);

    expect([...entries]).toEqual([
      ["api.example.com", 3],
      ["cdn.example.com", 4]
    ]);
    expect(buildProcessRouteSignature(["203.0.113.8"], entries.keys())).toBe(
      "ips:203.0.113.8|domains:api.example.com,cdn.example.com"
    );
  });
});
