import { describe, expect, it } from "vitest";
import { buildSelectedRulesWithProcessIps, describeUnsupportedSelectedRouting } from "../src/service/live-ssh-service.js";
import type { ConnectRequest, RoutingRule, SshConfig } from "../src/shared/types.js";

describe("live service routing support checks", () => {
  it("allows process-only selected routing on Windows", () => {
    const message = describeUnsupportedSelectedRouting(
      requestWithRules([{ id: "proc", type: "process.name", value: "chrome.exe", enabled: true, createdAt: "", updatedAt: "" }]),
      "win32"
    );

    expect(message).toBeUndefined();
  });

  it("allows mixed selected routing so PAC-compatible domain/IP rules still apply", () => {
    const message = describeUnsupportedSelectedRouting(
      requestWithRules([
        { id: "proc", type: "process.name", value: "chrome.exe", enabled: true, createdAt: "", updatedAt: "" },
        { id: "ip", type: "ip", value: "203.0.113.0/24", enabled: true, createdAt: "", updatedAt: "" }
      ]),
      "win32"
    );

    expect(message).toBeUndefined();
  });

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
});

function requestWithRules(routingRules: RoutingRule[]): ConnectRequest {
  return {
    config: config(),
    routingMode: "selected-rules",
    routingRules,
    routingProxyDomains: [],
    routingDirectDomains: [],
    checkEndpoint: "example.com:443",
    secrets: { password: "secret" }
  };
}

function config(): SshConfig {
  return {
    id: "config",
    name: "Config",
    host: "ssh.example.com",
    port: 22,
    username: "user",
    authType: "password",
    expectedServerFingerprint: "",
    keepaliveIntervalSec: 30,
    note: "",
    createdAt: "",
    updatedAt: ""
  };
}
