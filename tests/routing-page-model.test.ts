import { describe, expect, it } from "vitest";
import {
  connectionBadge,
  countTargets,
  cutsLastTargetWithPending,
  describeListError,
  duplicateMessage,
  filterDomains,
  filterRules,
  findDuplicateRule,
  listMetaText,
  MAX_PROCESS_CHIPS,
  presentTun,
  processChips,
  processFootText,
  ruleMatchKey,
  ruleMeta,
  rulesHeading,
  summaryCopy,
  tabCopy,
  validateRuleDraft,
  wouldCutLastTarget
} from "../src/renderer/components/pages/routing/routing-model.js";
import { createDefaultStore } from "../src/shared/defaults.js";
import type { RoutingRule, RoutingRuleType, TunStatus } from "../src/shared/types.js";

const at = "2026-10-06T09:00:00.000Z";
const rule = (id: string, type: RoutingRuleType, value: string, enabled = true): RoutingRule => ({
  id,
  type,
  value,
  enabled,
  createdAt: at,
  updatedAt: at
});

const noList = { enabled: false, domains: [] as string[] };

describe("routing targets", () => {
  it("counts enabled, valid rules by type plus a usable proxy list", () => {
    const rules = [
      rule("1", "domain", "youtube.com"),
      rule("2", "domain", "*.discord.gg", false),
      rule("3", "domain", "not a domain"),
      rule("4", "ip", "8.8.8.8"),
      rule("5", "process.name", "telegram.exe")
    ];
    expect(countTargets(rules, { enabled: true, domains: ["youtube.com"] })).toEqual({ domains: 1, ips: 1, apps: 1, lists: 1, total: 4 });
    expect(countTargets(rules, { enabled: true, domains: ["#comment", "localhost"] }).lists).toBe(0);
    expect(countTargets(rules, { enabled: false, domains: ["youtube.com"] }).lists).toBe(0);
  });

  it("asks only when a running Split tunnel would lose its last target", () => {
    const one = countTargets([rule("1", "domain", "x.com")], noList);
    const none = countTargets([], noList);
    expect(wouldCutLastTarget("selected-rules", true, one, none)).toBe(true);
    expect(wouldCutLastTarget("selected-rules", false, one, none)).toBe(false);
    expect(wouldCutLastTarget("proxy-all", true, one, none)).toBe(false);
    expect(wouldCutLastTarget("selected-rules", true, one, one)).toBe(false);
  });

  it("counts changes still on their way, so two quick ones can't both slip past the guard", () => {
    const list = { ...createDefaultStore().routingProxyList, enabled: true, domains: ["youtube.com"] };
    const nothingPending = { deletingRuleIds: new Set<string>(), proxyListTurningOff: false };
    const one = [rule("a", "domain", "a.com")];

    // The list is being turned off (still on in the snapshot): switching off the last rule now must ask.
    const ruleOff = [rule("a", "domain", "a.com", false)];
    expect(cutsLastTargetWithPending("selected-rules", true, { rules: one, proxyList: list }, { rules: ruleOff }, nothingPending)).toBe(false);
    expect(
      cutsLastTargetWithPending("selected-rules", true, { rules: one, proxyList: list }, { rules: ruleOff }, { ...nothingPending, proxyListTurningOff: true })
    ).toBe(true);

    // Rule A is mid-delete: deleting B, the only other target, must ask.
    const two = [rule("a", "domain", "a.com"), rule("b", "domain", "b.com")];
    const withoutB = [rule("a", "domain", "a.com")];
    const noListAtAll = { ...list, enabled: false };
    expect(cutsLastTargetWithPending("selected-rules", true, { rules: two, proxyList: noListAtAll }, { rules: withoutB }, nothingPending)).toBe(false);
    expect(
      cutsLastTargetWithPending(
        "selected-rules",
        true,
        { rules: two, proxyList: noListAtAll },
        { rules: withoutB },
        { ...nothingPending, deletingRuleIds: new Set(["a"]) }
      )
    ).toBe(true);
  });

  it("describes the summary for each mode", () => {
    const none = countTargets([], noList);
    const one = countTargets([rule("1", "domain", "x.com")], noList);
    const two = countTargets([rule("1", "domain", "x.com"), rule("2", "ip", "1.1.1.1")], noList);
    expect(summaryCopy("selected-rules", none)).toMatchObject({ tone: "warn", title: "Nothing to route yet" });
    expect(summaryCopy("selected-rules", one).title).toBe("target goes through the tunnel");
    expect(summaryCopy("selected-rules", two).title).toBe("targets go through the tunnel");
    expect(summaryCopy("proxy-all", two)).toMatchObject({ tone: "muted", title: "targets saved for Split tunnel" });
  });
});

describe("adding a rule", () => {
  it("explains what is wrong with a domain", () => {
    const domain = (value: string) => validateRuleDraft("domain", value, "windows");
    expect(domain("")).toEqual({ error: "Enter a domain, like youtube.com." });
    expect(domain("https://youtube.com/watch")).toEqual({ error: "Enter just the domain, without https:// or a path." });
    expect(domain("youtube.com/feed")).toEqual({ error: "Enter just the domain, without https:// or a path." });
    expect(domain("youtube.com:443")).toEqual({ error: "Enter just the domain, without a port." });
    expect(domain("8.8.8.8")).toEqual({ error: "That’s an IP address. Add it on the IPs tab." });
    expect(domain(".youtube.com").error).toMatch(/leading dot/u);
    expect(domain("you*tube.com")).toEqual({ error: "A * works only at the start, as in *.youtube.com." });
    expect(domain("localhost")).toEqual({ error: "Use the full domain with at least two parts, like youtube.com." });
    expect(domain("пример.рф").error).toMatch(/xn--/u);
    expect(domain("a".repeat(254)).error).toMatch(/253/u);
  });

  it("normalizes accepted domains", () => {
    expect(validateRuleDraft("domain", "  YouTube.COM. ", "windows")).toEqual({ value: "youtube.com" });
    expect(validateRuleDraft("domain", "*.googlevideo.com", "windows")).toEqual({ value: "*.googlevideo.com" });
  });

  it("checks IP addresses and ranges", () => {
    const ip = (value: string) => validateRuleDraft("ip", value, "windows");
    expect(ip("10.8.0.0/33")).toEqual({ error: "CIDR prefix must be between 0 and 32." });
    expect(ip("2a00::/129")).toEqual({ error: "CIDR prefix must be between 0 and 128." });
    expect(ip("1.1.1.1/2/3")).toEqual({ error: "CIDR may contain only one slash." });
    expect(ip("1.1.1.1/x")).toEqual({ error: "CIDR prefix must be a number." });
    expect(ip("01.1.1.1")).toEqual({ error: "IP address must be valid IPv4 or IPv6." });
    expect(ip("youtube.com")).toEqual({ error: "That’s a domain. Add it on the Domains tab." });
    expect(ip("2A00:1450::/32")).toEqual({ value: "2a00:1450::/32" });
    expect(ip(" 8.8.8.8 ")).toEqual({ value: "8.8.8.8" });
  });

  it("checks app names per platform", () => {
    expect(validateRuleDraft("process.name", "", "windows")).toEqual({ error: "Enter an app file name, like telegram.exe." });
    expect(validateRuleDraft("process.name", "", "macos")).toEqual({ error: "Enter an app name, like Telegram." });
    expect(validateRuleDraft("process.name", "C:\\Apps\\chrome.exe", "windows").error).toMatch(/not a path/u);
    expect(validateRuleDraft("process.name", "Helper (Renderer)", "macos").error).toMatch(/Latin letters/u);
    expect(validateRuleDraft("process.name", "Telegram.EXE", "windows")).toEqual({ value: "telegram.exe" });
  });

  it("finds rules that already cover the value", () => {
    const rules = [rule("1", "process.name", "chrome"), rule("2", "ip", "8.8.8.8"), rule("3", "domain", "x.com", false)];
    expect(findDuplicateRule(rules, "process.name", "chrome.exe", "windows")?.id).toBe("1");
    expect(findDuplicateRule(rules, "process.name", "chrome.exe", "macos")).toBeUndefined();
    expect(findDuplicateRule(rules, "ip", "8.8.8.8/32", "windows")?.id).toBe("2");
    expect(findDuplicateRule(rules, "ip", "8.8.8.8/24", "windows")).toBeUndefined();
    expect(ruleMatchKey("ip", "2a00::1/128", "windows")).toBe("2a00::1");
    expect(duplicateMessage("chrome.exe", rules[0])).toBe("chrome.exe is already in your rules as chrome.");
    expect(duplicateMessage("x.com", rules[2])).toBe("x.com is already in your rules but turned off. Turn it on in the list below.");
    expect(duplicateMessage("chrome", rules[0])).toBe("chrome is already in your rules.");
  });

  it("uses copy that fits each tab and platform", () => {
    expect(tabCopy("apps", "windows").placeholder).toBe("telegram.exe");
    expect(tabCopy("apps", "macos").placeholder).toBe("Telegram");
    expect(tabCopy("ips", "windows").addLabel).toBe("Add an IP address or range");
    expect(tabCopy("domains", "linux").type).toBe("domain");
  });
});

describe("rule rows", () => {
  it("says what each rule covers", () => {
    expect(ruleMeta({ type: "domain", value: "youtube.com" })).toBe("Includes subdomains");
    expect(ruleMeta({ type: "domain", value: "*.youtube.com" })).toBe("Subdomains only");
    expect(ruleMeta({ type: "ip", value: "1.1.1.1/32" })).toBe("IPv4 address");
    expect(ruleMeta({ type: "ip", value: "10.0.0.0/8" })).toBe("IPv4 range");
    expect(ruleMeta({ type: "ip", value: "2a00:1450::/32" })).toBe("IPv6 range");
    expect(ruleMeta({ type: "process.name", value: "discord.exe" })).toBe("Every connection from this app");
    expect(ruleMeta({ type: "domain", value: "bad value" })).toBe("Not a valid rule, so it’s skipped");
  });

  it("filters inside one tab and words the heading", () => {
    const rules = [rule("1", "domain", "youtube.com"), rule("2", "domain", "discord.com", false), rule("3", "ip", "1.1.1.1")];
    expect(filterRules(rules, "domain", "YOU").map((item) => item.id)).toEqual(["1"]);
    const copy = tabCopy("domains", "windows");
    expect(rulesHeading(copy, 2, 1, 2, "")).toBe("2 domains · 1 on");
    expect(rulesHeading(copy, 2, 1, 1, "you")).toBe("1 of 2 domains matches");
    expect(rulesHeading(copy, 9, 8, 3, "o")).toBe("3 of 9 domains match");
  });
});

describe("domain lists", () => {
  const now = new Date(2026, 9, 6, 12, 30);

  it("describes list state", () => {
    const refreshed = new Date(2026, 9, 6, 11, 40).toISOString();
    expect(listMetaText({ enabled: true, domains: ["a.com", "b.com"], updatedAt: refreshed }, undefined, now)).toBe("2 domains · refreshed today 11:40");
    expect(listMetaText({ enabled: false, domains: [] }, undefined, now)).toBe("Not downloaded yet · downloads when you turn it on");
    expect(listMetaText({ enabled: false, domains: [] }, "downloading", now)).toBe("Downloading from GitHub… up to 15 s");
    expect(listMetaText({ enabled: true, domains: ["a.com"] }, "turning-off", now)).toBe("Turning off…");
  });

  it("turns raw download errors into advice", () => {
    const empty = { enabled: false, domains: [] };
    const inUse = { enabled: true, domains: ["a.com"] };
    const timeout = describeListError("Error invoking remote method 'x': Error: Routing list download timed out.", "proxy", empty);
    expect(timeout.title).toBe("Couldn’t download Blocked in Russia");
    expect(timeout.text).toMatch(/^GitHub didn’t answer within 15 s\. Lists download directly.*The list stays off\.$/u);
    const offline = describeListError("TypeError: fetch failed", "direct", inUse);
    expect(offline.title).toBe("Couldn’t refresh Russian services");
    expect(offline.text).toMatch(/^Shadow SSH couldn’t reach GitHub\..*Your current copy stays in use\.$/u);
    expect(describeListError("Routing list download failed: 404 Not Found", "proxy", empty).text).toMatch(/^GitHub answered 404 Not Found\./u);
    expect(describeListError("Routing list is larger than the allowed limit.", "proxy", empty).text).toMatch(/2 MB/u);
    expect(describeListError("Routing proxy list refresh returned no domains.", "proxy", empty).text).toMatch(/didn’t contain any domains/u);
    expect(describeListError("Domain proxy list is larger than 20000 entries.", "direct", { enabled: false, domains: ["a.com"] }).text).toBe(
      "The list has more than 20,000 domains, the most Shadow SSH can use. Your current copy is kept."
    );
  });

  it("filters and highlights domains in the viewer", () => {
    const rows = filterDomains([".cdninstagram.com", "discord.com", "youtube.com"], "disc");
    expect(rows).toEqual([{ domain: "discord.com", pre: "", hit: "disc", post: "ord.com", zone: false }]);
    expect(filterDomains([".cdninstagram.com"], "")[0]).toMatchObject({ zone: true, pre: ".cdninstagram.com", hit: "" });
  });
});

describe("TUN status", () => {
  const base: TunStatus = {
    supported: true,
    enabled: true,
    elevated: true,
    wintunFound: true,
    searchedPaths: [],
    active: false,
    appliesOnNextConnect: false
  };

  it("reads each state honestly", () => {
    expect(presentTun({ ...base, enabled: false }, false)).toMatchObject({ tone: "off", title: "Off" });
    expect(presentTun({ ...base, active: true }, true)).toMatchObject({ tone: "ok", title: "Active this session", howLabel: "Requirements" });
    expect(presentTun({ ...base, elevated: false }, false)).toMatchObject({
      tone: "warn",
      title: "Not active: Shadow SSH isn’t running as administrator",
      howLabel: "How to enable"
    });
    expect(presentTun({ ...base, wintunFound: false }, false).title).toBe("Not active: wintun.dll wasn’t found");
    expect(presentTun({ ...base, lastFailure: "The TUN adapter couldn’t start this session." }, true).title).toBe("Not active this session");
    expect(presentTun(base, false).title).toBe("Ready · starts when you connect");
    expect(presentTun({ ...base, appliesOnNextConnect: true }, true).title).toBe("Ready · starts when you reconnect");
  });
});

describe("running apps", () => {
  it("marks apps that already have a rule and caps the chips", () => {
    const names = Array.from({ length: 120 }, (_, index) => `app${index}.exe`);
    const { chips, matches } = processChips(["Chrome.exe", "Telegram.exe"], "", [rule("1", "process.name", "chrome")], "windows");
    expect(matches).toBe(2);
    expect(chips).toEqual([
      { name: "Chrome.exe", added: true },
      { name: "Telegram.exe", added: false }
    ]);
    expect(processChips(names, "", [], "windows").chips).toHaveLength(MAX_PROCESS_CHIPS);
    expect(processChips(names, "app1", [], "windows").matches).toBe(31);
  });

  it("says how much of the list is shown", () => {
    expect(processFootText(214, 214, "")).toBe("Showing 80 of 214 · refine your search");
    expect(processFootText(40, 40, "")).toBe("40 running apps");
    expect(processFootText(214, 3, "tele")).toBe("3 matches among 214 running apps");
    expect(processFootText(214, 1, "tele")).toBe("1 match among 214 running apps");
    expect(processFootText(214, 120, "e")).toBe("Showing 80 of 120 matches · refine your search");
  });
});

describe("connection badge", () => {
  it("follows the active tunnel and routing", () => {
    expect(connectionBadge({ state: "Connected", preview: false, platform: "windows", targetName: "Frankfurt-01", blocked: false })).toEqual({
      tone: "ok",
      text: "Protected · Frankfurt-01",
      spinner: false
    });
    expect(connectionBadge({ state: "Connected", preview: false, platform: "macos", targetName: "Frankfurt-01", blocked: false }).text).toBe(
      "Proxy ready · Frankfurt-01"
    );
    expect(connectionBadge({ state: "Reconnecting", preview: false, platform: "windows", blocked: false })).toMatchObject({ tone: "busy", spinner: true });
    expect(connectionBadge({ state: "Disconnected", preview: false, platform: "windows", blocked: true }).text).toBe("Blocked by routing");
    expect(connectionBadge({ state: "Disconnected", preview: false, platform: "windows", blocked: false }).text).toBe("Not connected");
  });
});
