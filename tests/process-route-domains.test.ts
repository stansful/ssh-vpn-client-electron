import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { buildProxyPac } from "../src/core/network/windows-system-proxy.js";
import {
  hasProcessRouteDomainHints,
  isDomainCoveredByDirectDomains,
  isDomainCoveredByRoutePatterns,
  processRouteDomainHints
} from "../src/core/routing/process-route-domains.js";
import type { RoutingRule } from "../src/shared/types.js";

describe("process route domain hints", () => {
  it("seeds Discord HTTP, CDN, gateway, and media host families", () => {
    const domains = processRouteDomainHints(["discord.exe"]);

    expect(domains).toEqual(new Set([
      "discord.com",
      "*.discord.com",
      "discord.gg",
      "*.discord.gg",
      "discordapp.com",
      "*.discordapp.com",
      "discordapp.net",
      "*.discordapp.net",
      "discord.media",
      "*.discord.media"
    ]));
    expect(hasProcessRouteDomainHints("Discord.EXE")).toBe(true);
    expect(processRouteDomainHints(["DiscordCanary.exe"])).toEqual(domains);
    expect(processRouteDomainHints(["DiscordPTB.exe"])).toEqual(domains);
  });

  it("leaves unknown applications to generic DNS/IP learning", () => {
    expect(processRouteDomainHints(["custom-app.exe"])).toEqual(new Set());
    expect(hasProcessRouteDomainHints("custom-app.exe")).toBe(false);
  });

  it("recognizes exact and wildcard coverage without treating an apex as a wildcard match", () => {
    expect(isDomainCoveredByRoutePatterns("gateway.discord.gg", ["*.discord.gg"])).toBe(true);
    expect(isDomainCoveredByRoutePatterns("discord.gg", ["*.discord.gg"])).toBe(false);
    expect(isDomainCoveredByRoutePatterns("discord.gg", ["discord.gg"])).toBe(true);
    expect(isDomainCoveredByRoutePatterns("notdiscord.gg", ["*.discord.gg"])).toBe(false);
  });

  it("recognizes PAC direct-list suffix conflicts for exact learned hostnames", () => {
    expect(isDomainCoveredByDirectDomains("api.example.com", [".example.com"])).toBe(true);
    expect(isDomainCoveredByDirectDomains("api.example.com", ["*.example.com"])).toBe(true);
    expect(isDomainCoveredByDirectDomains("example.com", ["example.com"])).toBe(true);
    expect(isDomainCoveredByDirectDomains("notexample.com", ["example.com"])).toBe(false);
    expect(isDomainCoveredByDirectDomains("api.example.com", ["invalid host"])).toBe(false);
  });

  it("routes Discord API, gateway, and CDN subdomains while unrelated hosts stay direct", () => {
    const rules = [...processRouteDomainHints(["discord.exe"])].map<RoutingRule>((domain) => ({
      id: domain,
      type: "domain",
      value: domain,
      enabled: true,
      createdAt: "",
      updatedAt: ""
    }));
    const pac = buildProxyPac(rules, "127.0.0.1", 1080);
    const context: { result?: string } = {};

    runInNewContext(`${pac}\nresult = FindProxyForURL("https://gateway.discord.gg/", "gateway.discord.gg");`, context);
    expect(context.result).toContain("PROXY 127.0.0.1:1080");
    runInNewContext(`${pac}\nresult = FindProxyForURL("https://cdn.discordapp.com/", "cdn.discordapp.com");`, context);
    expect(context.result).toContain("PROXY 127.0.0.1:1080");
    runInNewContext(`${pac}\nresult = FindProxyForURL("https://unrelated.example/", "unrelated.example");`, context);
    expect(context.result).toBe("DIRECT");
  });
});
