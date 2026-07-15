import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import {
  buildWindowsDnsCachePowerShell,
  listWindowsDnsCacheEntries,
  MAX_WINDOWS_DNS_CACHE_CNAME_DEPTH,
  MAX_WINDOWS_DNS_CACHE_DOMAINS_PER_ADDRESS,
  MAX_WINDOWS_DNS_CACHE_OUTPUT_BYTES,
  parseWindowsDnsCacheEntries
} from "../src/core/network/windows-dns-cache.js";
import { parsePowerShellConnections } from "../src/core/network/windows-process-connections.js";

describe("Windows DNS cache queries", () => {
  it("does not inspect or consume address input outside Windows", async () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { configurable: true, value: "linux" });
    const addresses: Iterable<string> = {
      [Symbol.iterator](): Iterator<string> {
        throw new Error("address iterable should not be consumed");
      }
    };

    try {
      await expect(listWindowsDnsCacheEntries(addresses)).resolves.toEqual([]);
    } finally {
      if (platform) {
        Object.defineProperty(process, "platform", platform);
      }
    }
  });

  it("embeds only Base64 JSON and uses PowerShell 5.1-compatible filtering", () => {
    const injection = "1.1.1.1'); Write-Output 'injected'; #";
    const script = buildWindowsDnsCachePowerShell(["162.159.138.232", "2A00:1450:4001:831::200E", injection]);

    expect(script).toBeDefined();
    expect(script).not.toContain(injection);
    expect(script).toContain("Get-DnsClientCache -Type A,AAAA,CNAME");
    expect(script).toContain("[System.Net.IPAddress]::Parse");
    expect(script).toContain("$recordTypeValue = [string]$_.RecordType");
    expect(script).toContain("$recordTypeValue = [string]$_.Type");
    expect((script ?? "").indexOf("$_.RecordType")).toBeLessThan((script ?? "").indexOf("$_.Type"));
    expect(script).toContain("$recordStatus = 0");
    expect(script).toContain("$recordOwner = [string]$_.Name");
    expect(script).toContain("$recordOwner = [string]$_.RecordName");
    expect(script).toContain("$recordOwner = [string]$_.Entry");
    expect(script).toContain("canonicalDomain = [string]$_.Data");
    expect(script).not.toContain("ConvertTo-Json -AsArray");

    const encoded = script?.match(/FromBase64String\('([A-Za-z0-9+/=]+)'\)/u)?.[1];
    expect(encoded).toBeDefined();
    expect(JSON.parse(Buffer.from(encoded ?? "", "base64").toString("utf8"))).toEqual([
      "162.159.138.232",
      "2a00:1450:4001:831::200e"
    ]);
  });

  it("does not build a query without valid target addresses", () => {
    expect(buildWindowsDnsCachePowerShell([])).toBeUndefined();
    expect(buildWindowsDnsCachePowerShell(["not-an-ip", "127.0.0.1; Get-Process"])).toBeUndefined();
  });

  it("normalizes, filters, validates, and deduplicates cache entries", () => {
    const entries = parseWindowsDnsCacheEntries(
      JSON.stringify([
        { address: "162.159.138.232", domain: "Discord.COM.", ttlSeconds: 120 },
        { address: "162.159.138.232", domain: "discord.com", ttlSeconds: 180 },
        { address: "2a00:1450:4001:0831:0000:0000:0000:200e", domain: "Gateway.Discord.GG", ttlSeconds: "60" },
        { address: "1.1.1.1", domain: "unrequested.example", ttlSeconds: 60 },
        { address: "162.159.138.232", domain: "localhost", ttlSeconds: 60 },
        { address: "162.159.138.232", domain: "*.discord.com", ttlSeconds: 60 },
        { address: "162.159.138.232", domain: "bad..example", ttlSeconds: 60 },
        { address: "162.159.138.232", domain: "expired.example", ttlSeconds: 0 },
        { address: "162.159.138.232", domain: "huge.example", ttlSeconds: 604_801 },
        { address: "invalid", domain: "valid.example", ttlSeconds: 60 },
        null
      ]),
      ["162.159.138.232", "2a00:1450:4001:831::200e"]
    );

    expect(entries).toEqual([
      { address: "162.159.138.232", domain: "discord.com", ttlSeconds: 180 },
      { address: "2a00:1450:4001:831::200e", domain: "gateway.discord.gg", ttlSeconds: 60 }
    ]);
  });

  it("accepts a single PowerShell object and an IPv4-mapped address", () => {
    expect(parseWindowsDnsCacheEntries(
      JSON.stringify({ address: "::ffff:149.154.167.41", domain: "api.telegram.org.", ttlSeconds: 30 }),
      ["149.154.167.41"]
    )).toEqual([
      { address: "149.154.167.41", domain: "api.telegram.org", ttlSeconds: 30 }
    ]);
  });

  it("matches an expanded process IPv6 address with a compressed DNS cache address", () => {
    const [connection] = parsePowerShellConnections(JSON.stringify({
      processName: "Discord.exe",
      remoteAddress: "2A00:1450:4001:0831:0000:0000:0000:200E",
      remotePort: 443,
      state: "Established"
    }));

    expect(connection.remoteAddress).toBe("2a00:1450:4001:831::200e");
    expect(parseWindowsDnsCacheEntries(JSON.stringify({
      address: "2a00:1450:4001:831::200e",
      domain: "gateway.discord.gg",
      ttlSeconds: 60
    }), [connection.remoteAddress])).toEqual([{
      address: connection.remoteAddress,
      domain: "gateway.discord.gg",
      ttlSeconds: 60
    }]);
  });

  it("walks a bounded reverse CNAME chain and carries the shortest path TTL", () => {
    const entries = parseWindowsDnsCacheEntries(JSON.stringify([
      { address: "162.159.138.232", domain: "shard.vendor.example", ttlSeconds: 300 },
      { domain: "edge.vendor.example", canonicalDomain: "shard.vendor.example.", ttlSeconds: 120 },
      { domain: "api.example.com.", canonicalDomain: "edge.vendor.example", ttlSeconds: 240 }
    ]), ["162.159.138.232"]);

    expect(entries).toEqual([
      { address: "162.159.138.232", domain: "shard.vendor.example", ttlSeconds: 300 },
      { address: "162.159.138.232", domain: "edge.vendor.example", ttlSeconds: 120 },
      { address: "162.159.138.232", domain: "api.example.com", ttlSeconds: 120 }
    ]);
  });

  it("keeps the best valid CNAME path per requested address", () => {
    const entries = parseWindowsDnsCacheEntries(JSON.stringify([
      { address: "162.159.138.232", domain: "origin.vendor.example", ttlSeconds: 300 },
      { address: "162.159.138.232", domain: "alternate.vendor.example", ttlSeconds: 90 },
      { address: "203.0.113.20", domain: "origin.vendor.example", ttlSeconds: 600 },
      { domain: "edge.vendor.example", canonicalDomain: "origin.vendor.example", ttlSeconds: 120 },
      { domain: "api.example.com", canonicalDomain: "edge.vendor.example", ttlSeconds: 240 },
      { domain: "api.example.com", canonicalDomain: "alternate.vendor.example", ttlSeconds: 300 },
      { domain: "api.example.com", canonicalDomain: "edge.vendor.example", ttlSeconds: 60 }
    ]), ["162.159.138.232"]);

    expect(entries).toEqual(expect.arrayContaining([
      { address: "162.159.138.232", domain: "edge.vendor.example", ttlSeconds: 120 },
      { address: "162.159.138.232", domain: "api.example.com", ttlSeconds: 120 }
    ]));
    expect(entries.some((entry) => entry.address === "203.0.113.20")).toBe(false);
  });

  it("terminates CNAME cycles and truncates chains at the configured depth", () => {
    const address = "162.159.138.232";
    const rows = [
      { address, domain: "level-0.example.com", ttlSeconds: 300 },
      ...Array.from({ length: MAX_WINDOWS_DNS_CACHE_CNAME_DEPTH + 2 }, (_unused, index) => ({
        domain: `level-${index + 1}.example.com`,
        canonicalDomain: `level-${index}.example.com`,
        ttlSeconds: 300
      })),
      { domain: "level-1.example.com", canonicalDomain: "level-2.example.com", ttlSeconds: 300 },
      { domain: "self.example.com", canonicalDomain: "self.example.com", ttlSeconds: 300 }
    ];

    const entries = parseWindowsDnsCacheEntries(JSON.stringify(rows), [address]);
    const domains = new Set(entries.map((entry) => entry.domain));

    expect(domains.has(`level-${MAX_WINDOWS_DNS_CACHE_CNAME_DEPTH}.example.com`)).toBe(true);
    expect(domains.has(`level-${MAX_WINDOWS_DNS_CACHE_CNAME_DEPTH + 1}.example.com`)).toBe(false);
    expect(domains.has("self.example.com")).toBe(false);
    expect(entries.filter((entry) => entry.domain === "level-1.example.com")).toHaveLength(1);
  });

  it("rejects invalid, ambiguous, and unrooted CNAME cache rows", () => {
    const address = "162.159.138.232";
    const entries = parseWindowsDnsCacheEntries(JSON.stringify([
      { address, domain: "origin.example.com", ttlSeconds: 300 },
      { domain: "*.wildcard.example.com", canonicalDomain: "origin.example.com", ttlSeconds: 60 },
      { domain: "bad..example.com", canonicalDomain: "origin.example.com", ttlSeconds: 60 },
      { domain: "zero.example.com", canonicalDomain: "origin.example.com", ttlSeconds: 0 },
      { domain: "unrooted.example.com", canonicalDomain: "elsewhere.example.com", ttlSeconds: 60 },
      {
        address,
        domain: "ambiguous.example.com",
        canonicalDomain: "origin.example.com",
        ttlSeconds: 60
      }
    ]), [address]);

    expect(entries).toEqual([
      { address, domain: "origin.example.com", ttlSeconds: 300 }
    ]);
  });

  it("associates a CNAME alias independently with every requested canonical address", () => {
    const entries = parseWindowsDnsCacheEntries(JSON.stringify([
      { address: "162.159.138.232", domain: "shared.vendor.example", ttlSeconds: 120 },
      { address: "149.154.167.41", domain: "shared.vendor.example", ttlSeconds: 60 },
      { domain: "app.example.com", canonicalDomain: "shared.vendor.example", ttlSeconds: 90 }
    ]), ["162.159.138.232", "149.154.167.41"]);

    expect(entries).toEqual(expect.arrayContaining([
      { address: "162.159.138.232", domain: "app.example.com", ttlSeconds: 90 },
      { address: "149.154.167.41", domain: "app.example.com", ttlSeconds: 60 }
    ]));
  });

  it("bounds aliases learned for one shared address", () => {
    const rows = Array.from({ length: MAX_WINDOWS_DNS_CACHE_DOMAINS_PER_ADDRESS + 10 }, (_unused, index) => ({
      address: "162.159.138.232",
      domain: `alias-${index}.example.com`,
      ttlSeconds: 60
    }));

    const entries = parseWindowsDnsCacheEntries(JSON.stringify(rows), ["162.159.138.232"]);

    expect(entries).toHaveLength(MAX_WINDOWS_DNS_CACHE_DOMAINS_PER_ADDRESS);
    expect(entries.at(-1)?.domain).toBe(`alias-${MAX_WINDOWS_DNS_CACHE_DOMAINS_PER_ADDRESS - 1}.example.com`);
  });

  it("rejects oversized command output before JSON parsing", () => {
    const oversized = " ".repeat(MAX_WINDOWS_DNS_CACHE_OUTPUT_BYTES + 1);

    expect(() => parseWindowsDnsCacheEntries(oversized, ["1.1.1.1"])).toThrow("exceeded the allowed size");
  });

  it("returns an empty snapshot for blank output or an empty requested allowlist", () => {
    expect(parseWindowsDnsCacheEntries("", ["1.1.1.1"])).toEqual([]);
    expect(parseWindowsDnsCacheEntries(JSON.stringify({
      address: "1.1.1.1",
      domain: "one.one.one.one",
      ttlSeconds: 60
    }), [])).toEqual([]);
  });
});
