import { validateRoutingRuleValue } from "../../shared/validation.js";
import { normalizeProxyDomain } from "./domain-proxy-list.js";

export const MAX_PROCESS_ROUTE_SESSION_LEASES = 256;

export interface ProcessRouteSessionEvidence {
  processName: string;
  address: string;
  domain: string;
  firstObservedAt: number;
}

// A process-only PAC rule starts from sockets the application opened directly.
// Multi-endpoint Electron applications can stop exposing their real destinations
// as soon as some sockets move to the loopback proxy. Small, reviewed bootstrap
// profiles keep their essential HTTP/WebSocket host families stable while the
// generic Windows DNS-cache learner discovers exact hostnames for every app.
const DISCORD_ROUTE_DOMAIN_HINTS = [
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
] as const;

const PROCESS_ROUTE_DOMAIN_HINTS: Readonly<Record<string, readonly string[]>> = {
  "discord.exe": DISCORD_ROUTE_DOMAIN_HINTS,
  "discordcanary.exe": DISCORD_ROUTE_DOMAIN_HINTS,
  "discorddevelopment.exe": DISCORD_ROUTE_DOMAIN_HINTS,
  "discordptb.exe": DISCORD_ROUTE_DOMAIN_HINTS
};

export function processRouteDomainHints(processNames: Iterable<string>): Set<string> {
  const domains = new Set<string>();
  for (const processName of processNames) {
    const normalizedProcessName = processName.trim().toLowerCase();
    for (const domain of PROCESS_ROUTE_DOMAIN_HINTS[normalizedProcessName] ?? []) {
      if (validateRoutingRuleValue("domain", domain).ok) {
        domains.add(domain);
      }
    }
  }
  return domains;
}

export function hasProcessRouteDomainHints(processName: string): boolean {
  return (PROCESS_ROUTE_DOMAIN_HINTS[processName.trim().toLowerCase()]?.length ?? 0) > 0;
}

export function isDomainCoveredByRoutePatterns(domain: string, patterns: Iterable<string>): boolean {
  const normalizedDomain = domain.trim().toLowerCase().replace(/\.$/u, "");
  if (!validateRoutingRuleValue("domain", normalizedDomain).ok || normalizedDomain.startsWith("*.")) {
    return false;
  }
  for (const rawPattern of patterns) {
    const pattern = rawPattern.trim().toLowerCase().replace(/\.$/u, "");
    if (!validateRoutingRuleValue("domain", pattern).ok) {
      continue;
    }
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(2);
      if (normalizedDomain !== suffix && normalizedDomain.endsWith(`.${suffix}`)) {
        return true;
      }
      continue;
    }
    if (normalizedDomain === pattern) {
      return true;
    }
  }
  return false;
}

export function isDomainCoveredByDirectDomains(domain: string, directDomains: Iterable<string>): boolean {
  return isDomainCoveredByDirectDomainSuffixes(domain, normalizeProcessRouteDirectDomains(directDomains));
}

export function normalizeProcessRouteDirectDomains(directDomains: Iterable<string>): Set<string> {
  const normalized = new Set<string>();
  for (const directDomain of directDomains) {
    const suffix = normalizeProxyDomain(directDomain)?.replace(/^\./u, "");
    if (suffix) {
      normalized.add(suffix);
    }
  }
  return normalized;
}

export function isDomainCoveredByDirectDomainSuffixes(domain: string, directDomainSuffixes: ReadonlySet<string>): boolean {
  const normalizedDomain = domain.trim().toLowerCase().replace(/\.$/u, "");
  if (!validateRoutingRuleValue("domain", normalizedDomain).ok || normalizedDomain.startsWith("*.")) {
    return false;
  }
  let candidate = normalizedDomain;
  while (candidate) {
    if (directDomainSuffixes.has(candidate)) {
      return true;
    }
    const dot = candidate.indexOf(".");
    if (dot < 0) {
      return false;
    }
    candidate = candidate.slice(dot + 1);
  }
  return false;
}
