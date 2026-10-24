import type { RoutingMode, RoutingRule } from "../../shared/types.js";
import { normalizeRuleValue, validateRoutingRuleValue } from "../../shared/validation.js";
import { ipMatchesCidr, parseCidrRange, parseIpAddressUnmapped, type ParsedCidrRange } from "./ip-address.js";

export interface TrafficDescriptor {
  destinationDomain?: string;
  destinationIp?: string;
  processName?: string;
}

export interface RoutingMatch {
  shouldProxy: boolean;
  reason: "proxy-all" | "domain" | "ip" | "process.name" | "no-match" | "no-enabled-rules";
  ruleId?: string;
}

export interface RoutingMatcherSummary {
  mode: RoutingMode;
  enabledRules: number;
  domainRules: number;
  ipRules: number;
  processRules: number;
  invalidRules: number;
}

interface CompiledDomainRule {
  id: string;
  order: number;
}

interface CompiledIpRule {
  id: string;
  range: ParsedCidrRange;
}

interface CompiledProcessRule {
  id: string;
}

export class RoutingMatcher {
  // A plain `example.com` rule covers the domain and every subdomain, matching
  // how curated proxy-list entries behave. Exact-host-only matching made a rule
  // silently miss `www.` and the API/CDN subdomains almost every site depends
  // on, which made custom rules look inert next to the lists.
  private readonly domains = new Map<string, CompiledDomainRule>();
  private readonly wildcardDomains = new Map<string, CompiledDomainRule>();
  private readonly ips: CompiledIpRule[] = [];
  private readonly processes = new Map<string, CompiledProcessRule>();
  private domainRules = 0;
  private processRules = 0;
  private invalidRules = 0;

  constructor(
    private readonly mode: RoutingMode,
    rules: RoutingRule[]
  ) {
    for (const [order, rule] of rules.entries()) {
      if (!rule.enabled) {
        continue;
      }
      if (!validateRoutingRuleValue(rule.type, rule.value).ok) {
        this.invalidRules += 1;
        continue;
      }
      const normalized = normalizeRuleValue(rule.type, rule.value);
      if (rule.type === "domain") {
        const wildcard = normalized.startsWith("*.");
        const pattern = wildcard ? normalized.slice(2) : normalized;
        const index = wildcard ? this.wildcardDomains : this.domains;
        // Map insertion is intentionally first-wins: duplicate rule IDs/values
        // historically matched the earliest enabled rule in the source array.
        if (!index.has(pattern)) {
          index.set(pattern, {
            id: rule.id,
            order
          });
        }
        this.domainRules += 1;
        continue;
      }
      if (rule.type === "ip") {
        const range = parseCidrRange(normalized);
        if (range) {
          this.ips.push({ id: rule.id, range });
        } else {
          this.invalidRules += 1;
        }
        continue;
      }
      if (!this.processes.has(normalized)) {
        this.processes.set(normalized, { id: rule.id });
      }
      this.processRules += 1;
    }
  }

  /**
   * Matches the user's own rules in the shared routing order: a domain or IP
   * rule, then a process rule, and only then proxy-all. Every rule proxies,
   * so the order changes only the reported reason here; it matters to callers
   * that place the local network between the two kinds of rule and the
   * direct list between the rules and proxy-all (see TrafficPolicy).
   */
  match(descriptor: TrafficDescriptor): RoutingMatch {
    if (this.mode !== "proxy-all" && this.enabledRulesCount() === 0) {
      return this.unmatched();
    }
    return this.matchDestination(descriptor) ?? this.matchProcess(descriptor.processName) ?? this.unmatched();
  }

  /** A domain or IP rule naming the destination - the step ahead of the local network - or undefined. */
  matchDestination(descriptor: Pick<TrafficDescriptor, "destinationDomain" | "destinationIp">): RoutingMatch | undefined {
    const domain = descriptor.destinationDomain?.trim().toLowerCase();
    if (domain) {
      const matched = this.matchDomain(domain);
      if (matched) {
        return { shouldProxy: true, reason: "domain", ruleId: matched.id };
      }
    }

    const ip = descriptor.destinationIp ? parseIpAddressUnmapped(descriptor.destinationIp) : undefined;
    if (ip) {
      const matched = this.ips.find((rule) => ipMatchesCidr(ip, rule.range));
      if (matched) {
        return { shouldProxy: true, reason: "ip", ruleId: matched.id };
      }
    }
    return undefined;
  }

  /** A process rule for the owning process, compared case-insensitively as written, or undefined. */
  matchProcess(processName: string | undefined): RoutingMatch | undefined {
    const name = processName?.trim().toLowerCase();
    const matched = name ? this.processes.get(name) : undefined;
    return matched ? { shouldProxy: true, reason: "process.name", ruleId: matched.id } : undefined;
  }

  /** The answer when no rule matches: proxy-all, or direct as "no-match" or "no-enabled-rules". */
  unmatched(): RoutingMatch {
    if (this.mode === "proxy-all") {
      return { shouldProxy: true, reason: "proxy-all" };
    }
    return this.enabledRulesCount() === 0
      ? { shouldProxy: false, reason: "no-enabled-rules" }
      : { shouldProxy: false, reason: "no-match" };
  }

  summary(): RoutingMatcherSummary {
    return {
      mode: this.mode,
      enabledRules: this.enabledRulesCount(),
      domainRules: this.domainRules,
      ipRules: this.ips.length,
      processRules: this.processRules,
      invalidRules: this.invalidRules
    };
  }

  private enabledRulesCount(): number {
    return this.domainRules + this.ips.length + this.processRules;
  }

  private matchDomain(domain: string): CompiledDomainRule | undefined {
    let matched = this.domains.get(domain);
    // A plain rule also matches through any parent label, while a wildcard only
    // matches a strict subdomain. Walking label boundaries makes lookup
    // proportional to domain depth rather than total rule count.
    let separator = domain.indexOf(".");
    while (separator >= 0 && separator + 1 < domain.length) {
      const parent = domain.slice(separator + 1);
      for (const candidate of [this.domains.get(parent), this.wildcardDomains.get(parent)]) {
        if (candidate && (!matched || candidate.order < matched.order)) {
          matched = candidate;
        }
      }
      separator = domain.indexOf(".", separator + 1);
    }
    return matched;
  }
}
