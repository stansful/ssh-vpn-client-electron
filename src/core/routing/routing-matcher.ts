import type { RoutingMode, RoutingRule } from "../../shared/types.js";
import { normalizeRuleValue, validateRoutingRuleValue } from "../../shared/validation.js";
import { ipMatchesCidr, parseCidrRange, parseIpAddress, type ParsedCidrRange } from "./ip-address.js";

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
  private readonly exactDomains = new Map<string, CompiledDomainRule>();
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
        const index = wildcard ? this.wildcardDomains : this.exactDomains;
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

  match(descriptor: TrafficDescriptor): RoutingMatch {
    if (this.mode === "proxy-all") {
      return { shouldProxy: true, reason: "proxy-all" };
    }

    if (this.enabledRulesCount() === 0) {
      return { shouldProxy: false, reason: "no-enabled-rules" };
    }

    const domain = descriptor.destinationDomain?.trim().toLowerCase();
    if (domain) {
      const matched = this.matchDomain(domain);
      if (matched) {
        return { shouldProxy: true, reason: "domain", ruleId: matched.id };
      }
    }

    const ip = descriptor.destinationIp ? parseIpAddress(descriptor.destinationIp) : undefined;
    if (ip) {
      const matched = this.ips.find((rule) => ipMatchesCidr(ip, rule.range));
      if (matched) {
        return { shouldProxy: true, reason: "ip", ruleId: matched.id };
      }
    }

    const processName = descriptor.processName?.trim().toLowerCase();
    if (processName) {
      const matched = this.processes.get(processName);
      if (matched) {
        return { shouldProxy: true, reason: "process.name", ruleId: matched.id };
      }
    }

    return { shouldProxy: false, reason: "no-match" };
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
    let matched = this.exactDomains.get(domain);
    // A wildcard only matches a strict subdomain. Walking label boundaries
    // makes lookup proportional to domain depth rather than total rule count.
    let separator = domain.indexOf(".");
    while (separator >= 0 && separator + 1 < domain.length) {
      const wildcard = this.wildcardDomains.get(domain.slice(separator + 1));
      if (wildcard && (!matched || wildcard.order < matched.order)) {
        matched = wildcard;
      }
      separator = domain.indexOf(".", separator + 1);
    }
    return matched;
  }
}
