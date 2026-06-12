import type { RoutingMode, RoutingRule } from "../../shared/types.js";
import { normalizeRuleValue } from "../../shared/validation.js";
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
  pattern: string;
  wildcard: boolean;
}

interface CompiledIpRule {
  id: string;
  range: ParsedCidrRange;
}

interface CompiledProcessRule {
  id: string;
  name: string;
}

export class RoutingMatcher {
  private readonly domains: CompiledDomainRule[] = [];
  private readonly ips: CompiledIpRule[] = [];
  private readonly processes: CompiledProcessRule[] = [];
  private invalidRules = 0;

  constructor(
    private readonly mode: RoutingMode,
    rules: RoutingRule[]
  ) {
    for (const rule of rules) {
      if (!rule.enabled) {
        continue;
      }
      const normalized = normalizeRuleValue(rule.type, rule.value);
      if (rule.type === "domain") {
        this.domains.push({
          id: rule.id,
          pattern: normalized.startsWith("*.") ? normalized.slice(2) : normalized,
          wildcard: normalized.startsWith("*.")
        });
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
      this.processes.push({ id: rule.id, name: normalized });
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
      const matched = this.domains.find((rule) => domainMatches(rule, domain));
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
      const matched = this.processes.find((rule) => rule.name === processName);
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
      domainRules: this.domains.length,
      ipRules: this.ips.length,
      processRules: this.processes.length,
      invalidRules: this.invalidRules
    };
  }

  private enabledRulesCount(): number {
    return this.domains.length + this.ips.length + this.processes.length;
  }
}

function domainMatches(rule: CompiledDomainRule, domain: string): boolean {
  if (rule.wildcard) {
    return domain.endsWith(`.${rule.pattern}`) && domain.length > rule.pattern.length + 1;
  }
  return domain === rule.pattern;
}
