import { openDirectEgressChannel } from "../core/network/direct-tcp-channel.js";
import type { DirectTcpIpChannel, DirectTcpIpTarget } from "../core/network/local-tcp-proxy.js";
import { parseIpAddress } from "../core/routing/ip-address.js";
import {
  isDomainCoveredByDirectDomainSuffixes,
  normalizeProcessRouteDirectDomains
} from "../core/routing/process-route-domains.js";
import { TrafficPolicy } from "../core/routing/traffic-policy.js";
import { normalizeWindowsProcessName } from "../core/network/windows-process-connections.js";
import type { RoutingMode, RoutingRule } from "../shared/types.js";
import { normalizeRuleValue, validateRoutingRuleValue } from "../shared/validation.js";
import type { ProcessAttribution } from "./process-attribution.js";

export interface LocalRoutingContext {
  routingMode: RoutingMode;
  routingRules: RoutingRule[];
  routingProxyDomains?: string[];
  /**
   * Evaluated locally rather than in the PAC, so that it cannot pre-empt an
   * explicit process rule. See {@link LocalRoutingEnforcer.decide}.
   */
  routingDirectDomains?: string[];
  /**
   * The transport's own server endpoint. It must never be routed back into the
   * tunnel it carries, which would deadlock the transport.
   */
  protectedEndpoint?: { host: string; port: number };
}

export interface LocalRoutingDecision {
  shouldProxy: boolean;
  reason: string;
  processName?: string;
}

/**
 * Decides, per connection, whether traffic belongs in the tunnel.
 *
 * Windows PAC cannot express process identity, so a `process.name` rule can
 * only be honoured where the owning process is known: on the local listener.
 * While this enforcement is active the system proxy hands the listener every
 * proxy-aware TCP connection, and this class evaluates domain, IP and process
 * rules together for each one. Traffic that matches nothing is given an
 * ordinary direct socket, so unselected applications are unaffected.
 *
 * Both transports share this class so their routing behaviour cannot diverge.
 */
export class LocalRoutingEnforcer {
  private policyCache: {
    context: LocalRoutingContext;
    policy: TrafficPolicy;
    processNames: ReadonlySet<string>;
    proxyListSuffixes: ReadonlySet<string>;
    directListSuffixes: ReadonlySet<string>;
  } | undefined;

  constructor(private readonly attribution: ProcessAttribution | undefined) {}

  /**
   * Reports whether this connection can enforce process rules locally. The
   * answer must be settled before the system proxy is applied, because routing
   * everything to a listener that cannot recognise processes would silently
   * disable the tunnel.
   */
  async isEnforceable(context: LocalRoutingContext, platform: NodeJS.Platform = process.platform): Promise<boolean> {
    return (await this.describeEnforceability(context, platform)).enforceable;
  }

  /**
   * The same answer with the reason attached.
   *
   * Falling back to the PAC path changes what a `process.name` rule can reach,
   * and it happens for several unrelated causes. Reporting only the fallback -
   * as this did - leaves the user watching per-process routing stop working
   * with nothing in the log to act on.
   */
  async describeEnforceability(
    context: LocalRoutingContext,
    platform: NodeJS.Platform = process.platform
  ): Promise<{ enforceable: boolean; reason?: string }> {
    if (platform !== "win32") {
      return { enforceable: false, reason: "per-process enforcement is only implemented on Windows" };
    }
    if (context.routingMode !== "selected-rules") {
      return { enforceable: false };
    }
    if (!hasEnabledProcessRule(context.routingRules)) {
      return { enforceable: false };
    }
    if (!this.attribution) {
      return { enforceable: false, reason: "the native helper is not configured for this build" };
    }
    if (await this.attribution.isAvailable()) {
      return { enforceable: true };
    }
    return {
      enforceable: false,
      reason: this.attribution.unavailableReason?.() ?? "the native helper could not read the process table"
    };
  }

  /**
   * Order matters here.
   *
   * A `process.name` rule means "route everything this application sends", so
   * it is evaluated before the direct list and cannot be pre-empted by it. That
   * is also why the direct list is applied here instead of in the PAC: the PAC
   * runs before the listener and has no process context, so a direct-list entry
   * there would silently carve holes in a selected application's traffic.
   *
   * The transport's own endpoint stays excluded regardless, because routing it
   * into the tunnel it carries would deadlock the transport.
   */
  async decide(
    context: LocalRoutingContext,
    target: DirectTcpIpTarget,
    originator: { address: string; port: number }
  ): Promise<LocalRoutingDecision> {
    const processName = await this.attribution?.resolveProcessName(originator.port);
    const { policy, processNames, proxyListSuffixes, directListSuffixes } = this.compile(context);
    const destination = describeDestination(target.host);
    const decision = policy.decide("tcp", {
      ...destination,
      destinationPort: target.port,
      processName
    });

    if (decision.blockedReason) {
      return { shouldProxy: false, reason: decision.blockedReason, processName };
    }
    if (processName && processNames.has(normalizeWindowsProcessName(processName))) {
      return { shouldProxy: true, reason: "process.name", processName };
    }
    if (decision.shouldProxy) {
      return { shouldProxy: true, reason: decision.reason, processName };
    }
    // The curated proxy list is not expressible as routing rules - its entries
    // include bare suffixes such as `.ua` - so it is matched separately with
    // the domain-or-parent semantics the PAC applies to it.
    if (
      destination.destinationDomain !== undefined &&
      isDomainCoveredByDirectDomainSuffixes(destination.destinationDomain, proxyListSuffixes)
    ) {
      return { shouldProxy: true, reason: "proxy-list", processName };
    }
    if (
      destination.destinationDomain !== undefined &&
      isDomainCoveredByDirectDomainSuffixes(destination.destinationDomain, directListSuffixes)
    ) {
      return { shouldProxy: false, reason: "direct-list", processName };
    }
    return { shouldProxy: false, reason: decision.reason, processName };
  }

  /**
   * Opens the egress path for one connection: the transport's tunnel when a
   * rule matches, an ordinary direct socket otherwise.
   */
  async openChannel(
    context: LocalRoutingContext,
    target: DirectTcpIpTarget,
    originator: { address: string; port: number },
    openTunnelChannel: () => Promise<DirectTcpIpChannel>,
    signal?: AbortSignal
  ): Promise<{ channel: DirectTcpIpChannel; decision: LocalRoutingDecision }> {
    const decision = await this.decide(context, target, originator);
    const channel = decision.shouldProxy
      ? await openTunnelChannel()
      : await openDirectEgressChannel(target, { signal });
    return { channel, decision };
  }

  /**
   * Compiles the matcher once per routing revision. A curated proxy list holds
   * tens of thousands of domains, so rebuilding it per accepted socket would
   * put a full list scan on the connection hot path.
   */
  private compile(context: LocalRoutingContext): {
    policy: TrafficPolicy;
    processNames: ReadonlySet<string>;
    proxyListSuffixes: ReadonlySet<string>;
    directListSuffixes: ReadonlySet<string>;
  } {
    if (this.policyCache?.context !== context) {
      this.policyCache = {
        context,
        policy: new TrafficPolicy(context.routingMode, context.routingRules, {
          protectedSshEndpoint: context.protectedEndpoint
        }),
        processNames: enabledProcessRuleNames(context.routingRules),
        proxyListSuffixes: normalizeProcessRouteDirectDomains(context.routingProxyDomains ?? []),
        directListSuffixes: normalizeProcessRouteDirectDomains(context.routingDirectDomains ?? [])
      };
    }
    return this.policyCache;
  }
}

/** How many per-connection decisions of each direction reach the log. */
export const MAX_LOGGED_DECISIONS_PER_DIRECTION = 60;

/** Renders one routing decision for the diagnostics log. */
export function describeRoutingDecision(target: DirectTcpIpTarget, decision: LocalRoutingDecision): string {
  const origin = decision.processName ? ` from ${decision.processName}` : "";
  const egress = decision.shouldProxy ? "Tunnel" : "Direct";
  return `${egress} egress for ${target.host}:${target.port}${origin} (${decision.reason}).`;
}

/**
 * Caps how many per-connection decisions reach the log, counting each
 * direction separately.
 *
 * The separate budgets are the point. Only the direct branch used to be
 * logged, so a log full of `Direct egress` lines could not distinguish "no
 * rule matched this traffic" from "every rule matched and the tunnel behind
 * them is dead" - which is the question every routing complaint actually turns
 * on. Logging both directions from one shared budget would have reintroduced
 * the same blindness by a different route, because a browser opens hundreds of
 * unmatched sockets a minute and would spend the whole budget before a single
 * tunnelled line was written.
 *
 * Both transports share this so their diagnostics cannot drift apart.
 */
export class RoutingDecisionLog {
  private tunnelled = 0;
  private direct = 0;

  constructor(
    private readonly emit: (message: string) => void,
    private readonly limit: number = MAX_LOGGED_DECISIONS_PER_DIRECTION
  ) {}

  /** Starts a fresh budget, so a reconnect is not silenced by the last session. */
  reset(): void {
    this.tunnelled = 0;
    this.direct = 0;
  }

  record(target: DirectTcpIpTarget, decision: LocalRoutingDecision): void {
    const count = decision.shouldProxy ? (this.tunnelled += 1) : (this.direct += 1);
    if (count > this.limit) {
      return;
    }
    if (count === this.limit) {
      this.emit(
        decision.shouldProxy
          ? "Further tunnelled routing decisions are suppressed for this session."
          : "Further direct routing decisions are suppressed for this session."
      );
      return;
    }
    this.emit(describeRoutingDecision(target, decision));
  }
}

/**
 * Splits a proxy target into the descriptor fields the matcher expects. A
 * literal address must be offered as an IP so CIDR rules can match it, while a
 * hostname must stay a domain so it is not parsed as an address.
 */
export function describeDestination(host: string): { destinationDomain?: string; destinationIp?: string } {
  const value = host.trim().replace(/^\[|\]$/gu, "");
  return parseIpAddress(value) ? { destinationIp: value } : { destinationDomain: value };
}

export function hasEnabledProcessRule(rules: RoutingRule[]): boolean {
  return rules.some(
    (rule) => rule.enabled && rule.type === "process.name" && validateRoutingRuleValue(rule.type, rule.value).ok
  );
}

export function enabledProcessRuleNames(rules: RoutingRule[]): Set<string> {
  return new Set(
    rules
      .filter((rule) => rule.enabled && rule.type === "process.name")
      .filter((rule) => validateRoutingRuleValue(rule.type, rule.value).ok)
      .map((rule) => normalizeWindowsProcessName(normalizeRuleValue("process.name", rule.value)))
      .filter(Boolean)
  );
}
