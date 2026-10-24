import { lookup } from "node:dns/promises";
import { openDirectEgressChannel } from "../core/network/direct-tcp-channel.js";
import type { DirectTcpIpChannel, DirectTcpIpTarget } from "../core/network/local-tcp-proxy.js";
import { parseIpAddressUnmapped, unmapIpv4MappedAddress } from "../core/routing/ip-address.js";
import { RoutingMatcher } from "../core/routing/routing-matcher.js";
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

export interface LocalRoutingEnforcerOptions {
  /**
   * Resolves a hostname to its addresses, for IP rules. Defaults to the
   * system resolver; injected by tests.
   */
  resolveHost?: (host: string) => Promise<string[]>;
  /** Injection seam for tests; defaults to the wall clock. */
  now?: () => number;
}

/** How long a resolved hostname is reused for IP-rule matching. */
export const HOST_RESOLUTION_TTL_MS = 30_000;
/** How long a failed or empty resolution is remembered, so a dead name is not asked per socket. */
const HOST_RESOLUTION_FAILURE_TTL_MS = 5_000;
/** Longest a connection waits on the resolver before it is routed without the answer. */
export const HOST_RESOLUTION_TIMEOUT_MS = 2_000;
/** Bounds the resolution cache. */
const MAX_RESOLVED_HOSTS = 512;
/** Bounds how many addresses of one name are matched. */
const MAX_RESOLVED_ADDRESSES = 16;

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
  private policyCache: CompiledLocalRouting | undefined;
  private userRulesCache: { rules: RoutingRule[]; matcher: RoutingMatcher; hasIpRules: boolean } | undefined;
  private readonly resolvedHosts = new Map<string, ResolvedHost>();
  private readonly resolveHost: (host: string) => Promise<string[]>;
  private readonly now: () => number;

  constructor(
    private readonly attribution: ProcessAttribution | undefined,
    options: LocalRoutingEnforcerOptions = {}
  ) {
    this.resolveHost = options.resolveHost ?? resolveHostAddresses;
    this.now = options.now ?? (() => Date.now());
  }

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
   * The shared routing order, the same on every path (see TrafficPolicy):
   *
   * 1. the transport's own endpoint stays direct - routing it into the tunnel
   *    it carries would deadlock the transport;
   * 2. an enabled domain or IP rule proxies, a private range or a `.local`
   *    name included: an explicit rule wins;
   * 3. a local or private destination no rule named stays direct;
   * 4. a `process.name` rule for the owning process proxies;
   * 5. the direct list keeps a destination direct;
   * 6. proxy-all proxies;
   * 7. the proxy list proxies;
   * 8. anything else goes direct.
   *
   * A `process.name` rule means "route everything this application sends to
   * the internet", so it comes before the direct list and cannot be
   * pre-empted by it, and after the local network, which it does not pull
   * into the tunnel.
   *
   * An IP rule also matches a hostname through the addresses it resolves to,
   * as it does in the PAC and at the TUN adapter: a connection here arrives
   * by name, and matching IP rules against literal addresses only made a
   * single app rule silently switch every IP rule off for browser traffic.
   * The resolver is asked only when the answer would otherwise be direct:
   * every rule proxies, so for a connection a process rule or a list already
   * tunnels the lookup could change only the reason logged.
   */
  async decide(
    context: LocalRoutingContext,
    target: DirectTcpIpTarget,
    originator: { address: string; port: number }
  ): Promise<LocalRoutingDecision> {
    const processName = await this.attribution?.resolveProcessName(originator.port);
    const compiled = this.compile(context);
    const destination = describeDestination(target.host);
    // The owning process is matched below, with the `.exe` normalisation the
    // rules are stored with, rather than inside the policy.
    const decision = compiled.policy.decide("tcp", { ...destination, destinationPort: target.port });
    const local = decision.blockedReason === "local-destination";

    if (decision.blockedReason && !local) {
      return { shouldProxy: false, reason: decision.blockedReason, processName };
    }
    if (decision.shouldProxy && (decision.reason === "domain" || decision.reason === "ip")) {
      return { shouldProxy: true, reason: decision.reason, processName };
    }
    if (!local && processName && compiled.processNames.has(normalizeWindowsProcessName(processName))) {
      return { shouldProxy: true, reason: "process.name", processName };
    }
    if (decision.shouldProxy) {
      return { shouldProxy: true, reason: decision.reason, processName };
    }
    if (
      destination.destinationDomain !== undefined &&
      compiled.ipRules !== undefined &&
      (await this.matchesResolvedAddress(compiled.ipRules, destination.destinationDomain))
    ) {
      // Step 2 by address: ahead of the local network and the direct list,
      // as a rule always is.
      return { shouldProxy: true, reason: "ip", processName };
    }
    return { shouldProxy: false, reason: local ? "local-destination" : decision.reason, processName };
  }

  /**
   * Whether an enabled domain or IP rule names `host` - step 2 of the shared
   * order, a hostname's resolved addresses included. For the SSH listener
   * where nothing enforces routing per connection: the system proxy or the
   * TUN adapter has already chosen what reaches it, and the local network it
   * still keeps direct must give way to a rule that names it.
   */
  async matchesUserRule(rules: RoutingRule[], host: string): Promise<boolean> {
    if (this.userRulesCache?.rules !== rules) {
      const matcher = new RoutingMatcher("selected-rules", rules);
      this.userRulesCache = { rules, matcher, hasIpRules: matcher.summary().ipRules > 0 };
    }
    const { matcher, hasIpRules } = this.userRulesCache;
    const destination = describeDestination(host);
    if (matcher.matchDestination(destination)) {
      return true;
    }
    return (
      destination.destinationDomain !== undefined &&
      hasIpRules &&
      (await this.matchesResolvedAddress(matcher, destination.destinationDomain))
    );
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
  private compile(context: LocalRoutingContext): CompiledLocalRouting {
    if (this.policyCache?.context !== context) {
      const ipRules = context.routingRules.filter((rule) => rule.type === "ip");
      const ipMatcher = new RoutingMatcher("selected-rules", ipRules);
      this.policyCache = {
        context,
        policy: new TrafficPolicy(context.routingMode, context.routingRules, {
          protectedSshEndpoint: context.protectedEndpoint,
          proxyListDomains: context.routingProxyDomains ?? [],
          directListDomains: context.routingDirectDomains ?? []
        }),
        processNames: enabledProcessRuleNames(context.routingRules),
        ipRules: ipMatcher.summary().ipRules > 0 ? ipMatcher : undefined
      };
    }
    return this.policyCache;
  }

  /**
   * Whether any address `host` resolves to falls under an IP rule. The
   * answer is cached briefly, and a resolver that does not answer in time
   * counts as no match: the connection is then routed on its name alone
   * rather than kept waiting.
   */
  private async matchesResolvedAddress(ipRules: RoutingMatcher, host: string): Promise<boolean> {
    const addresses = await this.resolvedAddresses(host);
    return addresses.some((address) => ipRules.match({ destinationIp: address }).reason === "ip");
  }

  private resolvedAddresses(host: string): Promise<string[]> {
    const key = host.trim().toLowerCase().replace(/\.$/u, "");
    const now = this.now();
    const cached = this.resolvedHosts.get(key);
    if (cached && cached.expiresAt > now) {
      // Refresh its place so names in use survive eviction.
      this.resolvedHosts.delete(key);
      this.resolvedHosts.set(key, cached);
      return cached.addresses;
    }
    const entry: ResolvedHost = {
      expiresAt: now + HOST_RESOLUTION_TTL_MS,
      addresses: withTimeout(this.resolveHost(key), HOST_RESOLUTION_TIMEOUT_MS)
        .then((answers) => normalizeResolvedAddresses(answers))
        .catch(() => [] as string[])
        .then((addresses) => {
          if (addresses.length === 0) {
            entry.expiresAt = Math.min(entry.expiresAt, this.now() + HOST_RESOLUTION_FAILURE_TTL_MS);
          }
          return addresses;
        })
    };
    this.resolvedHosts.delete(key);
    this.resolvedHosts.set(key, entry);
    while (this.resolvedHosts.size > MAX_RESOLVED_HOSTS) {
      const oldest = this.resolvedHosts.keys().next().value as string | undefined;
      if (oldest === undefined) {
        break;
      }
      this.resolvedHosts.delete(oldest);
    }
    return entry.addresses;
  }
}

interface CompiledLocalRouting {
  context: LocalRoutingContext;
  policy: TrafficPolicy;
  processNames: ReadonlySet<string>;
  /** The enabled IP rules alone, for matching a hostname's addresses; undefined when there are none. */
  ipRules: RoutingMatcher | undefined;
}

interface ResolvedHost {
  expiresAt: number;
  /** Shared by every connection to the name while the lookup is running. */
  addresses: Promise<string[]>;
}

async function resolveHostAddresses(host: string): Promise<string[]> {
  const answers = await lookup(host, { all: true, verbatim: true });
  return answers.map((answer) => answer.address);
}

function normalizeResolvedAddresses(addresses: string[]): string[] {
  const normalized: string[] = [];
  for (const address of addresses) {
    if (typeof address !== "string" || !parseIpAddressUnmapped(address)) {
      continue;
    }
    const value = unmapIpv4MappedAddress(address.trim());
    if (!normalized.includes(value)) {
      normalized.push(value);
    }
    if (normalized.length >= MAX_RESOLVED_ADDRESSES) {
      break;
    }
  }
  return normalized;
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out after ${timeoutMs} ms`)), timeoutMs);
    timer.unref?.();
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    );
  });
}

/** How many per-connection decisions of each direction reach the log. */
export const MAX_LOGGED_DECISIONS_PER_DIRECTION = 40;
/** Each direction's budget refills once this much time has passed. */
export const ROUTING_DECISION_LOG_WINDOW_MS = 60_000;

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
export interface RoutingDecisionLogOptions {
  limit?: number;
  windowMs?: number;
  /** Injection seam for tests; defaults to the wall clock. */
  now?: () => number;
}

export class RoutingDecisionLog {
  private tunnelled = 0;
  private direct = 0;
  private windowStartedAt: number | undefined;
  private readonly limit: number;
  private readonly windowMs: number;
  private readonly now: () => number;

  constructor(private readonly emit: (message: string) => void, options: RoutingDecisionLogOptions = {}) {
    this.limit = options.limit ?? MAX_LOGGED_DECISIONS_PER_DIRECTION;
    this.windowMs = options.windowMs ?? ROUTING_DECISION_LOG_WINDOW_MS;
    this.now = options.now ?? (() => Date.now());
  }

  /** Starts a fresh budget, so a reconnect is not silenced by the last session. */
  reset(): void {
    this.tunnelled = 0;
    this.direct = 0;
    this.windowStartedAt = undefined;
  }

  record(target: DirectTcpIpTarget, decision: LocalRoutingDecision): void {
    // A rolling window rather than a once-per-session cap: an earlier version
    // capped each direction for the whole session, so a busy browser exhausted
    // the budget in the first minute and the log then went permanently silent -
    // useless for watching a stall that starts later. The budget now refills
    // every window, so recent activity is always visible while a burst is still
    // bounded.
    const at = this.now();
    if (this.windowStartedAt === undefined || at - this.windowStartedAt >= this.windowMs) {
      this.windowStartedAt = at;
      this.tunnelled = 0;
      this.direct = 0;
    }
    const count = decision.shouldProxy ? (this.tunnelled += 1) : (this.direct += 1);
    if (count > this.limit) {
      return;
    }
    if (count === this.limit) {
      const seconds = Math.round(this.windowMs / 1000);
      this.emit(
        decision.shouldProxy
          ? `Further tunnelled routing decisions are suppressed for up to ${seconds}s.`
          : `Further direct routing decisions are suppressed for up to ${seconds}s.`
      );
      return;
    }
    this.emit(describeRoutingDecision(target, decision));
  }
}

/**
 * Splits a proxy target into the descriptor fields the matcher expects. A
 * literal address must be offered as an IP so CIDR rules can match it, while a
 * hostname must stay a domain so it is not parsed as an address. An
 * IPv4-mapped IPv6 literal (`::ffff:a.b.c.d`) is the IPv4 host it carries, so
 * IPv4 rules, the local ranges and the protected endpoint all see it as one.
 */
export function describeDestination(host: string): { destinationDomain?: string; destinationIp?: string } {
  const value = host.trim().replace(/^\[|\]$/gu, "");
  return parseIpAddressUnmapped(value) ? { destinationIp: unmapIpv4MappedAddress(value) } : { destinationDomain: value };
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
