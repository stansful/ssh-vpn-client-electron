import { RoutingMatcher, type RoutingMatch, type TrafficDescriptor } from "./routing-matcher.js";
import { isLocalDestinationHost, isLocalDestinationIp } from "./ip-address.js";
import { isDomainCoveredByDirectDomainSuffixes, normalizeProcessRouteDirectDomains } from "./process-route-domains.js";
import type { RoutingMode, RoutingRule } from "../../shared/types.js";

export type TransportProtocol = "tcp" | "udp";

export interface TrafficPolicyDecision extends Omit<RoutingMatch, "reason"> {
  reason: RoutingMatch["reason"] | "direct-list" | "proxy-list";
  protocol: TransportProtocol;
  blockedReason?: "udp-not-supported" | "protected-ssh-connection" | "local-destination";
}

export interface TrafficPolicyOptions {
  udpSupported?: boolean;
  protectedSshEndpoint?: {
    host: string;
    port: number;
  };
  /** The curated proxy list ("Blocked in Russia"), in the form the list parser returns. */
  proxyListDomains?: Iterable<string>;
  /** The curated direct list ("Russian services"), in the form the list parser returns. */
  directListDomains?: Iterable<string>;
}

/**
 * The routing decision every path shares, in this order:
 *
 * 1. the transport's own protected endpoint stays direct;
 * 2. an enabled domain or IP rule proxies - an explicit rule wins, so a rule
 *    for a private range or a `.local` name reaches the network behind the
 *    server;
 * 3. a local or private destination no rule named stays direct;
 * 4. a process rule for the owning process proxies;
 * 5. a destination on the direct list stays direct;
 * 6. proxy-all proxies;
 * 7. a destination on the proxy list proxies;
 * 8. anything else stays direct.
 *
 * The PAC, Xray's routing and the native TUN policy implement the same order
 * (the TUN policy adds the transport's own process right after step 1), so a
 * destination is routed alike whichever path carries it. Each path applies it
 * once: what the TUN adapter or the routing listener hands on to the
 * transport is tunnelled as it arrives - a private address a domain rule
 * picked by a learned name comes as a bare address no rule here matches - and
 * only what the Windows proxy hands over gets step 3 again (see
 * LiveSshServiceBridge.openProxyChannel and XrayConfigInput.localNetworkDirect). A process rule comes
 * after step 3: it means "everything this application sends to the
 * internet", not its LAN traffic. The lists take part only when they are
 * passed in options.
 *
 * One path cannot keep step 4 where it is: the PAC fallback cannot tell which
 * application asks. What process discovery learned for a process rule
 * reaches it as addresses and names, which it checks after the direct list
 * (see buildProxyPac) - so there a direct-list site stays direct for the
 * selected application too, where the TUN adapter and the routing listener
 * tunnel it. And process rules act only in split tunnel there, while the TUN
 * adapter applies them in full tunnel as well.
 */
export class TrafficPolicy {
  private readonly matcher: RoutingMatcher;
  private readonly udpSupported: boolean;
  private readonly protectedSshEndpoint?: { host: string; port: number };
  private readonly proxyListSuffixes: ReadonlySet<string>;
  private readonly directListSuffixes: ReadonlySet<string>;

  constructor(mode: RoutingMode, rules: RoutingRule[], options: boolean | TrafficPolicyOptions = false) {
    this.matcher = new RoutingMatcher(mode, rules);
    if (typeof options === "boolean") {
      this.udpSupported = options;
      this.proxyListSuffixes = new Set();
      this.directListSuffixes = new Set();
    } else {
      this.udpSupported = options.udpSupported ?? false;
      this.protectedSshEndpoint = options.protectedSshEndpoint
        ? {
            host: options.protectedSshEndpoint.host.trim().toLowerCase(),
            port: options.protectedSshEndpoint.port
          }
        : undefined;
      this.proxyListSuffixes = normalizeProcessRouteDirectDomains(options.proxyListDomains ?? []);
      this.directListSuffixes = normalizeProcessRouteDirectDomains(options.directListDomains ?? []);
    }
  }

  decide(protocol: TransportProtocol, descriptor: TrafficDescriptor & { destinationPort?: number }): TrafficPolicyDecision {
    if (protocol === "udp" && !this.udpSupported) {
      return {
        protocol,
        shouldProxy: false,
        reason: "no-match",
        blockedReason: "udp-not-supported"
      };
    }

    if (this.isProtectedSshConnection(descriptor)) {
      return {
        protocol,
        shouldProxy: false,
        reason: "no-match",
        blockedReason: "protected-ssh-connection"
      };
    }

    const rule = this.matcher.matchDestination(descriptor);
    if (rule) {
      return { protocol, ...rule };
    }

    if (isLocalDestination(descriptor)) {
      return {
        protocol,
        shouldProxy: false,
        reason: "no-match",
        blockedReason: "local-destination"
      };
    }

    const processRule = this.matcher.matchProcess(descriptor.processName);
    if (processRule) {
      return { protocol, ...processRule };
    }
    const domain = descriptor.destinationDomain;
    if (domain && isDomainCoveredByDirectDomainSuffixes(domain, this.directListSuffixes)) {
      return { protocol, shouldProxy: false, reason: "direct-list" };
    }
    const unmatched = this.matcher.unmatched();
    if (unmatched.shouldProxy) {
      return { protocol, ...unmatched };
    }
    if (domain && isDomainCoveredByDirectDomainSuffixes(domain, this.proxyListSuffixes)) {
      return { protocol, shouldProxy: true, reason: "proxy-list" };
    }
    return { protocol, ...unmatched };
  }

  private isProtectedSshConnection(descriptor: TrafficDescriptor & { destinationPort?: number }): boolean {
    if (!this.protectedSshEndpoint || descriptor.destinationPort !== this.protectedSshEndpoint.port) {
      return false;
    }

    const domain = descriptor.destinationDomain?.trim().toLowerCase();
    const ip = descriptor.destinationIp?.trim().toLowerCase();
    return domain === this.protectedSshEndpoint.host || ip === this.protectedSshEndpoint.host;
  }
}

function isLocalDestination(descriptor: TrafficDescriptor): boolean {
  if (descriptor.destinationIp !== undefined && isLocalDestinationIp(descriptor.destinationIp)) {
    return true;
  }
  return descriptor.destinationDomain !== undefined && isLocalDestinationHost(descriptor.destinationDomain);
}
