import { RoutingMatcher, type RoutingMatch, type TrafficDescriptor } from "./routing-matcher.js";
import type { RoutingMode, RoutingRule } from "../../shared/types.js";

export type TransportProtocol = "tcp" | "udp";

export interface TrafficPolicyDecision extends RoutingMatch {
  protocol: TransportProtocol;
  blockedReason?: "udp-not-supported" | "protected-ssh-connection";
}

export interface TrafficPolicyOptions {
  udpSupported?: boolean;
  protectedSshEndpoint?: {
    host: string;
    port: number;
  };
}

export class TrafficPolicy {
  private readonly matcher: RoutingMatcher;
  private readonly udpSupported: boolean;
  private readonly protectedSshEndpoint?: { host: string; port: number };

  constructor(mode: RoutingMode, rules: RoutingRule[], options: boolean | TrafficPolicyOptions = false) {
    this.matcher = new RoutingMatcher(mode, rules);
    if (typeof options === "boolean") {
      this.udpSupported = options;
    } else {
      this.udpSupported = options.udpSupported ?? false;
      this.protectedSshEndpoint = options.protectedSshEndpoint
        ? {
            host: options.protectedSshEndpoint.host.trim().toLowerCase(),
            port: options.protectedSshEndpoint.port
          }
        : undefined;
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

    return {
      protocol,
      ...this.matcher.match(descriptor)
    };
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
