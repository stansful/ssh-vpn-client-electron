import { normalizeProxyDomain } from "../../../../core/routing/domain-proxy-list.js";
import { proxyProtocolMark } from "../../../../shared/proxy-protocols.js";
import { validateRoutingRuleValue } from "../../../../shared/validation.js";
import type { AppSnapshot, AppStore, GlobalTab, ProxyProfile, RoutingRuleType, SshConfig } from "../../../../shared/types.js";
import { formatHostPort, formatProfileAddress, formatProfileSummary, formatSshTarget, initials, plural } from "../../../lib/format.js";

/** What the Connect hero shows in its picker and copy for one transport. */
export interface ConnectTarget {
  kind: GlobalTab;
  /** Saved server/profile id; undefined when the session's item was deleted meanwhile. */
  id?: string;
  name: string;
  /** Mono second line: "root@203.0.113.10:22" or "VLESS · 185.244.30.9:443 · tcp · reality". */
  sub: string;
  /** host:port the transport dials; every hop port for Hysteria 2 port hopping ("example.com:443,20000-30000"). */
  address?: string;
  /** Avatar text: "FR" for a server, "VL" for a VLESS profile, "HY" for Hysteria 2. */
  initials: string;
  config?: SshConfig;
  profile?: ProxyProfile;
  /** Which part of the profile the bundled Xray engine can't run. */
  unsupported?: "security" | "transport";
  /**
   * The Hysteria 2 link asks to skip certificate checks (insecure=1) without a
   * pinSHA256. It can still connect; a self-signed server fails.
   */
  insecureWithoutPin?: boolean;
  /** The public list no longer offers this profile. */
  stale?: boolean;
}

export interface TargetState {
  /** The running session's target on this transport, else the saved selection. */
  target?: ConnectTarget;
  /** Nothing is saved for this transport yet. */
  noneSaved: boolean;
  /** Items exist but none is selected (or the selection points at a deleted item). */
  noneSelected: boolean;
  /** Saved servers or profiles for this transport. */
  count: number;
  /** The target belongs to a session running on this transport (picker shows it, not the selection). */
  fromSession: boolean;
}

export function profileInitials(profile: Pick<ProxyProfile, "protocol">): string {
  return proxyProtocolMark(profile.protocol);
}

export function unsupportedPart(profile: Pick<ProxyProfile, "security" | "transport">): ConnectTarget["unsupported"] {
  if (profile.security === "unknown") {
    return "security";
  }
  return profile.transport === "unknown" ? "transport" : undefined;
}

export function sshTarget(config: SshConfig): ConnectTarget {
  return {
    kind: "ssh",
    id: config.id,
    name: config.name,
    sub: formatSshTarget(config),
    address: formatHostPort(config.host, config.port),
    initials: initials(config.name),
    config
  };
}

export function profileTarget(profile: ProxyProfile): ConnectTarget {
  return {
    kind: "xray",
    id: profile.id,
    name: profile.name,
    sub: formatProfileSummary(profile),
    address: formatProfileAddress(profile),
    initials: profileInitials(profile),
    profile,
    unsupported: unsupportedPart(profile),
    insecureWithoutPin: profile.insecureWithoutPin || undefined,
    stale: profile.isStale || undefined
  };
}

/** A session keeps the server/profile it started with; edits and selection changes apply to the next connect. */
function hasSessionOn(snapshot: Pick<AppSnapshot, "activeTransport" | "runtime">, transport: GlobalTab): boolean {
  const { state } = snapshot.runtime;
  return snapshot.activeTransport === transport && state !== "Disconnected" && state !== "Error";
}

/**
 * Resolves what the hero describes for `transport`: while a session runs on
 * it, the server/profile the session started with (even if it was renamed or
 * deleted since); otherwise the saved selection.
 */
export function resolveTarget(snapshot: Pick<AppSnapshot, "store" | "runtime" | "activeTransport">, transport: GlobalTab): TargetState {
  const { store, runtime } = snapshot;
  const session = hasSessionOn(snapshot, transport);
  if (transport === "ssh") {
    const count = store.sshConfigs.length;
    if (session) {
      const config = store.sshConfigs.find((candidate) => candidate.id === runtime.activeConfigId);
      if (config) {
        return { target: sshTarget(config), noneSaved: false, noneSelected: false, count, fromSession: true };
      }
      if (runtime.activeConfigName) {
        return {
          target: {
            kind: "ssh",
            name: runtime.activeConfigName,
            sub: runtime.activeTarget ?? "",
            address: runtime.activeTarget,
            initials: initials(runtime.activeConfigName)
          },
          noneSaved: false,
          noneSelected: false,
          count,
          fromSession: true
        };
      }
    }
    const selected = store.sshConfigs.find((candidate) => candidate.id === store.selectedConfigId);
    return {
      target: selected ? sshTarget(selected) : undefined,
      noneSaved: count === 0,
      noneSelected: count > 0 && !selected,
      count,
      fromSession: false
    };
  }

  const count = store.proxyProfiles.length;
  if (session) {
    const profile = store.proxyProfiles.find((candidate) => candidate.id === runtime.activeConfigId);
    if (profile) {
      return { target: profileTarget(profile), noneSaved: false, noneSelected: false, count, fromSession: true };
    }
    if (runtime.activeConfigName) {
      return {
        target: {
          kind: "xray",
          name: runtime.activeConfigName,
          sub: runtime.activeTarget ?? "",
          address: runtime.activeTarget,
          initials: initials(runtime.activeConfigName)
        },
        noneSaved: false,
        noneSelected: false,
        count,
        fromSession: true
      };
    }
  }
  const selected =
    store.proxyProfiles.find((candidate) => candidate.id === store.selectedProxyProfileId) ??
    store.proxyProfiles.find((candidate) => candidate.isSelected);
  return {
    target: selected ? profileTarget(selected) : undefined,
    noneSaved: count === 0,
    noneSelected: count > 0 && !selected,
    count,
    fromSession: false
  };
}

/** Name of what the other transport runs, for "Xray is connected · de-fra-reality". */
export function sessionTargetName(snapshot: Pick<AppSnapshot, "store" | "runtime" | "activeTransport">): string | undefined {
  return resolveTarget(snapshot, snapshot.activeTransport).target?.name ?? snapshot.runtime.activeConfigName;
}

type RoutingState = Pick<AppStore, "routingMode" | "routingRules" | "routingProxyList" | "routingDirectList">;

/** Display names of the curated domain lists (see the rename table in the brief). */
export const PROXY_LIST_NAME = "Blocked in Russia";
export const DIRECT_LIST_NAME = "Russian services";

function usableRuleCounts(store: Pick<AppStore, "routingRules">): Record<RoutingRuleType, number> {
  const counts: Record<RoutingRuleType, number> = { domain: 0, ip: 0, "process.name": 0 };
  for (const rule of store.routingRules) {
    if (rule.enabled && validateRoutingRuleValue(rule.type, rule.value).ok) {
      counts[rule.type] += 1;
    }
  }
  return counts;
}

function proxyListRoutes(store: Pick<AppStore, "routingProxyList">): boolean {
  return store.routingProxyList.enabled && store.routingProxyList.domains.some((domain) => normalizeProxyDomain(domain) !== undefined);
}

/**
 * Split tunnel needs at least one enabled, valid rule or a non-empty
 * "Blocked in Russia" list; mirrors the main process's connect guard.
 */
export function hasRoutingTargets(store: Pick<AppStore, "routingRules" | "routingProxyList">): boolean {
  const counts = usableRuleCounts(store);
  return counts.domain + counts.ip + counts["process.name"] > 0 || proxyListRoutes(store);
}

export interface RoutingSummary {
  split: boolean;
  /** "Split tunnel" / "Full tunnel". */
  title: string;
  sub: string;
  /** Outline badges: "9 domains", "3 IPs", "2 apps", "Blocked in Russia list". */
  badges: string[];
  /** Split tunnel with nothing to route: connecting is paused. */
  blocked: boolean;
  /** Hint under the picker while off and ready. */
  hint: string;
}

export function summarizeRouting(store: RoutingState): RoutingSummary {
  const split = store.routingMode === "selected-rules";
  if (!split) {
    const directList = store.routingDirectList.enabled && store.routingDirectList.domains.length > 0;
    return {
      split,
      title: "Full tunnel",
      sub: "All traffic goes through the tunnel. Sites on the Russian services list stay direct when the system proxy is used.",
      badges: directList ? ["All traffic", `${DIRECT_LIST_NAME} stay direct`] : ["All traffic"],
      blocked: false,
      hint: directList
        ? `Full tunnel: all your traffic uses it, except the ${DIRECT_LIST_NAME} list.`
        : "Full tunnel: all your traffic uses it."
    };
  }
  const counts = usableRuleCounts(store);
  const listOn = proxyListRoutes(store);
  const ruleTotal = counts.domain + counts.ip + counts["process.name"];
  const badges: string[] = [];
  if (counts.domain > 0) {
    badges.push(plural(counts.domain, "domain"));
  }
  if (counts.ip > 0) {
    badges.push(plural(counts.ip, "IP"));
  }
  if (counts["process.name"] > 0) {
    badges.push(plural(counts["process.name"], "app"));
  }
  if (listOn) {
    badges.push(`${PROXY_LIST_NAME} list`);
  }
  let hint: string;
  if (ruleTotal > 0 && listOn) {
    hint = `Split tunnel: only your routing rules and the ${PROXY_LIST_NAME} list use it.`;
  } else if (ruleTotal > 0) {
    hint = "Split tunnel: only your routing rules use it.";
  } else if (listOn) {
    hint = `Split tunnel: only the ${PROXY_LIST_NAME} list uses it.`;
  } else {
    hint = "Split tunnel: nothing is picked yet.";
  }
  return {
    split,
    title: "Split tunnel",
    sub: "Only the apps, sites and IPs you choose use the tunnel. Everything else stays direct.",
    badges,
    blocked: ruleTotal === 0 && !listOn,
    hint
  };
}
