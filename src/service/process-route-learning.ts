import {
  isAutoLearnableRemoteAddress,
  normalizeWindowsProcessName,
  type WindowsProcessConnection
} from "../core/network/windows-process-connections.js";
import type { WindowsDnsCacheEntry } from "../core/network/windows-dns-cache.js";
import {
  isDomainCoveredByDirectDomainSuffixes,
  isDomainCoveredByRoutePatterns,
  LEARNED_PROCESS_IP_RULE_PREFIX,
  MAX_PROCESS_ROUTE_SESSION_LEASES,
  normalizeProcessRouteDirectDomains,
  processRouteDomainHints,
  type ProcessRouteSessionEvidence
} from "../core/routing/process-route-domains.js";
import { isLocalDestinationHost } from "../core/routing/ip-address.js";
import type { RoutingRule } from "../shared/types.js";
import { normalizeRuleValue, validateRoutingRuleValue } from "../shared/validation.js";

const PROCESS_ROUTE_TTL_MS = 5 * 60 * 1000;
const PROCESS_ROUTE_REFRESH_INTERVAL_MS = 10 * 1000;
const PROCESS_ROUTE_DISCOVERY_DELAYS_MS = [1_000, 2_000, 4_000, 8_000] as const;
const PROCESS_ROUTE_DNS_REFRESH_MS = 5 * 60 * 1000;
const PROCESS_ROUTE_DNS_MIN_REFRESH_MS = 1_000;
const PROCESS_ROUTE_DNS_RETRY_BASE_MS = 10_000;

export interface ProcessRouteLearnerOptions {
  connectionsProvider: (processNames: Iterable<string>) => Promise<WindowsProcessConnection[]>;
  dnsEntriesProvider: (addresses: Iterable<string>) => Promise<WindowsDnsCacheEntry[]>;
  /** The steady refresh cadence the platform asks for; 10 s when absent. */
  refreshIntervalMs?: () => number;
  onWarning: (message: string) => void;
  /** Names the transport in a warning that has to say which one it is, e.g. " for Xray transport". */
  transportLabel?: string;
}

/**
 * What process-name routing has learned on the proxy path, where a PAC file
 * cannot see which process opened a connection: the remote addresses the
 * selected applications were seen talking to, and the names those addresses
 * had in the Windows DNS cache. The transport turns them into PAC rules (see
 * {@link buildSelectedRulesWithProcessIps}) and decides when to publish them;
 * this only learns, and keeps the result bounded.
 *
 * Both transports run the same heuristics through this, so a fix to one is a
 * fix to the other.
 */
export class ProcessRouteLearner {
  /** Learned literal addresses, by when each was last observed. */
  ips = new Map<string, number>();
  /** Learned exact names, by when each expires. */
  domains = new Map<string, number>();
  /** Addresses promoted on high-confidence evidence, kept for the session. */
  sessionLeases = new Map<string, ProcessRouteSessionEvidence>();
  /** The signature of the routes learned last; see {@link buildProcessRouteSignature}. */
  lastSignature = "";
  /** The signature the transport last published successfully. */
  appliedSignature = "";
  /** Set while learned routes still have to be published. */
  applyPending = false;
  lastMatchedConnections = 0;
  /** A failed cycle is reported once, until the targets change or the transport resets it for a new session. */
  warningEmitted = false;
  private hintDomains = new Set<string>();
  private dnsLookupAt = new Map<string, number>();
  private dnsLookupFailures = new Map<string, number>();
  private profileCoveredAddresses = new Map<string, number>();
  private targetSignature = "";
  private dnsWarningEmitted = false;
  private discoveryStep = 0;
  private readonly requestedRefreshIntervalMs: () => number;

  constructor(private readonly options: ProcessRouteLearnerOptions) {
    this.requestedRefreshIntervalMs = options.refreshIntervalMs ?? (() => PROCESS_ROUTE_REFRESH_INTERVAL_MS);
  }

  /** Restarts the short discovery burst for a monitor that is starting. */
  beginDiscovery(): void {
    this.discoveryStep = 0;
  }

  /** Forgets everything learned, for a session or a routing path that no longer needs it. */
  clear(): void {
    this.ips.clear();
    this.hintDomains.clear();
    this.domains.clear();
    this.dnsLookupAt.clear();
    this.dnsLookupFailures.clear();
    this.profileCoveredAddresses.clear();
    this.sessionLeases.clear();
    this.lastSignature = "";
    this.appliedSignature = "";
    this.targetSignature = "";
    this.applyPending = false;
    this.lastMatchedConnections = 0;
    this.dnsWarningEmitted = false;
  }

  /**
   * Runs one discovery cycle: which remote addresses the selected processes
   * hold open now, and which names those addresses had in the Windows DNS
   * cache. Returns whether the learned routes changed.
   *
   * `isStale` is asked after every wait; once it says the routing this cycle
   * serves was replaced, the cycle stops without committing anything further.
   * `publishLiteralIpSnapshot`, when given, receives the literal-IP routes
   * before the DNS phase runs.
   */
  async learn(
    rules: RoutingRule[],
    directDomains: string[] = [],
    isStale: () => boolean = () => false,
    publishLiteralIpSnapshot?: (signature: string) => Promise<void>
  ): Promise<boolean> {
    if (!supportsDynamicProcessRouting("selected-rules", rules)) {
      return false;
    }
    if (isStale()) {
      return false;
    }
    const directDomainSuffixes = normalizeProcessRouteDirectDomains(directDomains);
    const signatureBeforeLearning = this.lastSignature;
    const literalIpsBeforeLearning = new Set(this.ips.keys());

    try {
      const processNames = enabledProcessRuleNames(rules);
      this.resetForTargets(processNames);
      const connections = await this.options.connectionsProvider(processNames);
      if (isStale()) {
        return false;
      }
      const now = Date.now();
      const routeTtlMs = this.ttlMs();
      const expiresBefore = now - routeTtlMs;
      // A learned destination can never be observed a second time: as soon as it
      // enters the PAC the application connects to the loopback proxy instead of
      // the real remote address, so Get-NetTCPConnection stops reporting it and
      // nothing re-populates its Windows DNS cache entry. Expiring such a route
      // on its original TTL therefore dropped a destination the application was
      // still actively using back to DIRECT, which is why process-name routing
      // only ever covered part of an application's traffic. Renew every retained
      // route on each successful discovery cycle instead: routes live for the
      // connected session (bounded by the LRU caps, and cleared by stopRouting()
      // or a routing-target change) and only decay once discovery itself has
      // been failing for a full TTL.
      const nextIps = new Map(
        [...this.ips]
          .filter((entry) => entry[1] >= expiresBefore)
          .map(([address]) => [address, now] as const)
      );
      const nextDomains = new Map(
        [...this.domains]
          .filter((entry) =>
            entry[1] > now && !isDomainCoveredByDirectDomainSuffixes(entry[0], directDomainSuffixes)
          )
          .map(([domain]) => [domain, now + routeTtlMs] as const)
      );
      const activeProfileCoveredAddresses = new Map(
        [...this.profileCoveredAddresses]
          .filter((entry) => entry[1] > now)
          .map(([address]) => [address, now + routeTtlMs] as const)
      );
      const nextSessionLeases = new Map(this.sessionLeases);
      const knownAddressesBeforeObservation = new Set([
        ...nextIps.keys(),
        ...activeProfileCoveredAddresses.keys(),
        ...nextSessionLeases.keys()
      ]);
      const observedAddresses = new Set<string>();
      const unprofiledAddresses = new Set<string>();
      const processOwnersByAddress = new Map<string, Set<string>>();
      const profilePatternsByAddress = new Map<string, Set<string>>();
      const profilePatternsByProcess = new Map(
        [...processNames].map((processName) => [processName, processRouteDomainHints([processName])] as const)
      );
      let matchedConnections = 0;
      for (const connection of connections) {
        const processName = normalizeWindowsProcessName(connection.processName);
        if (processNames.has(processName)) {
          matchedConnections += 1;
          observedAddresses.add(connection.remoteAddress);
          recordBoundedProcessRouteIp(nextIps, connection.remoteAddress, now);
          const owners = processOwnersByAddress.get(connection.remoteAddress) ?? new Set<string>();
          owners.add(processName);
          processOwnersByAddress.set(connection.remoteAddress, owners);
          const profilePatterns = profilePatternsByProcess.get(processName) ?? new Set<string>();
          if (profilePatterns.size === 0) {
            unprofiledAddresses.add(connection.remoteAddress);
          } else {
            const addressPatterns = profilePatternsByAddress.get(connection.remoteAddress) ?? new Set<string>();
            for (const pattern of profilePatterns) {
              addressPatterns.add(pattern);
            }
            profilePatternsByAddress.set(connection.remoteAddress, addressPatterns);
          }
        }
      }
      this.lastMatchedConnections = matchedConnections;

      for (const [address, lease] of [...nextSessionLeases]) {
        if (isDomainCoveredByDirectDomainSuffixes(lease.domain, directDomainSuffixes)) {
          nextSessionLeases.delete(address);
        }
      }

      for (const address of [...activeProfileCoveredAddresses.keys()]) {
        if (profilePatternsByAddress.has(address) && !unprofiledAddresses.has(address)) {
          activeProfileCoveredAddresses.set(address, now + routeTtlMs);
          nextIps.delete(address);
        }
      }

      // Publish the literal-IP fallback before the optional DNS cache query.
      // Dynamic process IPs intentionally do not resolve PAC hostnames, so this
      // fast path only helps clients that give PAC an already-resolved IP. DNS
      // enrichment below remains the required hostname-routing phase.
      const literalIpSnapshotChanged = this.commit(
        nextIps,
        nextDomains,
        activeProfileCoveredAddresses,
        nextSessionLeases
      );
      const literalIpSetChanged =
        literalIpsBeforeLearning.size !== nextIps.size ||
        [...literalIpsBeforeLearning].some((address) => !nextIps.has(address));
      if (
        directDomainSuffixes.size === 0 &&
        literalIpSnapshotChanged &&
        literalIpSetChanged &&
        publishLiteralIpSnapshot
      ) {
        await publishLiteralIpSnapshot(this.lastSignature);
        if (isStale()) {
          return false;
        }
      }

      const dnsLookupAddresses = [...observedAddresses].filter((address) => {
        const nextLookupAt = this.dnsLookupAt.get(address);
        return nextLookupAt === undefined || now >= nextLookupAt;
      });
      if (dnsLookupAddresses.length > 0) {
        for (const address of dnsLookupAddresses) {
          const failures = Math.min((this.dnsLookupFailures.get(address) ?? 0) + 1, 16);
          const retryDelay = Math.min(
            PROCESS_ROUTE_DNS_REFRESH_MS,
            PROCESS_ROUTE_DNS_RETRY_BASE_MS * 2 ** Math.min(failures - 1, 5)
          );
          recordBoundedProcessRouteIp(this.dnsLookupFailures, address, failures);
          recordBoundedProcessRouteIp(this.dnsLookupAt, address, now + retryDelay);
        }
        try {
          const dnsEntries = await this.options.dnsEntriesProvider(dnsLookupAddresses);
          if (isStale()) {
            return false;
          }
          const configuredDomainPatterns = rules
            .filter((rule) => rule.enabled && rule.type === "domain" && validateRoutingRuleValue(rule.type, rule.value).ok)
            .map((rule) => normalizeRuleValue("domain", rule.value));
          const stableDomainPatterns = [...this.hintDomains, ...configuredDomainPatterns];
          const addressesWithDnsEntries = new Set<string>();
          const profileCoveredAddresses = new Set<string>();
          const validDnsEntriesByTuple = new Map<string, WindowsDnsCacheEntry>();
          for (const entry of dnsEntries) {
            const domain = normalizeRuleValue("domain", entry.domain).replace(/\.$/u, "");
            if (
              !observedAddresses.has(entry.address) ||
              !Number.isSafeInteger(entry.ttlSeconds) ||
              entry.ttlSeconds <= 0 ||
              domain.startsWith("*.") ||
              !validateRoutingRuleValue("domain", domain).ok
            ) {
              continue;
            }
            const key = `${entry.address}\u0000${domain}`;
            const existing = validDnsEntriesByTuple.get(key);
            if (!existing || entry.ttlSeconds > existing.ttlSeconds) {
              validDnsEntriesByTuple.set(key, { ...entry, domain });
            }
          }
          const validDnsEntries = [...validDnsEntriesByTuple.values()];
          const exactDomainsByAddress = new Map<string, Set<string>>();
          for (const entry of validDnsEntries) {
            addressesWithDnsEntries.add(entry.address);
            const domains = exactDomainsByAddress.get(entry.address) ?? new Set<string>();
            domains.add(entry.domain);
            exactDomainsByAddress.set(entry.address, domains);
            const profilePatterns = profilePatternsByAddress.get(entry.address);
            if (profilePatterns && isDomainCoveredByRoutePatterns(entry.domain, profilePatterns)) {
              profileCoveredAddresses.add(entry.address);
            }
          }
          const dnsRefreshAtByAddress = new Map<string, number>();
          for (const entry of validDnsEntries) {
            const ttlMs = Math.min(routeTtlMs, PROCESS_ROUTE_DNS_REFRESH_MS, entry.ttlSeconds * 1000);
            const refreshAt = now + Math.max(PROCESS_ROUTE_DNS_MIN_REFRESH_MS, ttlMs);
            const currentRefreshAt = dnsRefreshAtByAddress.get(entry.address);
            if (currentRefreshAt === undefined || refreshAt < currentRefreshAt) {
              dnsRefreshAtByAddress.set(entry.address, refreshAt);
            }
          }

          const promotedSessionLeaseAddresses = new Set<string>();
          for (const address of dnsLookupAddresses) {
            const owners = processOwnersByAddress.get(address);
            const soleProcessName = owners?.size === 1 ? owners.values().next().value as string | undefined : undefined;
            const exactDomains = exactDomainsByAddress.get(address) ?? new Set<string>();
            const exactDomain = exactDomains.size === 1
              ? exactDomains.values().next().value as string | undefined
              : undefined;
            const hasProfileEvidence =
              profilePatternsByAddress.has(address) ||
              profileCoveredAddresses.has(address) ||
              activeProfileCoveredAddresses.has(address);
            const isHighConfidenceEvidence = Boolean(
              soleProcessName &&
              exactDomain &&
              (profilePatternsByProcess.get(soleProcessName)?.size ?? 0) === 0 &&
              !hasProfileEvidence &&
              isAutoLearnableRemoteAddress(address) &&
              !isDomainCoveredByDirectDomainSuffixes(exactDomain, directDomainSuffixes)
            );
            if (
              isHighConfidenceEvidence &&
              soleProcessName &&
              exactDomain &&
              !knownAddressesBeforeObservation.has(address) &&
              nextSessionLeases.size < MAX_PROCESS_ROUTE_SESSION_LEASES
            ) {
              nextSessionLeases.set(address, {
                processName: soleProcessName,
                address,
                domain: exactDomain,
                firstObservedAt: now
              });
              promotedSessionLeaseAddresses.add(address);
            }
          }

          for (const entry of validDnsEntries) {
            const profilePatterns = profilePatternsByAddress.get(entry.address);
            const restrictToReviewedProfile =
              (profileCoveredAddresses.has(entry.address) || activeProfileCoveredAddresses.has(entry.address)) &&
              !unprofiledAddresses.has(entry.address);
            if (
              restrictToReviewedProfile &&
              (!profilePatterns || !isDomainCoveredByRoutePatterns(entry.domain, profilePatterns))
            ) {
              continue;
            }
            if (!isDomainCoveredByRoutePatterns(
              entry.domain,
              stableDomainPatterns
            ) && !isDomainCoveredByDirectDomainSuffixes(entry.domain, directDomainSuffixes)) {
              // The record TTL only says when the Windows DNS cache entry has to
              // be re-read (dnsRefreshAtByAddress above); it says nothing about
              // how long the application keeps using the hostname. Binding the
              // PAC route to it expired CDN/API hosts after a few tens of
              // seconds, so route on the process-route TTL and let the renewal
              // above keep it alive for the session.
              recordBoundedProcessRouteDomain(nextDomains, entry.domain, now + routeTtlMs);
            }
          }
          for (const address of addressesWithDnsEntries) {
            const refreshAt = dnsRefreshAtByAddress.get(address) ?? now + PROCESS_ROUTE_DNS_RETRY_BASE_MS;
            recordBoundedProcessRouteIp(this.dnsLookupAt, address, refreshAt);
            this.dnsLookupFailures.delete(address);
          }
          for (const address of promotedSessionLeaseAddresses) {
            recordBoundedProcessRouteIp(
              this.dnsLookupAt,
              address,
              now + PROCESS_ROUTE_DNS_RETRY_BASE_MS
            );
          }
          for (const address of profileCoveredAddresses) {
            recordBoundedProcessRouteIp(
              activeProfileCoveredAddresses,
              address,
              now + routeTtlMs
            );
            if (!unprofiledAddresses.has(address)) {
              nextIps.delete(address);
            }
          }
          if (addressesWithDnsEntries.size > 0) {
            this.dnsWarningEmitted = false;
          }
        } catch (error) {
          for (const address of dnsLookupAddresses) {
            if (nextSessionLeases.has(address) && observedAddresses.has(address)) {
              recordBoundedProcessRouteIp(nextIps, address, now);
            }
          }
          if (!this.dnsWarningEmitted) {
            this.dnsWarningEmitted = true;
            this.options.onWarning(
              `Process-name DNS enrichment failed${this.options.transportLabel ?? ""}; IP fallback remains active: ${error instanceof Error ? error.message : String(error)}`
            );
          }
        }
      }

      this.commit(
        nextIps,
        nextDomains,
        activeProfileCoveredAddresses,
        nextSessionLeases
      );
      return this.lastSignature !== signatureBeforeLearning;
    } catch (error) {
      this.lastMatchedConnections = 0;
      this.domains = new Map(
        [...this.domains].filter((entry) =>
          !isDomainCoveredByDirectDomainSuffixes(entry[0], directDomainSuffixes)
        )
      );
      this.sessionLeases = new Map(
        [...this.sessionLeases].filter((entry) =>
          !isDomainCoveredByDirectDomainSuffixes(entry[1].domain, directDomainSuffixes)
        )
      );
      const changed = this.pruneExpired();
      if (!this.warningEmitted) {
        this.warningEmitted = true;
        this.options.onWarning(
          `Process-name routing monitor failed: ${error instanceof Error ? error.message : String(error)}`
        );
      }
      return changed;
    }
  }

  private commit(
    ips: ReadonlyMap<string, number>,
    domains: ReadonlyMap<string, number>,
    profileCoveredAddresses: ReadonlyMap<string, number>,
    sessionLeases: ReadonlyMap<string, ProcessRouteSessionEvidence>
  ): boolean {
    const signature = buildProcessRouteSignature(
      ips.keys(),
      [
        ...this.hintDomains,
        ...domains.keys(),
        ...[...sessionLeases.values()].map((lease) => lease.domain)
      ]
    );
    const changed = signature !== this.lastSignature;
    // Clone the phase-local maps so DNS enrichment cannot mutate the
    // published interim snapshot while its PAC application is in flight.
    this.ips = new Map(ips);
    this.domains = new Map(domains);
    this.profileCoveredAddresses = new Map(profileCoveredAddresses);
    this.sessionLeases = new Map(sessionLeases);
    this.lastSignature = signature;
    return changed;
  }

  /** The steady refresh cadence, as configured, within sane bounds. */
  refreshIntervalMs(): number {
    try {
      const requested = this.requestedRefreshIntervalMs();
      return Number.isFinite(requested) && requested >= 1_000
        ? Math.min(requested, 10 * 60 * 1000)
        : PROCESS_ROUTE_REFRESH_INTERVAL_MS;
    } catch {
      return PROCESS_ROUTE_REFRESH_INTERVAL_MS;
    }
  }

  /** The delay before the next cycle: a short discovery burst after {@link beginDiscovery}, then the steady cadence. */
  nextRefreshIntervalMs(): number {
    const discoveryDelay = PROCESS_ROUTE_DISCOVERY_DELAYS_MS[this.discoveryStep];
    if (discoveryDelay !== undefined) {
      this.discoveryStep += 1;
      return discoveryDelay;
    }
    return this.refreshIntervalMs();
  }

  ttlMs(): number {
    return Math.max(PROCESS_ROUTE_TTL_MS, this.refreshIntervalMs() * 3);
  }

  currentIps(): Set<string> {
    return new Set(this.ips.keys());
  }

  currentDomains(): Set<string> {
    return new Set([
      ...this.hintDomains,
      ...this.domains.keys(),
      ...[...this.sessionLeases.values()].map((lease) => lease.domain)
    ]);
  }

  private pruneExpired(now = Date.now()): boolean {
    const expiresBefore = now - this.ttlMs();
    const nextIps = new Map([...this.ips].filter((entry) => entry[1] >= expiresBefore));
    const nextDomains = new Map([...this.domains].filter((entry) => entry[1] > now));
    const activeProfileCoveredAddresses = new Map(
      [...this.profileCoveredAddresses].filter((entry) => entry[1] > now)
    );
    const nextSignature = buildProcessRouteSignature(
      nextIps.keys(),
      [
        ...this.hintDomains,
        ...nextDomains.keys(),
        ...[...this.sessionLeases.values()].map((lease) => lease.domain)
      ]
    );
    const changed = nextSignature !== this.lastSignature;
    this.ips = nextIps;
    this.domains = nextDomains;
    this.profileCoveredAddresses = activeProfileCoveredAddresses;
    this.lastSignature = nextSignature;
    return changed;
  }

  private resetForTargets(processNames: Set<string>): void {
    const targetSignature = [...processNames].sort().join(",");
    if (targetSignature === this.targetSignature) {
      return;
    }
    this.targetSignature = targetSignature;
    this.ips.clear();
    this.hintDomains.clear();
    this.domains.clear();
    this.dnsLookupAt.clear();
    for (const domain of processRouteDomainHints(processNames)) {
      this.hintDomains.add(domain);
    }
    this.dnsLookupFailures.clear();
    this.profileCoveredAddresses.clear();
    this.sessionLeases.clear();
    this.lastSignature = "";
    this.appliedSignature = "";
    this.applyPending = false;
    this.lastMatchedConnections = 0;
    this.warningEmitted = false;
    this.dnsWarningEmitted = false;
  }
}

/**
 * The user's rules plus what process discovery learned, as rules the PAC can
 * read. Learned destinations on the local network are left out: they stand
 * for a process rule, which comes after the local network in the shared
 * order, and as rules they would rank with the user's own - which win over
 * it - and pull a selected application's LAN traffic into the tunnel.
 */
export function buildSelectedRulesWithProcessIps(
  rules: RoutingRule[],
  processIps: ReadonlySet<string>,
  processDomains: ReadonlySet<string> = new Set()
): RoutingRule[] {
  if (processIps.size === 0 && processDomains.size === 0) {
    return rules;
  }

  const existingIpRules = new Set(
    rules.filter((rule) => rule.enabled && rule.type === "ip").map((rule) => normalizeRuleValue("ip", rule.value).toLowerCase())
  );
  const existingDomainRules = new Set(
    rules.filter((rule) => rule.enabled && rule.type === "domain").map((rule) => normalizeRuleValue("domain", rule.value))
  );
  const now = new Date(0).toISOString();
  const dynamicDomainRules = [...processDomains]
    .map((domain) => normalizeRuleValue("domain", domain))
    .filter((domain) => validateRoutingRuleValue("domain", domain).ok && !isLocalDestinationHost(domain))
    .filter((domain) => !existingDomainRules.has(domain))
    .sort()
    .map<RoutingRule>((domain) => ({
      id: `process-domain:${domain}`,
      type: "domain",
      value: domain,
      enabled: true,
      createdAt: now,
      updatedAt: now
    }));
  const dynamicIpRules = [...processIps]
    .map((ip) => ip.trim())
    .filter((ip) => validateRoutingRuleValue("ip", ip).ok && !isLocalDestinationHost(ip))
    .filter((ip) => !existingIpRules.has(ip.toLowerCase()))
    .sort()
    .map<RoutingRule>((ip) => ({
      id: `${LEARNED_PROCESS_IP_RULE_PREFIX}${ip}`,
      type: "ip",
      value: ip,
      enabled: true,
      createdAt: now,
      updatedAt: now
    }));

  return [...rules, ...dynamicDomainRules, ...dynamicIpRules];
}

export const MAX_LEARNED_PROCESS_ROUTE_IPS = 2048;
export const MAX_LEARNED_PROCESS_ROUTE_DOMAINS = 512;

export function recordBoundedProcessRouteIp(
  entries: Map<string, number>,
  ip: string,
  observedAt: number,
  maximum = MAX_LEARNED_PROCESS_ROUTE_IPS
): void {
  if (maximum <= 0) {
    entries.clear();
    return;
  }
  // Refresh insertion order so actively used destinations survive eviction.
  entries.delete(ip);
  entries.set(ip, observedAt);
  while (entries.size > maximum) {
    const oldest = entries.keys().next().value as string | undefined;
    if (!oldest) {
      break;
    }
    entries.delete(oldest);
  }
}

export function recordBoundedProcessRouteDomain(
  entries: Map<string, number>,
  domain: string,
  expiresAt: number,
  maximum = MAX_LEARNED_PROCESS_ROUTE_DOMAINS
): void {
  const normalized = normalizeRuleValue("domain", domain).replace(/\.$/u, "");
  if (normalized.startsWith("*.") || !validateRoutingRuleValue("domain", normalized).ok) {
    return;
  }
  if (maximum <= 0) {
    entries.clear();
    return;
  }
  entries.delete(normalized);
  entries.set(normalized, expiresAt);
  while (entries.size > maximum) {
    const oldest = entries.keys().next().value as string | undefined;
    if (!oldest) {
      break;
    }
    entries.delete(oldest);
  }
}

export function buildProcessRouteSignature(processIps: Iterable<string>, processDomains: Iterable<string>): string {
  return [
    `ips:${[...processIps].sort().join(",")}`,
    `domains:${[...processDomains].sort().join(",")}`
  ].join("|");
}

export function supportsDynamicProcessRouting(mode: string, rules: RoutingRule[], platform: NodeJS.Platform = process.platform): boolean {
  return platform === "win32" && mode === "selected-rules" && enabledProcessRuleNames(rules).size > 0;
}

function enabledProcessRuleNames(rules: RoutingRule[]): Set<string> {
  return new Set(
    rules
      .filter((rule) => rule.enabled && rule.type === "process.name")
      .filter((rule) => validateRoutingRuleValue(rule.type, rule.value).ok)
      .map((rule) => normalizeWindowsProcessName(normalizeRuleValue("process.name", rule.value)))
      .filter(Boolean)
  );
}
