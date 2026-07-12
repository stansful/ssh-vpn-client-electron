export interface DnsCacheEntry {
  domain: string;
  addresses: string[];
  expiresAt: number;
}

export interface DomainIpCacheOptions {
  maxEntries?: number;
  maxAddressesPerEntry?: number;
  maxTtlMs?: number;
}

export const DEFAULT_DNS_CACHE_MAX_ENTRIES = 4096;
export const DEFAULT_DNS_CACHE_MAX_ADDRESSES = 16;
export const DEFAULT_DNS_CACHE_MAX_TTL_MS = 24 * 60 * 60 * 1000;

export class DomainIpCache {
  private readonly entries = new Map<string, DnsCacheEntry>();
  private readonly domainsByIp = new Map<string, Set<string>>();
  private readonly maxEntries: number;
  private readonly maxAddressesPerEntry: number;
  private readonly maxTtlMs: number;

  constructor(options: DomainIpCacheOptions = {}) {
    this.maxEntries = positiveInteger(options.maxEntries, DEFAULT_DNS_CACHE_MAX_ENTRIES);
    this.maxAddressesPerEntry = positiveInteger(options.maxAddressesPerEntry, DEFAULT_DNS_CACHE_MAX_ADDRESSES);
    this.maxTtlMs = positiveInteger(options.maxTtlMs, DEFAULT_DNS_CACHE_MAX_TTL_MS);
  }

  set(domain: string, addresses: string[], ttlMs: number, now = Date.now()): void {
    const normalized = normalizeDomain(domain);
    this.delete(normalized);
    if (!normalized || !Number.isFinite(ttlMs) || ttlMs <= 0) {
      return;
    }
    const uniqueAddresses: string[] = [];
    const seenAddresses = new Set<string>();
    for (const address of addresses) {
      if (!address || seenAddresses.has(address)) {
        continue;
      }
      seenAddresses.add(address);
      uniqueAddresses.push(address);
      if (uniqueAddresses.length >= this.maxAddressesPerEntry) {
        break;
      }
    }
    if (uniqueAddresses.length === 0) {
      return;
    }
    if (this.entries.size >= this.maxEntries) {
      this.prune(now);
    }
    while (this.entries.size >= this.maxEntries) {
      const oldestDomain = this.entries.keys().next().value as string | undefined;
      if (!oldestDomain) {
        break;
      }
      this.delete(oldestDomain);
    }
    const entry = {
      domain: normalized,
      addresses: uniqueAddresses,
      expiresAt: now + Math.min(ttlMs, this.maxTtlMs)
    };
    this.entries.set(normalized, entry);
    for (const address of entry.addresses) {
      const domains = this.domainsByIp.get(address) ?? new Set<string>();
      domains.add(normalized);
      this.domainsByIp.set(address, domains);
    }
  }

  get(domain: string, now = Date.now()): string[] {
    const normalized = normalizeDomain(domain);
    const entry = this.entries.get(normalized);
    if (!entry) {
      return [];
    }
    if (entry.expiresAt <= now) {
      this.delete(normalized);
      return [];
    }
    // Map insertion order doubles as a bounded LRU without another list.
    this.entries.delete(normalized);
    this.entries.set(normalized, entry);
    return [...entry.addresses];
  }

  findDomainsForIp(ip: string, now = Date.now()): string[] {
    const domains: string[] = [];
    for (const domain of this.domainsByIp.get(ip) ?? []) {
      const entry = this.entries.get(domain);
      if (!entry) {
        continue;
      }
      if (entry.expiresAt <= now) {
        this.delete(domain);
        continue;
      }
      domains.push(domain);
    }
    return domains;
  }

  prune(now = Date.now()): void {
    for (const [domain, entry] of this.entries) {
      if (entry.expiresAt <= now) {
        this.delete(domain);
      }
    }
  }

  get size(): number {
    return this.entries.size;
  }

  private delete(domain: string): void {
    const entry = this.entries.get(domain);
    if (!entry) {
      return;
    }
    this.entries.delete(domain);
    for (const address of entry.addresses) {
      const domains = this.domainsByIp.get(address);
      domains?.delete(domain);
      if (domains?.size === 0) {
        this.domainsByIp.delete(address);
      }
    }
  }
}

function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/\.$/u, "");
}

function positiveInteger(value: number | undefined, fallback: number): number {
  return Number.isSafeInteger(value) && Number(value) > 0 ? Number(value) : fallback;
}
