export interface DnsCacheEntry {
  domain: string;
  addresses: string[];
  expiresAt: number;
}

export class DomainIpCache {
  private readonly entries = new Map<string, DnsCacheEntry>();

  set(domain: string, addresses: string[], ttlMs: number, now = Date.now()): void {
    const normalized = normalizeDomain(domain);
    this.entries.set(normalized, {
      domain: normalized,
      addresses: Array.from(new Set(addresses)),
      expiresAt: now + ttlMs
    });
  }

  get(domain: string, now = Date.now()): string[] {
    const normalized = normalizeDomain(domain);
    const entry = this.entries.get(normalized);
    if (!entry) {
      return [];
    }
    if (entry.expiresAt <= now) {
      this.entries.delete(normalized);
      return [];
    }
    return [...entry.addresses];
  }

  findDomainsForIp(ip: string, now = Date.now()): string[] {
    const domains: string[] = [];
    for (const [domain, entry] of this.entries) {
      if (entry.expiresAt <= now) {
        this.entries.delete(domain);
        continue;
      }
      if (entry.addresses.includes(ip)) {
        domains.push(domain);
      }
    }
    return domains;
  }

  prune(now = Date.now()): void {
    for (const [domain, entry] of this.entries) {
      if (entry.expiresAt <= now) {
        this.entries.delete(domain);
      }
    }
  }
}

function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/\.$/u, "");
}
