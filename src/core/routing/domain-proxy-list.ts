const MAX_PROXY_DOMAINS = 20_000;
const DOMAIN_TOKEN = /^[*.]?[a-z0-9][a-z0-9.-]*[a-z0-9]$/iu;

export function parseDomainProxyList(text: string): string[] {
  const domains = new Set<string>();
  for (const token of text.split(/\s+/u)) {
    const domain = normalizeProxyDomain(token);
    if (!domain) {
      continue;
    }
    domains.add(domain);
    if (domains.size > MAX_PROXY_DOMAINS) {
      throw new Error(`Domain proxy list is larger than ${MAX_PROXY_DOMAINS} entries.`);
    }
  }
  return [...domains].sort((left, right) => left.localeCompare(right));
}

export function normalizeProxyDomain(value: string): string | undefined {
  const trimmed = value.trim().toLowerCase().replace(/\.$/u, "");
  if (!trimmed || trimmed.startsWith("#")) {
    return undefined;
  }
  const normalized = trimmed.startsWith("*.") ? trimmed.slice(1) : trimmed;
  if (normalized.includes("/") || normalized.includes(":") || normalized.includes("@")) {
    return undefined;
  }
  if (!DOMAIN_TOKEN.test(normalized)) {
    return undefined;
  }
  return normalized;
}
