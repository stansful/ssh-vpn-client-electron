const MAX_PROXY_DOMAINS = 20_000;
const MAX_DOMAIN_LENGTH = 253;
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/iu;

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
  const suffixRule = trimmed.startsWith(".") || trimmed.startsWith("*.");
  const domain = trimmed.startsWith("*.")
    ? trimmed.slice(2)
    : trimmed.startsWith(".")
      ? trimmed.slice(1)
      : trimmed;
  if (!domain || domain.length > MAX_DOMAIN_LENGTH) {
    return undefined;
  }
  const labels = domain.split(".");
  // A leading dot intentionally represents a TLD suffix such as `.ru` in the
  // built-in country list. Bare single-label hostnames (for example
  // `localhost`) are not valid proxy-list domains.
  if ((!suffixRule && labels.length < 2) || !labels.every((label) => DOMAIN_LABEL.test(label))) {
    return undefined;
  }
  return suffixRule ? `.${domain}` : domain;
}
