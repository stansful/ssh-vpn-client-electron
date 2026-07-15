import { canonicalizeIpAddress, ipAddressKey } from "../routing/ip-address.js";
import { validateDomainPattern } from "../../shared/validation.js";
import { runWindowsPowerShellScript } from "./windows-powershell.js";

export const MAX_WINDOWS_DNS_CACHE_TARGETS = 2048;
export const MAX_WINDOWS_DNS_CACHE_INPUT_CANDIDATES = MAX_WINDOWS_DNS_CACHE_TARGETS * 4;
export const MAX_WINDOWS_DNS_CACHE_OUTPUT_BYTES = 4 * 1024 * 1024;
export const MAX_WINDOWS_DNS_CACHE_ROWS_SCANNED = 16_384;
export const MAX_WINDOWS_DNS_CACHE_ENTRIES = 4096;
export const MAX_WINDOWS_DNS_CACHE_DOMAINS_PER_ADDRESS = 64;
export const MAX_WINDOWS_DNS_CACHE_ADDRESS_ROWS = 2048;
export const MAX_WINDOWS_DNS_CACHE_CNAME_ROWS = 2048;
export const MAX_WINDOWS_DNS_CACHE_CNAME_DEPTH = 8;
export const MAX_WINDOWS_DNS_CACHE_CNAME_ALIASES_PER_TARGET = 64;
export const MAX_WINDOWS_DNS_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60;
export const WINDOWS_DNS_CACHE_QUERY_TIMEOUT_MS = 7000;

export interface WindowsDnsCacheEntry {
  address: string;
  domain: string;
  ttlSeconds: number;
}

interface RawWindowsDnsCacheEntry {
  address?: unknown;
  domain?: unknown;
  canonicalDomain?: unknown;
  ttlSeconds?: unknown;
}

type DirectDnsCacheEntry = WindowsDnsCacheEntry;

interface WindowsDnsCacheCnameEdge {
  alias: string;
  canonicalDomain: string;
  ttlSeconds: number;
}

/**
 * Reads cached A/AAAA records for the requested addresses and enriches them
 * with bounded reverse CNAME aliases. No network DNS lookup is performed, and
 * unsupported platforms return an empty snapshot.
 */
export async function listWindowsDnsCacheEntries(addresses: Iterable<string>): Promise<WindowsDnsCacheEntry[]> {
  if (process.platform !== "win32") {
    return [];
  }

  const requestedAddresses = normalizeRequestedAddresses(addresses);
  const script = buildWindowsDnsCachePowerShell(requestedAddresses);
  if (!script) {
    return [];
  }

  const stdout = await runWindowsPowerShellScript(script, {
    timeoutMs: WINDOWS_DNS_CACHE_QUERY_TIMEOUT_MS,
    maxBufferBytes: MAX_WINDOWS_DNS_CACHE_OUTPUT_BYTES
  });
  return parseWindowsDnsCacheEntries(stdout, requestedAddresses);
}

/**
 * Builds a Windows PowerShell 5.1-compatible query. The only caller-provided
 * value embedded in the source is Base64-encoded JSON, so an address string can
 * never escape into executable PowerShell syntax.
 */
export function buildWindowsDnsCachePowerShell(addresses: Iterable<string>): string | undefined {
  const requestedAddresses = normalizeRequestedAddresses(addresses);
  if (requestedAddresses.length === 0) {
    return undefined;
  }

  const encodedAddresses = Buffer.from(JSON.stringify(requestedAddresses), "utf8").toString("base64");
  return [
    "$ErrorActionPreference = 'SilentlyContinue'",
    `$targetJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${encodedAddresses}'))`,
    "$targets = @{}",
    "@($targetJson | ConvertFrom-Json) | ForEach-Object {",
    "  try {",
    "    $targetAddress = ([System.Net.IPAddress]::Parse([string]$_)).ToString().ToLowerInvariant()",
    "    $targets[$targetAddress] = $true",
    "  } catch {}",
    "}",
    "$addressRows = New-Object System.Collections.ArrayList",
    "$cnameRows = New-Object System.Collections.ArrayList",
    "$addressRowKeys = @{}",
    "$addressDomainCounts = @{}",
    "$cnameRowKeys = @{}",
    "Get-DnsClientCache -Type A,AAAA,CNAME -ErrorAction SilentlyContinue | ForEach-Object {",
    "  $recordTypeValue = [string]$_.RecordType",
    "  if ([string]::IsNullOrWhiteSpace($recordTypeValue)) { $recordTypeValue = [string]$_.Type }",
    "  $recordType = 0",
    "  if ($recordTypeValue -ieq 'A') { $recordType = 1 }",
    "  elseif ($recordTypeValue -ieq 'CNAME') { $recordType = 5 }",
    "  elseif ($recordTypeValue -ieq 'AAAA') { $recordType = 28 }",
    "  else { try { $recordType = [int]$recordTypeValue } catch {} }",
    "  $recordStatusValue = [string]$_.Status",
    "  $recordStatus = 0",
    "  if (-not [string]::IsNullOrWhiteSpace($recordStatusValue) -and $recordStatusValue -ine 'Success') {",
    "    $recordStatus = -1",
    "    try { $recordStatus = [long]$recordStatusValue } catch {}",
    "  }",
    "  if ($recordStatus -eq 0) {",
    "    $recordOwner = [string]$_.Name",
    "    if ([string]::IsNullOrWhiteSpace($recordOwner)) { $recordOwner = [string]$_.RecordName }",
    "    if ([string]::IsNullOrWhiteSpace($recordOwner)) { $recordOwner = [string]$_.Entry }",
    "    if ($recordType -eq 5) {",
    "      $canonicalDomain = [string]$_.Data",
    "      $cnameTtl = [long]$_.TimeToLive",
    "      $cnameRowKey = $recordOwner + \"`n\" + $canonicalDomain",
    "      if ($cnameRowKeys.ContainsKey($cnameRowKey)) {",
    "        $cnameRowIndex = [int]$cnameRowKeys[$cnameRowKey]",
    "        if ($cnameTtl -gt [long]$cnameRows[$cnameRowIndex].ttlSeconds) { $cnameRows[$cnameRowIndex].ttlSeconds = $cnameTtl }",
    `      } elseif ($cnameRows.Count -lt ${MAX_WINDOWS_DNS_CACHE_CNAME_ROWS}) {`,
    "        $cnameRowKeys[$cnameRowKey] = $cnameRows.Count",
    "        [void]$cnameRows.Add([PSCustomObject]@{",
    "          domain = $recordOwner",
    "          canonicalDomain = $canonicalDomain",
    "          ttlSeconds = $cnameTtl",
    "        })",
    "      }",
    "    } elseif ($recordType -eq 1 -or $recordType -eq 28) {",
    "      $cacheAddress = $null",
    "      try { $cacheAddress = ([System.Net.IPAddress]::Parse([string]$_.Data)).ToString().ToLowerInvariant() } catch {}",
    "      $addressTtl = [long]$_.TimeToLive",
    "      $addressRowKey = $cacheAddress + \"`n\" + $recordOwner",
    "      $addressDomainCount = 0",
    "      if ($cacheAddress -and $addressDomainCounts.ContainsKey($cacheAddress)) { $addressDomainCount = [int]$addressDomainCounts[$cacheAddress] }",
    "      if ($cacheAddress -and $targets.ContainsKey($cacheAddress) -and $addressRowKeys.ContainsKey($addressRowKey)) {",
    "        $addressRowIndex = [int]$addressRowKeys[$addressRowKey]",
    "        if ($addressTtl -gt [long]$addressRows[$addressRowIndex].ttlSeconds) { $addressRows[$addressRowIndex].ttlSeconds = $addressTtl }",
    `      } elseif ($cacheAddress -and $targets.ContainsKey($cacheAddress) -and $addressDomainCount -lt ${MAX_WINDOWS_DNS_CACHE_DOMAINS_PER_ADDRESS} -and $addressRows.Count -lt ${MAX_WINDOWS_DNS_CACHE_ADDRESS_ROWS}) {`,
    "        $addressRowKeys[$addressRowKey] = $addressRows.Count",
    "        $addressDomainCounts[$cacheAddress] = $addressDomainCount + 1",
    "        [void]$addressRows.Add([PSCustomObject]@{",
    "          address = $cacheAddress",
    "          domain = $recordOwner",
    "          ttlSeconds = $addressTtl",
    "        })",
    "      }",
    "    }",
    "  }",
    "}",
    "$outputRows = @($addressRows.ToArray()) + @($cnameRows.ToArray())",
    "$outputRows | ConvertTo-Json -Compress"
  ].join("\n");
}

/**
 * Parses the bounded PowerShell response and applies the requested-address
 * allowlist again. This second filter keeps the trust boundary in Node even if
 * PowerShell or a mocked command returns unrelated cache records.
 */
export function parseWindowsDnsCacheEntries(
  stdout: string,
  requestedAddresses: Iterable<string>
): WindowsDnsCacheEntry[] {
  if (Buffer.byteLength(stdout, "utf8") > MAX_WINDOWS_DNS_CACHE_OUTPUT_BYTES) {
    throw new Error("Windows DNS cache output exceeded the allowed size.");
  }

  const trimmed = stdout.trim();
  if (!trimmed) {
    return [];
  }

  const requested = new Set(normalizeRequestedAddresses(requestedAddresses).map(addressKey));
  if (requested.size === 0) {
    return [];
  }

  const parsed = JSON.parse(trimmed) as unknown;
  const rows = Array.isArray(parsed) ? parsed : [parsed];
  const directEntries = new Map<string, DirectDnsCacheEntry>();
  const cnameEdges = new Map<string, WindowsDnsCacheCnameEdge>();
  const rowsToScan = Math.min(rows.length, MAX_WINDOWS_DNS_CACHE_ROWS_SCANNED);

  for (let index = 0; index < rowsToScan; index += 1) {
    const row = asRawEntry(rows[index]);
    if (!row) {
      continue;
    }
    const domain = normalizeDnsDomain(row.domain);
    const ttlSeconds = parseTtlSeconds(row.ttlSeconds);
    const hasAddressField = row.address !== undefined && row.address !== null;
    const hasCanonicalDomainField = row.canonicalDomain !== undefined && row.canonicalDomain !== null;
    if (!domain || ttlSeconds === undefined || hasAddressField === hasCanonicalDomainField) {
      continue;
    }

    if (hasAddressField) {
      const address = normalizeIpAddress(row.address);
      if (!address || !requested.has(addressKey(address))) {
        continue;
      }
      const key = dnsAddressDomainKey(address, domain);
      const existing = directEntries.get(key);
      if (!existing || ttlSeconds > existing.ttlSeconds) {
        directEntries.set(key, { address, domain, ttlSeconds });
      }
      continue;
    }

    const canonicalDomain = normalizeDnsDomain(row.canonicalDomain);
    if (!canonicalDomain || canonicalDomain === domain) {
      continue;
    }
    const key = `${canonicalDomain}\u0000${domain}`;
    const existing = cnameEdges.get(key);
    if (!existing || ttlSeconds > existing.ttlSeconds) {
      cnameEdges.set(key, { alias: domain, canonicalDomain, ttlSeconds });
    }
  }

  const entries = new Map<string, WindowsDnsCacheEntry>();
  const domainsPerAddress = new Map<string, number>();
  const initialFrontier = new Map<string, WindowsDnsCacheEntry>();
  for (const entry of directEntries.values()) {
    if (recordResolvedDnsEntry(entries, domainsPerAddress, entry)) {
      initialFrontier.set(dnsAddressDomainKey(entry.address, entry.domain), entry);
    }
  }

  const reverseCnameEdges = buildReverseCnameEdges(cnameEdges.values());
  const bestTtlByAddressDomain = new Map(
    [...initialFrontier].map(([key, entry]) => [key, entry.ttlSeconds] as const)
  );
  let frontier = initialFrontier;
  for (let depth = 0; depth < MAX_WINDOWS_DNS_CACHE_CNAME_DEPTH && frontier.size > 0; depth += 1) {
    const nextFrontier = new Map<string, WindowsDnsCacheEntry>();
    for (const current of frontier.values()) {
      for (const edge of reverseCnameEdges.get(current.domain) ?? []) {
        const ttl = Math.min(current.ttlSeconds, edge.ttlSeconds);
        const key = dnsAddressDomainKey(current.address, edge.alias);
        if (ttl <= (bestTtlByAddressDomain.get(key) ?? 0)) {
          continue;
        }
        const aliasEntry = { address: current.address, domain: edge.alias, ttlSeconds: ttl };
        if (!recordResolvedDnsEntry(entries, domainsPerAddress, aliasEntry)) {
          continue;
        }
        bestTtlByAddressDomain.set(key, ttl);
        const queued = nextFrontier.get(key);
        if (!queued || ttl > queued.ttlSeconds) {
          nextFrontier.set(key, aliasEntry);
        }
      }
    }
    frontier = nextFrontier;
  }

  return [...entries.values()];
}

function buildReverseCnameEdges(
  edges: Iterable<WindowsDnsCacheCnameEdge>
): Map<string, WindowsDnsCacheCnameEdge[]> {
  const reverse = new Map<string, WindowsDnsCacheCnameEdge[]>();
  for (const edge of [...edges].sort((left, right) =>
    left.canonicalDomain.localeCompare(right.canonicalDomain) || left.alias.localeCompare(right.alias)
  )) {
    const aliases = reverse.get(edge.canonicalDomain) ?? [];
    if (aliases.length >= MAX_WINDOWS_DNS_CACHE_CNAME_ALIASES_PER_TARGET) {
      continue;
    }
    aliases.push(edge);
    reverse.set(edge.canonicalDomain, aliases);
  }
  return reverse;
}

function recordResolvedDnsEntry(
  entries: Map<string, WindowsDnsCacheEntry>,
  domainsPerAddress: Map<string, number>,
  entry: WindowsDnsCacheEntry
): boolean {
  const key = dnsAddressDomainKey(entry.address, entry.domain);
  const existing = entries.get(key);
  if (existing) {
    if (entry.ttlSeconds > existing.ttlSeconds) {
      entries.set(key, entry);
    }
    return true;
  }
  if (entries.size >= MAX_WINDOWS_DNS_CACHE_ENTRIES) {
    return false;
  }
  const addressDomainCount = domainsPerAddress.get(entry.address) ?? 0;
  if (addressDomainCount >= MAX_WINDOWS_DNS_CACHE_DOMAINS_PER_ADDRESS) {
    return false;
  }
  domainsPerAddress.set(entry.address, addressDomainCount + 1);
  entries.set(key, entry);
  return true;
}

function dnsAddressDomainKey(address: string, domain: string): string {
  return `${address}\u0000${domain}`;
}

function normalizeRequestedAddresses(addresses: Iterable<string>): string[] {
  const normalized = new Map<string, string>();
  let candidates = 0;
  for (const address of addresses) {
    candidates += 1;
    if (candidates > MAX_WINDOWS_DNS_CACHE_INPUT_CANDIDATES || normalized.size >= MAX_WINDOWS_DNS_CACHE_TARGETS) {
      break;
    }
    const value = normalizeIpAddress(address);
    if (value) {
      normalized.set(addressKey(value), value);
    }
  }
  return [...normalized.values()];
}

function asRawEntry(value: unknown): RawWindowsDnsCacheEntry | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as RawWindowsDnsCacheEntry
    : undefined;
}

function normalizeIpAddress(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  return canonicalizeIpAddress(value);
}

function addressKey(address: string): string {
  return ipAddressKey(address) ?? "";
}

function normalizeDnsDomain(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const domain = value.trim().toLowerCase().replace(/\.$/u, "");
  return !domain.startsWith("*.") && validateDomainPattern(domain).ok ? domain : undefined;
}

function parseTtlSeconds(value: unknown): number | undefined {
  const parsed = typeof value === "number"
    ? value
    : typeof value === "string" && /^\d+$/u.test(value.trim())
      ? Number(value.trim())
      : Number.NaN;
  return Number.isSafeInteger(parsed) && parsed > 0 && parsed <= MAX_WINDOWS_DNS_CACHE_TTL_SECONDS
    ? parsed
    : undefined;
}
