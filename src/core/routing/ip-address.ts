export type IpVersion = 4 | 6;

export interface ParsedIpAddress {
  version: IpVersion;
  value: bigint;
}

export interface ParsedCidrRange {
  version: IpVersion;
  network: bigint;
  prefixLength: number;
}

const IPV4_BITS = 32;
const IPV6_BITS = 128;
// Declared before anything that parses at module load (the local ranges below).
const IPV6_GROUPS = 8;

export function parseIpAddress(input: string): ParsedIpAddress | undefined {
  const value = input.trim();
  if (value.includes(".")) {
    return parseIpv4(value);
  }
  if (value.includes(":")) {
    return parseIpv6(value);
  }
  return undefined;
}

export function canonicalizeIpAddress(input: string): string | undefined {
  const trimmed = input.trim().toLowerCase();
  const withoutMappedPrefix = trimmed.startsWith("::ffff:") ? trimmed.slice("::ffff:".length) : trimmed;
  const parsed = parseIpAddress(withoutMappedPrefix);
  if (!parsed) {
    return undefined;
  }
  if (parsed.version === 4) {
    return [24, 16, 8, 0]
      .map((shift) => Number((parsed.value >> BigInt(shift)) & 0xffn))
      .join(".");
  }
  return formatIpv6(parsed.value);
}

/**
 * Parses an IP literal (brackets allowed) and reads an IPv4-mapped IPv6
 * address (`::ffff:a.b.c.d`, in either spelling) as the IPv4 address it
 * carries. A client that hands the proxy a mapped address means the IPv4 host,
 * so IPv4 rules and ranges have to match it.
 */
export function parseIpAddressUnmapped(input: string): ParsedIpAddress | undefined {
  const value = input.trim().replace(/^\[(.*)\]$/u, "$1").toLowerCase();
  // An IPv6 literal may end in dotted IPv4 notation (`::ffff:1.2.3.4`).
  // Rewrite that tail as two hex groups so the whole address parses once.
  const dottedTail = value.includes(":") ? /^(.*:)([^:]*\.[^:]*)$/u.exec(value) : null;
  const parsed = dottedTail
    ? parseDottedTailIpv6(dottedTail[1], dottedTail[2])
    : parseIpAddress(value);
  if (parsed?.version === 6 && parsed.value >> 32n === 0xffffn) {
    return { version: 4, value: parsed.value & 0xffff_ffffn };
  }
  return parsed;
}

function parseDottedTailIpv6(head: string, tail: string): ParsedIpAddress | undefined {
  const ipv4 = parseIpv4(tail);
  if (!ipv4) {
    return undefined;
  }
  return parseIpv6(`${head}${(ipv4.value >> 16n).toString(16)}:${(ipv4.value & 0xffffn).toString(16)}`);
}

function formatIpv4(value: bigint): string {
  return [24, 16, 8, 0].map((shift) => Number((value >> BigInt(shift)) & 0xffn)).join(".");
}

/** An IPv4-mapped IPv6 literal as dotted IPv4; any other host unchanged. */
export function unmapIpv4MappedAddress(host: string): string {
  const parsed = parseIpAddressUnmapped(host);
  if (parsed?.version !== 4 || !host.includes(":")) {
    return host;
  }
  return formatIpv4(parsed.value);
}

/**
 * Destinations that stay out of the tunnel unless a user rule names them, on
 * every routing path: the local machine, private and link-local networks,
 * carrier-grade NAT (which overlay networks such as Tailscale use) and "this
 * network". The PAC, Xray's routing, the TUN policy and the local listener
 * all apply this one list, right after the user's own domain and IP rules, so
 * on Windows LAN traffic stays direct whichever path carries it while a rule
 * such as `10.0.0.0/8` still reaches the network behind the server. The
 * Windows proxy override names none of it - WinINet can only write a wildcard
 * that public names match too - and leaves it to the listener or Xray behind
 * it. Where nothing steers the system's traffic - macOS, Linux - an app sends
 * the local proxy only what it wants tunnelled, and none of this applies.
 */
export const LOCAL_DESTINATION_CIDRS: readonly string[] = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "::1/128",
  "fc00::/7",
  "fe80::/10"
];

const LOCAL_DESTINATION_RANGES = LOCAL_DESTINATION_CIDRS.map((cidr) => {
  const range = parseCidrRange(cidr);
  if (!range) {
    throw new Error(`Invalid built-in local destination range ${cidr}.`);
  }
  return range;
});

/** True for an IP literal on {@link LOCAL_DESTINATION_CIDRS}, IPv4-mapped forms included. */
export function isLocalDestinationIp(input: string): boolean {
  const ip = parseIpAddressUnmapped(input);
  return ip !== undefined && LOCAL_DESTINATION_RANGES.some((range) => ipMatchesCidr(ip, range));
}

/**
 * True for a destination that stays direct when no user rule selects it: a
 * local or private IP literal, `localhost`, a single-label name (an intranet
 * host resolved by the local network) or a `.local` (mDNS) name. Names are
 * judged as written; nothing is resolved.
 */
export function isLocalDestinationHost(host: string): boolean {
  const value = host.trim().replace(/^\[(.*)\]$/u, "$1").toLowerCase().replace(/\.$/u, "");
  if (!value) {
    return false;
  }
  if (parseIpAddressUnmapped(value)) {
    return isLocalDestinationIp(value);
  }
  return !value.includes(".") || value === "localhost" || value.endsWith(".local");
}

/**
 * True for an IP rule that covers at least one address on
 * {@link LOCAL_DESTINATION_CIDRS} - `10.8.0.0/16`, or a wider `0.0.0.0/0` -
 * and so selects part of the local network ahead of the step that keeps it
 * direct. Xray's routing, which has that step built in, needs to know them.
 */
export function overlapsLocalDestinationRange(input: string): boolean {
  const range = parseCidrRange(input);
  if (!range) {
    return false;
  }
  const bits = range.version === 4 ? IPV4_BITS : IPV6_BITS;
  return LOCAL_DESTINATION_RANGES.some((local) => {
    if (local.version !== range.version) {
      return false;
    }
    const mask = prefixToMask(bits, Math.min(local.prefixLength, range.prefixLength));
    return (local.network & mask) === (range.network & mask);
  });
}

/** A parsed range as `network/prefix`, host bits cleared, IPv6 in its shortest form. */
export function formatCidrRange(range: ParsedCidrRange): string {
  const network = range.version === 4 ? formatIpv4(range.network) : formatIpv6(range.network);
  return `${network}/${range.prefixLength}`;
}

export function ipAddressKey(input: string): string | undefined {
  const canonical = canonicalizeIpAddress(input);
  if (!canonical) {
    return undefined;
  }
  const parsed = parseIpAddress(canonical);
  return parsed ? `${parsed.version}:${parsed.value.toString(16)}` : undefined;
}

export function parseCidrRange(input: string): ParsedCidrRange | undefined {
  const [ipRaw, prefixRaw] = input.trim().split("/");
  if (!ipRaw) {
    return undefined;
  }

  const ip = parseIpAddress(ipRaw);
  if (!ip) {
    return undefined;
  }

  const bits = ip.version === 4 ? IPV4_BITS : IPV6_BITS;
  const prefixLength = prefixRaw === undefined ? bits : Number(prefixRaw);
  if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > bits) {
    return undefined;
  }

  const mask = prefixToMask(bits, prefixLength);
  return {
    version: ip.version,
    network: ip.value & mask,
    prefixLength
  };
}

export function ipMatchesCidr(ip: ParsedIpAddress, cidr: ParsedCidrRange): boolean {
  if (ip.version !== cidr.version) {
    return false;
  }
  const bits = ip.version === 4 ? IPV4_BITS : IPV6_BITS;
  const mask = prefixToMask(bits, cidr.prefixLength);
  return (ip.value & mask) === cidr.network;
}

export function parseIpv4(input: string): ParsedIpAddress | undefined {
  const octets = input.split(".");
  if (octets.length !== 4) {
    return undefined;
  }

  let value = 0n;
  for (const octet of octets) {
    if (!/^\d+$/.test(octet) || (octet.length > 1 && octet.startsWith("0"))) {
      return undefined;
    }
    const parsed = Number(octet);
    if (parsed < 0 || parsed > 255) {
      return undefined;
    }
    value = (value << 8n) | BigInt(parsed);
  }

  return { version: 4, value };
}

export function parseIpv6(input: string): ParsedIpAddress | undefined {
  if (!input || input.includes(":::")) {
    return undefined;
  }

  const parts = input.split("::");
  if (parts.length > 2) {
    return undefined;
  }

  const left = parts[0] ? parseIpv6Groups(parts[0]) : [];
  const right = parts[1] ? parseIpv6Groups(parts[1]) : [];
  if (!left || !right) {
    return undefined;
  }

  const compression = parts.length === 2;
  const missing = IPV6_GROUPS - left.length - right.length;
  if (compression ? missing < 1 : missing !== 0) {
    return undefined;
  }

  const groups = [...left, ...Array<number>(missing).fill(0), ...right];
  if (groups.length !== IPV6_GROUPS) {
    return undefined;
  }

  let value = 0n;
  for (const group of groups) {
    value = (value << 16n) | BigInt(group);
  }
  return { version: 6, value };
}

function parseIpv6Groups(input: string): number[] | undefined {
  if (!input) {
    return [];
  }

  const groups = input.split(":");
  if (groups.some((group) => group.length === 0)) {
    return undefined;
  }

  const parsed: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) {
      return undefined;
    }
    parsed.push(Number.parseInt(group, 16));
  }
  return parsed;
}

function formatIpv6(value: bigint): string {
  const groups = Array.from({ length: IPV6_GROUPS }, (_unused, index) =>
    Number((value >> BigInt((IPV6_GROUPS - 1 - index) * 16)) & 0xffffn).toString(16)
  );
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < groups.length;) {
    if (groups[index] !== "0") {
      index += 1;
      continue;
    }
    let end = index + 1;
    while (end < groups.length && groups[end] === "0") {
      end += 1;
    }
    if (end - index > bestLength && end - index >= 2) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  if (bestStart < 0) {
    return groups.join(":");
  }
  const left = groups.slice(0, bestStart).join(":");
  const right = groups.slice(bestStart + bestLength).join(":");
  return `${left}::${right}`;
}

function prefixToMask(bits: number, prefixLength: number): bigint {
  if (prefixLength === 0) {
    return 0n;
  }
  return ((1n << BigInt(prefixLength)) - 1n) << BigInt(bits - prefixLength);
}
