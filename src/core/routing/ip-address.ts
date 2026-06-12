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

function prefixToMask(bits: number, prefixLength: number): bigint {
  if (prefixLength === 0) {
    return 0n;
  }
  return ((1n << BigInt(prefixLength)) - 1n) << BigInt(bits - prefixLength);
}

const IPV6_GROUPS = 8;
