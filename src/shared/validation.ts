import type { RoutingRuleType } from "./types.js";

export interface ValidationResult {
  ok: boolean;
  message?: string;
}

const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const HEX_GROUP = /^[0-9a-f]{1,4}$/i;
const SSH_SHA256_FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/u;

export function validateSshServerFingerprint(value: string, allowDiscovery = true): ValidationResult {
  const fingerprint = value.trim();
  if (!fingerprint) {
    return allowDiscovery
      ? { ok: true }
      : { ok: false, message: "A verified SSH server SHA256 fingerprint is required." };
  }
  if (!SSH_SHA256_FINGERPRINT.test(fingerprint)) {
    return {
      ok: false,
      message: "SSH server fingerprint must use the OpenSSH SHA256:base64 format (43 characters after SHA256:)."
    };
  }
  return { ok: true };
}

export const CHECK_ENDPOINT_FORMAT_MESSAGE = "Enter host:port without https:// or a path — for example youtube.com:443.";
const CHECK_ENDPOINT_HOST_LABEL = /^[\p{L}\p{N}_](?:[\p{L}\p{N}_-]{0,61}[\p{L}\p{N}_])?$/u;

/**
 * The tunnel check opens a raw TCP connection to `host:port`, so anything a
 * URL would carry - a scheme, a path, credentials - is a sign the user pasted
 * a link and would be checking something other than they think.
 */
export function validateCheckEndpoint(value: string): ValidationResult {
  const endpoint = value.trim();
  if (!endpoint) {
    return { ok: false, message: "Endpoint is required. Use host:port." };
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//iu.test(endpoint) || /[/?#@\\]/u.test(endpoint)) {
    return { ok: false, message: CHECK_ENDPOINT_FORMAT_MESSAGE };
  }
  const bracketed = endpoint.match(/^\[([^\]]+)\](?::(.*))?$/u);
  const plain = bracketed ? undefined : endpoint.match(/^([^:]+)(?::(.*))?$/u);
  const host = bracketed?.[1] ?? plain?.[1];
  const rawPort = bracketed ? bracketed[2] : plain?.[2];
  if (host === undefined || (bracketed ? !isValidIpv6(host) : !isValidCheckEndpointHost(host))) {
    return { ok: false, message: "Endpoint must use host:port, for example youtube.com:443." };
  }
  if (rawPort === undefined || !/^\d{1,5}$/u.test(rawPort) || Number(rawPort) < 1 || Number(rawPort) > 65535) {
    return { ok: false, message: "Endpoint must use host:port with a valid TCP port." };
  }
  return { ok: true };
}

function isValidCheckEndpointHost(host: string): boolean {
  if (isValidIpv4(host)) {
    return true;
  }
  const name = host.endsWith(".") ? host.slice(0, -1) : host;
  if (!name || name.length > 253 || /^[\d.]+$/u.test(name)) {
    return false;
  }
  return name.split(".").every((label) => CHECK_ENDPOINT_HOST_LABEL.test(label));
}

export function validateDomainPattern(value: string): ValidationResult {
  const pattern = value.trim().toLowerCase();
  if (!pattern) {
    return { ok: false, message: "Domain pattern is required." };
  }

  const normalized = pattern.startsWith("*.") ? pattern.slice(2) : pattern;
  if (normalized.length > 253) {
    return { ok: false, message: "Domain pattern is too long." };
  }

  const labels = normalized.split(".");
  if (labels.length < 2) {
    return { ok: false, message: "Domain pattern must include at least two labels." };
  }

  if (!labels.every((label) => DOMAIN_LABEL.test(label))) {
    return { ok: false, message: "Domain labels may contain letters, numbers, and internal hyphens." };
  }

  return { ok: true };
}

export function validateIpOrCidr(value: string): ValidationResult {
  const input = value.trim();
  if (!input) {
    return { ok: false, message: "IP address or CIDR is required." };
  }

  const parts = input.split("/");
  if (parts.length > 2) {
    return { ok: false, message: "CIDR may contain only one slash." };
  }

  const ip = parts[0] ?? "";
  const version = isValidIpv4(ip) ? 4 : isValidIpv6(ip) ? 6 : 0;
  if (version === 0) {
    return { ok: false, message: "IP address must be valid IPv4 or IPv6." };
  }

  if (parts.length === 2) {
    const rawPrefix = parts[1] ?? "";
    if (!/^\d+$/.test(rawPrefix)) {
      return { ok: false, message: "CIDR prefix must be a number." };
    }

    const prefix = Number(rawPrefix);
    const max = version === 4 ? 32 : 128;
    if (prefix < 0 || prefix > max) {
      return { ok: false, message: `CIDR prefix must be between 0 and ${max}.` };
    }
  }

  return { ok: true };
}

export function validateProcessName(value: string): ValidationResult {
  const name = value.trim();
  if (!name) {
    return { ok: false, message: "Process name is required." };
  }
  if (name.length > 260) {
    return { ok: false, message: "Process name is too long." };
  }
  if (/[\\/]/.test(name)) {
    return { ok: false, message: "Use a process name, not a path." };
  }
  if (!/^[a-z0-9._+\- ]+$/i.test(name)) {
    return { ok: false, message: "Process name contains unsupported characters." };
  }
  return { ok: true };
}

export function validateRoutingRuleValue(type: RoutingRuleType, value: string): ValidationResult {
  if (type === "domain") {
    return validateDomainPattern(value);
  }
  if (type === "ip") {
    return validateIpOrCidr(value);
  }
  if (type === "process.name") {
    return validateProcessName(value);
  }
  return { ok: false, message: "Unsupported routing rule type." };
}

export function isValidIpv4(value: string): boolean {
  const octets = value.split(".");
  if (octets.length !== 4) {
    return false;
  }
  return octets.every((octet) => {
    if (!/^\d+$/.test(octet)) {
      return false;
    }
    if (octet.length > 1 && octet.startsWith("0")) {
      return false;
    }
    const parsed = Number(octet);
    return parsed >= 0 && parsed <= 255;
  });
}

export function isValidIpv6(value: string): boolean {
  if (!value || value.includes(":::")) {
    return false;
  }

  const compressedParts = value.split("::");
  if (compressedParts.length > 2) {
    return false;
  }

  const hasCompression = compressedParts.length === 2;
  const left = compressedParts[0] ? compressedParts[0].split(":") : [];
  const right = compressedParts[1] ? compressedParts[1].split(":") : [];
  const groups = [...left, ...right];

  if (!groups.every((group) => HEX_GROUP.test(group))) {
    return false;
  }

  if (hasCompression) {
    return groups.length < 8;
  }

  return groups.length === 8;
}

export function normalizeRuleValue(type: RoutingRuleType, value: string): string {
  const trimmed = value.trim();
  if (type === "domain" || type === "process.name") {
    return trimmed.toLowerCase();
  }
  return trimmed;
}

export const MAX_PROXY_PROFILE_NAME_LENGTH = 64;

/**
 * A profile name is one line of display text: control characters (newlines
 * and tabs too) and the Unicode line and paragraph separators become spaces,
 * and it is cut to 64 code points so a surrogate pair is never split.
 * Returns "" for a blank name.
 */
export function normalizeProxyProfileName(input: string): string {
  const flattened = input.replace(/[\p{Cc}\p{Zl}\p{Zp}]/gu, " ").trim();
  return Array.from(flattened).slice(0, MAX_PROXY_PROFILE_NAME_LENGTH).join("").trimEnd();
}
