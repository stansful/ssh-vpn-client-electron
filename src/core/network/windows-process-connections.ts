import {
  canonicalizeIpAddress,
  ipMatchesCidr,
  parseCidrRange,
  parseIpAddress,
  type ParsedCidrRange
} from "../routing/ip-address.js";
import { runWindowsPowerShellScript } from "./windows-powershell.js";

const MAX_WINDOWS_PROCESS_CONNECTION_OUTPUT_BYTES = 16 * 1024 * 1024;
const AUTO_LEARNABLE_IPV6_RANGE = requireCidrRange("2000::/3");
const PROCESS_ROUTE_FALLBACK_EXCLUDED_RANGES = [
  "0.0.0.0/32",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "::/128",
  "::1/128",
  "fe80::/10"
].map(requireCidrRange);
const AUTO_LEARN_EXCLUDED_RANGES = [
  // IPv4 special-purpose, non-unicast, and non-public ranges. Keep this list
  // local to process discovery: manually configured IP/CIDR rules may still
  // intentionally target LAN, CGNAT, or other private destinations.
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.31.196.0/24",
  "192.52.193.0/24",
  "192.88.99.0/24",
  "192.168.0.0/16",
  "192.175.48.0/24",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4",
  // Special-purpose ranges inside IPv6's global-unicast space. Everything
  // outside 2000::/3 is rejected separately below.
  "2001::/23",
  "2001:db8::/32",
  "2002::/16",
  "2620:4f:8000::/48",
  "3fff::/20"
].map(requireCidrRange);

export interface WindowsProcessConnection {
  processName: string;
  remoteAddress: string;
  remotePort: number;
  state: string;
}

interface RawPowerShellConnection {
  processName?: unknown;
  remoteAddress?: unknown;
  remotePort?: unknown;
  state?: unknown;
}

export async function listWindowsProcessConnections(processNames?: Iterable<string>): Promise<WindowsProcessConnection[]> {
  if (process.platform !== "win32") {
    return [];
  }

  const script = buildWindowsProcessConnectionsPowerShell(processNames);
  if (!script) {
    return [];
  }

  const stdout = await runWindowsPowerShellScript(script, {
    timeoutMs: 7000,
    maxBufferBytes: MAX_WINDOWS_PROCESS_CONNECTION_OUTPUT_BYTES
  });
  return parsePowerShellConnections(stdout);
}

export function buildWindowsProcessConnectionsPowerShell(processNames?: Iterable<string>): string | undefined {
  const targets = processNames === undefined
    ? undefined
    : [...new Set([...processNames].map(normalizeWindowsProcessName).filter(Boolean))];
  if (targets?.length === 0) {
    return undefined;
  }

  const targetSetup = targets === undefined
    ? ["$targets = $null"]
    : [
        `$targetJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(JSON.stringify(targets), "utf8").toString("base64")}'))`,
        "$targets = @{}",
        "@(ConvertFrom-Json -InputObject $targetJson) | ForEach-Object { $targets[[string]$_] = $true }"
      ];

  // Keep the Windows 10/11-compatible full TCP snapshot. Some PowerShell
  // 5.1/CIM combinations returned an empty result when Get-NetTCPConnection
  // itself was pre-filtered by owning PID. We filter only the objects emitted
  // for JSON serialization, which also keeps IPC output proportional to the
  // selected process set.
  return [
    "$ErrorActionPreference = 'SilentlyContinue'",
    "$p = @{}",
    "Get-Process | ForEach-Object { $p[[int]$_.Id] = ($_.ProcessName + '.exe') }",
    ...targetSetup,
    "Get-NetTCPConnection -State Established,SynSent | ForEach-Object {",
    "  $processName = $p[[int]$_.OwningProcess]",
    "  if ($null -eq $targets -or $targets.ContainsKey([string]$processName)) {",
    "    [PSCustomObject]@{",
    "      processName = $processName",
    "      remoteAddress = [string]$_.RemoteAddress",
    "      remotePort = [int]$_.RemotePort",
    "      state = [string]$_.State",
    "    }",
    "  }",
    "} | ConvertTo-Json -Compress"
  ].join("\n");
}

export function normalizeWindowsProcessName(name: string): string {
  const normalized = name.trim().toLowerCase();
  if (!normalized || normalized.endsWith(".exe")) {
    return normalized;
  }
  return `${normalized}.exe`;
}

export function parsePowerShellConnections(stdout: string): WindowsProcessConnection[] {
  const trimmed = stdout.trim();
  if (!trimmed) {
    return [];
  }
  const parsed = JSON.parse(trimmed) as RawPowerShellConnection | RawPowerShellConnection[];
  const rows = Array.isArray(parsed) ? parsed : [parsed];
  return rows.flatMap((row) => {
    const processName = typeof row.processName === "string" ? row.processName.trim() : "";
    const remoteAddress = typeof row.remoteAddress === "string" ? normalizeRemoteAddress(row.remoteAddress) : "";
    const remotePort = typeof row.remotePort === "number" ? row.remotePort : Number(row.remotePort);
    const state = typeof row.state === "string" ? row.state : "";
    if (!processName || !isRoutableRemoteAddress(remoteAddress) || !Number.isInteger(remotePort) || remotePort <= 0 || remotePort > 65535) {
      return [];
    }
    return [{ processName, remoteAddress, remotePort, state }];
  });
}

export function isAutoLearnableRemoteAddress(address: string): boolean {
  const canonical = canonicalizeIpAddress(address);
  const parsed = canonical ? parseIpAddress(canonical) : undefined;
  if (!parsed) {
    return false;
  }
  if (parsed.version === 6 && !ipMatchesCidr(parsed, AUTO_LEARNABLE_IPV6_RANGE)) {
    return false;
  }
  return !AUTO_LEARN_EXCLUDED_RANGES.some((range) => ipMatchesCidr(parsed, range));
}

export function isRoutableRemoteAddress(address: string): boolean {
  const canonical = canonicalizeIpAddress(address);
  const parsed = canonical ? parseIpAddress(canonical) : undefined;
  return parsed !== undefined && !PROCESS_ROUTE_FALLBACK_EXCLUDED_RANGES.some((range) => ipMatchesCidr(parsed, range));
}

function normalizeRemoteAddress(address: string): string {
  return canonicalizeIpAddress(address) ?? "";
}

function requireCidrRange(value: string): ParsedCidrRange {
  const range = parseCidrRange(value);
  if (!range) {
    throw new Error(`Invalid internal CIDR range: ${value}`);
  }
  return range;
}
