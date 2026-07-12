import { execFile } from "node:child_process";
import net from "node:net";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

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

  const targets = processNames === undefined
    ? undefined
    : [...new Set([...processNames].map((name) => name.trim().toLowerCase()).filter(Boolean))];
  if (targets?.length === 0) {
    return [];
  }
  const encodedTargets = targets === undefined
    ? ""
    : Buffer.from(JSON.stringify(targets), "utf8").toString("base64");

  const script = [
    "$ErrorActionPreference = 'SilentlyContinue'",
    encodedTargets
      ? `$targetJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encodedTargets}'))`
      : "$targetJson = '[]'",
    "$targets = @{}",
    "@($targetJson | ConvertFrom-Json) | ForEach-Object { $targets[[string]$_.ToLowerInvariant()] = $true }",
    "$connections = @(Get-NetTCPConnection -State Established,SynSent)",
    "$p = @{}",
    "$ids = @($connections | Select-Object -ExpandProperty OwningProcess -Unique)",
    "if ($ids.Count -gt 0) {",
    "  Get-Process -Id $ids | ForEach-Object {",
    "    $name = ($_.ProcessName + '.exe')",
    "    if ($targets.Count -eq 0 -or $targets.ContainsKey($name.ToLowerInvariant())) { $p[[int]$_.Id] = $name }",
    "  }",
    "}",
    "$connections | ForEach-Object {",
    "  $name = $p[[int]$_.OwningProcess]",
    "  if ($name) {",
    "  [PSCustomObject]@{",
    "    processName = $name",
    "    remoteAddress = [string]$_.RemoteAddress",
    "    remotePort = [int]$_.RemotePort",
    "    state = [string]$_.State",
    "  }",
    "  }",
    "} | ConvertTo-Json -Compress"
  ].join("\n");

  const { stdout } = await execFileAsync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], {
    timeout: 7000,
    windowsHide: true
  });
  return parsePowerShellConnections(stdout);
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

export function isRoutableRemoteAddress(address: string): boolean {
  if (!address || address === "0.0.0.0" || address === "::") {
    return false;
  }
  if (address.startsWith("127.") || address === "::1") {
    return false;
  }
  if (address.startsWith("169.254.") || address.toLowerCase().startsWith("fe80:")) {
    return false;
  }
  return net.isIP(address) !== 0;
}

function normalizeRemoteAddress(address: string): string {
  const trimmed = address.trim().toLowerCase();
  if (trimmed.startsWith("::ffff:")) {
    return trimmed.slice("::ffff:".length);
  }
  return trimmed;
}
