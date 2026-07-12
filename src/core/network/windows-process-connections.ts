import { execFile } from "node:child_process";
import net from "node:net";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const MAX_WINDOWS_PROCESS_CONNECTION_OUTPUT_BYTES = 16 * 1024 * 1024;

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

  const { stdout } = await execFileAsync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], {
    timeout: 7000,
    maxBuffer: MAX_WINDOWS_PROCESS_CONNECTION_OUTPUT_BYTES,
    windowsHide: true
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

  // Keep the pre-optimization Windows snapshot path for compatibility. Some
  // PowerShell 5.1/CIM combinations returned an empty result when the owning
  // PID list was pre-filtered. Filtering the completed snapshot in Node is a
  // little more work, but it is the behavior known to work across Windows 10
  // and 11 builds.
  return [
    "$ErrorActionPreference = 'SilentlyContinue'",
    "$p = @{}",
    "Get-Process | ForEach-Object { $p[[int]$_.Id] = ($_.ProcessName + '.exe') }",
    "Get-NetTCPConnection -State Established,SynSent | ForEach-Object {",
    "  [PSCustomObject]@{",
    "    processName = $p[[int]$_.OwningProcess]",
    "    remoteAddress = [string]$_.RemoteAddress",
    "    remotePort = [int]$_.RemotePort",
    "    state = [string]$_.State",
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
