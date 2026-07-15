import { describe, expect, it } from "vitest";
import {
  buildWindowsProcessConnectionsPowerShell,
  isAutoLearnableRemoteAddress,
  isRoutableRemoteAddress,
  normalizeWindowsProcessName,
  parsePowerShellConnections
} from "../src/core/network/windows-process-connections.js";

describe("Windows process connection parsing", () => {
  it("normalizes PowerShell TCP connection rows", () => {
    const rows = parsePowerShellConnections(
      JSON.stringify([
        {
          processName: "Telegram.exe",
          remoteAddress: "::ffff:149.154.167.41",
          remotePort: 443,
          state: "Established"
        },
        {
          processName: "chrome.exe",
          remoteAddress: "127.0.0.1",
          remotePort: 8080,
          state: "Established"
        }
      ])
    );

    expect(rows).toEqual([
      {
        processName: "Telegram.exe",
        remoteAddress: "149.154.167.41",
        remotePort: 443,
        state: "Established"
      }
    ]);
  });

  it("keeps public remote addresses eligible for auto-learning", () => {
    expect(isAutoLearnableRemoteAddress("149.154.167.41")).toBe(true);
    expect(isAutoLearnableRemoteAddress("::ffff:149.154.167.41")).toBe(true);
    expect(isAutoLearnableRemoteAddress("2a00:1450:4001:831::200e")).toBe(true);
    expect(isRoutableRemoteAddress("149.154.167.41")).toBe(true);
  });

  it("keeps private, CGNAT, and ULA destinations available to compatibility IP fallback", () => {
    expect(isRoutableRemoteAddress("10.12.0.8")).toBe(true);
    expect(isRoutableRemoteAddress("100.64.10.20")).toBe(true);
    expect(isRoutableRemoteAddress("192.168.1.1")).toBe(true);
    expect(isRoutableRemoteAddress("fd00::5")).toBe(true);
    expect(isRoutableRemoteAddress("127.0.0.1")).toBe(false);
    expect(isRoutableRemoteAddress("169.254.10.20")).toBe(false);
    expect(isRoutableRemoteAddress("::1")).toBe(false);
    expect(isRoutableRemoteAddress("fe80::1")).toBe(false);
  });

  it.each([
    "0.0.0.0",
    "10.12.0.8",
    "100.64.10.20",
    "127.0.0.1",
    "169.254.10.20",
    "172.20.0.1",
    "192.0.0.170",
    "192.0.2.1",
    "192.31.196.1",
    "192.52.193.1",
    "192.168.1.1",
    "192.175.48.1",
    "198.18.0.1",
    "198.51.100.2",
    "203.0.113.3",
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "2001::1",
    "2001:db8::1",
    "2002:c000:0204::1",
    "2620:4f:8000::1",
    "3fff::1",
    "fc00::1",
    "fe80::1",
    "ff02::1"
  ])("does not auto-learn private or special-use address %s", (address) => {
    expect(isAutoLearnableRemoteAddress(address)).toBe(false);
  });

  it("retains non-loopback rows for compatibility while filtering local endpoints", () => {
    const rows = parsePowerShellConnections(
      JSON.stringify([
        { processName: "discord.exe", remoteAddress: "162.159.135.232", remotePort: 443, state: "Established" },
        { processName: "discord.exe", remoteAddress: "10.0.0.5", remotePort: 443, state: "Established" },
        { processName: "discord.exe", remoteAddress: "198.51.100.5", remotePort: 443, state: "Established" },
        { processName: "discord.exe", remoteAddress: "2001:db8::5", remotePort: 443, state: "Established" },
        { processName: "discord.exe", remoteAddress: "fd00::5", remotePort: 443, state: "Established" },
        { processName: "discord.exe", remoteAddress: "127.0.0.1", remotePort: 443, state: "Established" },
        { processName: "discord.exe", remoteAddress: "fe80::5", remotePort: 443, state: "Established" }
      ])
    );

    expect(rows.map((row) => row.remoteAddress)).toEqual([
      "162.159.135.232",
      "10.0.0.5",
      "198.51.100.5",
      "2001:db8::5",
      "fd00::5"
    ]);
  });

  it("normalizes manually entered Windows process names to executable names", () => {
    expect(normalizeWindowsProcessName(" Chrome ")).toBe("chrome.exe");
    expect(normalizeWindowsProcessName("TELEGRAM.EXE")).toBe("telegram.exe");
  });

  it("uses a full Windows TCP snapshot but serializes only Base64-encoded target names", () => {
    const processNames = ["Chrome", "TELEGRAM.EXE", "chrome.exe", "evil'); Write-Output 'owned"];
    const script = buildWindowsProcessConnectionsPowerShell(processNames);
    expect(script).toBeDefined();
    expect(script).toContain("$ErrorActionPreference = 'SilentlyContinue'");
    expect(script).toContain("Get-Process | ForEach-Object");
    expect(script).toContain("Get-NetTCPConnection -State Established,SynSent | ForEach-Object");
    expect(script).toContain("$targets.ContainsKey([string]$processName)");
    expect(script).not.toContain("-OwningProcess");
    expect(script).not.toContain("evil'); Write-Output 'owned");
    expect(script).not.toContain("Select-Object -First");

    const encodedTargets = script?.match(/FromBase64String\('([A-Za-z0-9+/=]+)'\)/)?.[1];
    expect(encodedTargets).toBeDefined();
    expect(JSON.parse(Buffer.from(encodedTargets ?? "", "base64").toString("utf8"))).toEqual([
      "chrome.exe",
      "telegram.exe",
      "evil'); write-output 'owned.exe"
    ]);
    expect(buildWindowsProcessConnectionsPowerShell([])).toBeUndefined();
  });

  it("keeps undefined targets as an all-process snapshot", () => {
    const script = buildWindowsProcessConnectionsPowerShell();
    expect(script).toContain("$targets = $null");
    expect(script).toContain("Get-NetTCPConnection -State Established,SynSent | ForEach-Object");
    expect(script).not.toContain("FromBase64String");
  });
});
