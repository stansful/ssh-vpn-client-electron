import { describe, expect, it } from "vitest";
import { isRoutableRemoteAddress, parsePowerShellConnections } from "../src/core/network/windows-process-connections.js";

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

  it("filters local and link-local addresses", () => {
    expect(isRoutableRemoteAddress("149.154.167.41")).toBe(true);
    expect(isRoutableRemoteAddress("2a00:1450:4001:831::200e")).toBe(true);
    expect(isRoutableRemoteAddress("127.0.0.1")).toBe(false);
    expect(isRoutableRemoteAddress("::1")).toBe(false);
    expect(isRoutableRemoteAddress("169.254.10.20")).toBe(false);
    expect(isRoutableRemoteAddress("fe80::1")).toBe(false);
  });
});
