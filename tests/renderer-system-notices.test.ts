import { describe, expect, it } from "vitest";
import {
  AUTO_CONNECT_NOTICE_MS,
  autoConnectCopy,
  backOnlineCopy,
  reconnectingCopy,
  updateDownloadedCopy
} from "../src/renderer/lib/system-notices.js";

describe("system notices", () => {
  it("announces auto-connect only while it is fresh", () => {
    const at = "2026-10-06T09:00:00.000Z";
    const notice = { at, transport: "ssh" as const, targetName: "Frankfurt-01" };
    expect(autoConnectCopy(notice, Date.parse(at) + 1000)).toEqual({
      title: "Connecting automatically",
      message: "Auto-connect is on, so Shadow is starting Frankfurt-01."
    });
    expect(autoConnectCopy(notice, Date.parse(at) + AUTO_CONNECT_NOTICE_MS + 1)).toBeUndefined();
    expect(autoConnectCopy(undefined)).toBeUndefined();
  });

  it("explains routine reconnects and mentions the routing hold on Windows only", () => {
    expect(reconnectingCopy("wake", "Frankfurt-01", "windows")).toEqual({
      title: "Reconnecting · woke from sleep",
      message: "Trying Frankfurt-01 now instead of waiting for the next attempt. Routing stays on for 30 s."
    });
    expect(reconnectingCopy("network-change", "Frankfurt-01", "macos")).toEqual({
      title: "Reconnecting · network changed",
      message: "Trying Frankfurt-01 now instead of waiting for the next attempt."
    });
    expect(reconnectingCopy("stuck", "Frankfurt-01", "windows")).toBeUndefined();
    expect(reconnectingCopy(undefined, "Frankfurt-01", "windows")).toBeUndefined();
  });

  it("says why the tunnel is back and adds a passed check", () => {
    const check = { endpoint: "youtube.com:443", ok: true, at: "2026-10-06T09:00:02.000Z", message: "ok", latencyMs: 184 };
    expect(backOnlineCopy({ targetName: "Frankfurt-01", reason: "network-change", check })).toEqual({
      title: "Back online · Frankfurt-01",
      message: "Reconnected after the network change. Tunnel check: Passed · 184 ms."
    });
    expect(backOnlineCopy({ reason: "session-lost" })).toEqual({ title: "Back online", message: "The tunnel reconnected on its own." });
    expect(backOnlineCopy({ targetName: "Frankfurt-01", check: { ...check, ok: false } }).message).toBe("The tunnel reconnected on its own.");
  });

  it("names the downloaded file", () => {
    expect(updateDownloadedCopy("C:\\Users\\alex\\updates\\shadow-ssh-2.3.0-windows-portable-x64.exe", undefined)).toEqual({
      title: "Update downloaded",
      message: "shadow-ssh-2.3.0-windows-portable-x64.exe is ready to run."
    });
    expect(updateDownloadedCopy(undefined, "shadow-ssh-2.3.0.exe").message).toBe("shadow-ssh-2.3.0.exe is ready to run.");
    expect(updateDownloadedCopy(undefined, undefined).message).toBe("The new version is ready to run.");
    expect(updateDownloadedCopy("/Users/alex/updates/shadow-ssh-2.3.0-macos-dmg-arm64.dmg", undefined, "macos-dmg").message).toBe(
      "shadow-ssh-2.3.0-macos-dmg-arm64.dmg is ready to install."
    );
    expect(updateDownloadedCopy(undefined, "shadow-ssh-2.3.0-linux-package-amd64.deb", "linux-deb").message).toBe(
      "shadow-ssh-2.3.0-linux-package-amd64.deb is ready to install."
    );
    expect(updateDownloadedCopy(undefined, "shadow-ssh-2.3.0-linux-portable-x86_64.AppImage", "linux-appimage").message).toBe(
      "shadow-ssh-2.3.0-linux-portable-x86_64.AppImage is ready to run."
    );
  });
});
