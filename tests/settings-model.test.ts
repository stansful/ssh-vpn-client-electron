import { describe, expect, it } from "vitest";
import {
  activeSectionAt,
  autoConnectTarget,
  colourHex,
  coloursAreDefault,
  contrastChecks,
  contrastVerdict,
  describeDownloadFailure,
  formatProgressBytes,
  historyPatch,
  isOfflineError,
  logFilePath,
  normalizeHexInput,
  platformCopy,
  presentDiagnostics,
  presentUpdates,
  routingModeLabel,
  secretsCopy,
  withColour,
  withSettingsPatch,
  type UpdatesInput
} from "../src/renderer/components/pages/settings/settings-model.js";
import { createDefaultStore, DEFAULT_CUSTOM_THEME, DEFAULT_SETTINGS } from "../src/shared/defaults.js";
import type { AppUpdateInfo, ProxyProfile, SshConfig } from "../src/shared/types.js";
import { createTestSnapshot } from "./renderer-fixtures.js";

describe("settings section spy", () => {
  const sections = [
    { id: "general", top: -900 },
    { id: "appearance", top: -120 },
    { id: "diagnostics", top: 60 },
    { id: "about", top: 700 }
  ];

  it("picks the last section whose top passed the threshold", () => {
    expect(activeSectionAt(sections, 96, false)).toBe("diagnostics");
    expect(activeSectionAt(sections, 40, false)).toBe("appearance");
  });

  it("keeps the first section above everything and the last one at the bottom", () => {
    expect(activeSectionAt([{ id: "general", top: 200 }, { id: "about", top: 900 }], 96, false)).toBe("general");
    expect(activeSectionAt(sections, 96, true)).toBe("about");
    expect(activeSectionAt([], 96, false)).toBeUndefined();
  });
});

describe("optimistic settings", () => {
  it("patches settings without touching the rest of the snapshot", () => {
    const snapshot = createTestSnapshot();
    const next = withSettingsPatch(snapshot, { closeToTrayEnabled: false, theme: "dark" });

    expect(next.store.settings.closeToTrayEnabled).toBe(false);
    expect(next.store.settings.theme).toBe("dark");
    expect(next.store.settings.loggingEnabled).toBe(snapshot.store.settings.loggingEnabled);
    expect(next.runtime).toBe(snapshot.runtime);
    expect(snapshot.store.settings.theme).toBe("system");
  });
});

describe("platform copy", () => {
  it("talks about the menu bar on macOS and the tray elsewhere", () => {
    expect(platformCopy("macos").trayTitle).toBe("Keep running in the menu bar when you close the window");
    expect(platformCopy("windows").trayTitle).toBe("Keep running in the tray when you close the window");
    expect(platformCopy("linux").freeMemoryWhy).toBe("Turn on “Keep running in the tray” to use this.");
  });

  it("offers launch at sign-in and in-app updates on Windows only", () => {
    expect(platformCopy("windows").signInAvailable).toBe(true);
    expect(platformCopy("macos").signInAvailable).toBe(false);
    expect(platformCopy("linux").signInDescription).toBe("Available on Windows only.");
    expect(platformCopy("linux").updatesInApp).toBe(false);
    expect(platformCopy("windows").successHint).toBe("Protected state and passed checks.");
    expect(platformCopy("macos").successHint).toBe("Proxy ready state and passed checks.");
  });

  it("names the secrets backend", () => {
    expect(secretsCopy("Windows DPAPI").title).toBe("Encrypted with Windows DPAPI");
    expect(secretsCopy("macOS Keychain").title).toBe("Encrypted with the macOS Keychain");
    expect(secretsCopy("Linux keyring").title).toBe("Encrypted with the system keyring");
    expect(secretsCopy("unavailable").title).toBe("No secure storage found");
  });
});

describe("general section", () => {
  it("names what auto-connect would start", () => {
    const store = {
      ...createDefaultStore(),
      sshConfigs: [{ id: "fra", name: "Frankfurt-01" } as SshConfig],
      proxyProfiles: [{ id: "nl", name: "Amsterdam reality" } as ProxyProfile],
      selectedConfigId: "fra"
    };
    expect(autoConnectTarget(store)).toEqual({ label: "SSH · Frankfurt-01", selected: true });
    expect(autoConnectTarget({ ...store, settings: { ...store.settings, lastConnectedTransport: "xray" } })).toEqual({ label: "Xray", selected: false });
    expect(
      autoConnectTarget({ ...store, selectedProxyProfileId: "nl", settings: { ...store.settings, lastConnectedTransport: "xray" } })
    ).toEqual({ label: "Xray · Amsterdam reality", selected: true });
  });

  it("uses the new routing mode names", () => {
    expect(routingModeLabel("proxy-all")).toBe("Full tunnel");
    expect(routingModeLabel("selected-rules")).toBe("Split tunnel");
  });
});

describe("diagnostics section", () => {
  it("reports recording, nothing recorded and off", () => {
    expect(presentDiagnostics(DEFAULT_SETTINGS).badge).toEqual({ text: "Recording", tone: "ok" });
    const nothing = presentDiagnostics({ loggingEnabled: true, diagnosticsLoggingEnabled: false, fileLoggingEnabled: false });
    expect(nothing.nothingRecorded).toBe(true);
    expect(nothing.badge).toEqual({ text: "Nothing recorded", tone: "warn" });
    const off = presentDiagnostics({ loggingEnabled: false, diagnosticsLoggingEnabled: true, fileLoggingEnabled: true });
    expect(off).toMatchObject({ historyOn: false, liveOn: false, fileOn: false, nothingRecorded: false });
    expect(off.badge).toEqual({ text: "Off", tone: "outline" });
  });

  it("brings both recorders back when history turns on again", () => {
    expect(historyPatch(true)).toEqual({ loggingEnabled: true, diagnosticsLoggingEnabled: true, fileLoggingEnabled: true });
    expect(historyPatch(false)).toEqual({ loggingEnabled: false });
  });

  it("shows the reported main.log path, else derives it", () => {
    expect(logFilePath(createTestSnapshot({ logFilePaths: ["C:\\data\\logs\\main.log.1", "C:\\data\\logs\\main.log"] }))).toBe("C:\\data\\logs\\main.log");
    expect(logFilePath(createTestSnapshot())).toBe("C:\\Users\\test\\AppData\\Roaming\\Shadow SSH\\logs\\main.log");
  });
});

describe("colours", () => {
  it("normalizes HEX input", () => {
    expect(normalizeHexInput("f6a019")).toBe("#F6A019");
    expect(normalizeHexInput(" #fa1 ")).toBe("#FFAA11");
    expect(normalizeHexInput("#F6A01")).toBeUndefined();
    expect(normalizeHexInput("orange")).toBeUndefined();
  });

  it("shows the theme's own Success and Danger while they are the defaults", () => {
    expect(colourHex(DEFAULT_CUSTOM_THEME, "success", "dark")).toBe("#34D08A");
    expect(colourHex(DEFAULT_CUSTOM_THEME, "success", "light")).toBe("#17A065");
    expect(colourHex(DEFAULT_CUSTOM_THEME, "danger", "light")).toBe("#D9363F");
    expect(colourHex(DEFAULT_CUSTOM_THEME, "accent", "light")).toBe("#F6A019");
    expect(colourHex(DEFAULT_CUSTOM_THEME, "background", "dark")).toBe("#EDF0F4");
  });

  it("stores picked colours, and the theme's own shade as following the theme", () => {
    const picked = withColour(DEFAULT_CUSTOM_THEME, "success", "#00FF00", "dark");
    expect(picked.success).toEqual({ r: 0, g: 255, b: 0 });
    expect(coloursAreDefault(picked)).toBe(false);

    const backToTheme = withColour(picked, "success", "#17A065", "light");
    expect(backToTheme.success).toEqual(DEFAULT_CUSTOM_THEME.success);
    expect(coloursAreDefault(backToTheme)).toBe(true);

    expect(withColour(DEFAULT_CUSTOM_THEME, "border", "#112233", "dark").border).toEqual({ r: 17, g: 34, b: 51 });
  });

  it("grades contrast like WCAG AA", () => {
    expect(contrastVerdict(4.5)).toEqual({ verdict: "passes", tone: "ok" });
    expect(contrastVerdict(3.2)).toEqual({ verdict: "large text only", tone: "warn" });
    expect(contrastVerdict(2.1)).toEqual({ verdict: "too low", tone: "danger" });
  });

  it("checks the built-in theme or the custom palette", () => {
    const builtIn = contrastChecks(DEFAULT_CUSTOM_THEME, "dark", "dark");
    expect(builtIn.note).toBe("Checked against the Dark theme");
    expect(builtIn.checks.map((check) => check.label)).toEqual(["Text on Background", "Muted text on Surface", "Button label on Accent"]);
    expect(builtIn.checks[0].verdict).toBe("passes");
    expect(builtIn.checks[0].value).toMatch(/^\d+\.\d:1$/u);

    const lowContrast = { ...DEFAULT_CUSTOM_THEME, text: { r: 200, g: 205, b: 210 } };
    const custom = contrastChecks(lowContrast, "custom", "light");
    expect(custom.note).toBe("Checked against your palette");
    expect(custom.checks[0].verdict).toBe("too low");
  });
});

describe("update download details", () => {
  it("explains checksum and size mismatches as an untrusted file", () => {
    expect(describeDownloadFailure("Downloaded update SHA-256 digest does not match the release metadata.").message).toBe(
      "The file didn’t match the checksum published with the release, so it can’t be trusted. Try downloading it again."
    );
    expect(describeDownloadFailure("Downloaded update size 12 does not match release metadata size 92.").technical).toBe(
      "Downloaded update size 12 does not match release metadata size 92."
    );
  });

  it("keeps other failures readable", () => {
    expect(describeDownloadFailure("Update download timed out.").message).toBe("GitHub took too long to answer. Check your connection, then try again.");
    expect(describeDownloadFailure("Unable to write downloaded update to disk.").message).toBe("Unable to write downloaded update to disk.");
    expect(describeDownloadFailure(undefined).message).toBe("The download stopped before it finished. Try downloading it again.");
  });

  it("recognises an unreachable GitHub", () => {
    expect(isOfflineError(new Error("Error invoking remote method 'shadow-ssh:check-for-updates': TypeError: fetch failed"))).toBe(true);
    expect(isOfflineError(new Error("net::ERR_INTERNET_DISCONNECTED"))).toBe(true);
    expect(isOfflineError(new Error("Update check timed out."))).toBe(true);
    expect(isOfflineError(new Error("GitHub update check failed: 403 Forbidden"))).toBe(false);
  });

  it("shows progress in the unit of the total", () => {
    expect(formatProgressBytes(85_100_000, 92_000_000)).toBe("85 of 92 MB");
    expect(formatProgressBytes(0, 92_000_000)).toBe("0 of 92 MB");
    expect(formatProgressBytes(500_000, undefined)).toBe("500 KB");
    expect(formatProgressBytes(0, undefined)).toBe("");
  });
});

describe("updates presentation", () => {
  const now = new Date(2026, 9, 6, 15, 0, 0);
  const available: AppUpdateInfo = {
    available: true,
    currentVersion: "2.2.0",
    latestVersion: "2.3.0",
    asset: {
      name: "shadow-ssh-2.3.0-windows-portable-x64.exe",
      version: "2.3.0",
      arch: "x64",
      size: 92_000_000,
      downloadUrl: "https://github.com/stansful/ssh-vpn-client-electron/releases/download/v2.3.0/shadow-ssh-2.3.0-windows-portable-x64.exe"
    },
    checkedAt: new Date(2026, 9, 6, 12, 4, 0).toISOString(),
    message: "Update 2.3.0 is available for Windows x64."
  };
  const base: UpdatesInput = { platform: "windows", arch: "x64", currentVersion: "2.2.0", checking: false, now };

  it("points macOS and Linux to GitHub", () => {
    const view = presentUpdates({ ...base, platform: "macos" });
    expect(view.phase).toBe("unsupported");
    expect(view.badge).toEqual({ text: "Windows only", tone: "outline", dot: false });
    expect(view.canDownload).toBe(false);
    expect(view.navDot).toBe(false);
  });

  it("starts unchecked and shows a busy check", () => {
    const fresh = presentUpdates(base);
    expect(fresh.phase).toBe("notChecked");
    expect(fresh.title).toBe("Not checked yet");
    expect(fresh.check).toMatchObject({ label: "Check now", disabled: false });

    const checking = presentUpdates({ ...base, checking: true, info: available });
    expect(checking.phase).toBe("checking");
    expect(checking.badge).toEqual({ text: "Checking…", tone: "busy", dot: false });
    expect(checking.check).toMatchObject({ label: "Checking…", disabled: true });
    expect(checking.latestVersion).toBeUndefined();
  });

  it("offers the download with version, size and the time of the check", () => {
    const view = presentUpdates({ ...base, info: available });
    expect(view.phase).toBe("available");
    expect(view.title).toBe("Version 2.3.0 is available for Windows x64");
    expect(view.sub).toBe("Checked today at 12:04.");
    expect(view.badge).toEqual({ text: "2.3.0 available", tone: "accent", dot: true });
    expect(view.fileLine).toBe("shadow-ssh-2.3.0-windows-portable-x64.exe · 92 MB");
    expect(view.downloadLabel).toBe("Download 2.3.0 · 92 MB");
    expect(view.canDownload).toBe(true);
    expect(view.navDot).toBe(true);
  });

  it("tracks a running download and keeps Check now disabled meanwhile", () => {
    const view = presentUpdates({
      ...base,
      info: available,
      download: { state: "downloading", downloadedBytes: 46_000_000, totalBytes: 92_000_000, percent: 50.4 }
    });
    expect(view.badge).toEqual({ text: "Downloading…", tone: "busy", dot: false });
    expect(view.download).toMatchObject({ state: "downloading", percent: 50, bytesText: "46 of 92 MB" });
    expect(view.canDownload).toBe(false);
    expect(view.check).toMatchObject({ disabled: true, title: "Available when the download finishes" });
  });

  it("shows a finished download with its file", () => {
    const view = presentUpdates({
      ...base,
      info: available,
      download: { state: "downloaded", downloadedBytes: 92_000_000, totalBytes: 92_000_000, percent: 100, filePath: "C:\\data\\updates\\x.exe" }
    });
    expect(view.badge).toEqual({ text: "Downloaded", tone: "ok", dot: true });
    expect(view.download).toMatchObject({ state: "downloaded", percent: 100, filePath: "C:\\data\\updates\\x.exe" });
    expect(view.navDot).toBe(false);
  });

  it("offers a new attempt after a failed download", () => {
    const view = presentUpdates({
      ...base,
      info: available,
      download: { state: "error", downloadedBytes: 10, totalBytes: 92_000_000, message: "Downloaded update SHA-256 digest does not match the release metadata." }
    });
    expect(view.download.state).toBe("failed");
    expect(view.download.failure?.message).toContain("checksum");
    expect(view.downloadLabel).toBe("Download again · 92 MB");
    expect(view.canDownload).toBe(true);

    const early = presentUpdates({ ...base, info: available, downloadError: new Error("No downloadable update asset is selected. Check for updates first.") });
    expect(early.download.state).toBe("failed");
    expect(early.download.failure?.message).toBe("No downloadable update asset is selected. Check for updates first.");
  });

  it("says GitHub can't be reached and keeps a known newer version on screen", () => {
    const offline = presentUpdates({ ...base, checkError: new Error("net::ERR_INTERNET_DISCONNECTED") });
    expect(offline.phase).toBe("checkFailed");
    expect(offline.title).toBe("Can’t reach GitHub");
    expect(offline.sub).toBe("Check your internet connection, then try again.");
    expect(offline.titleDanger).toBe(true);
    expect(offline.badge).toEqual({ text: "Check failed", tone: "danger", dot: true });
    expect(offline.check.label).toBe("Try again");

    const other = presentUpdates({ ...base, info: available, checkError: new Error("Latest release tag is not a strict SemVer version.") });
    expect(other.title).toBe("Couldn’t check for updates");
    expect(other.sub).toBe("Latest release tag is not a strict SemVer version.");
    expect(other.latestVersion).toBe("2.3.0");
    expect(other.canDownload).toBe(true);
  });

  it("reports the latest version and releases without a matching file", () => {
    const latest = presentUpdates({ ...base, info: { available: false, currentVersion: "2.2.0", checkedAt: available.checkedAt, message: "You are already on 2.2.0." } });
    expect(latest.phase).toBe("upToDate");
    expect(latest.title).toBe("You’re on the latest version");
    expect(latest.sub).toBe("2.2.0 is the newest release. Checked today at 12:04.");
    expect(latest.badge).toEqual({ text: "Up to date", tone: "ok", dot: true });

    const noAsset = presentUpdates({ ...base, arch: "arm64", info: { ...available, asset: undefined } });
    expect(noAsset.phase).toBe("availableNoAsset");
    expect(noAsset.title).toBe("Version 2.3.0 is available");
    expect(noAsset.sub).toContain("no portable file for Windows arm64");
    expect(noAsset.canDownload).toBe(false);
    expect(noAsset.latestVersion).toBe("2.3.0");
  });
});
