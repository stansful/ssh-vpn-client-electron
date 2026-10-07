import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  createAppEnvironment,
  deriveTunStatus,
  describeSecretsBackend,
  TUN_FAILURE_GENERIC,
  TUN_FAILURE_NO_WINTUN,
  TUN_FAILURE_NOT_ELEVATED,
  type TunEnvironmentFacts
} from "../src/main/app/environment.js";
import { resolveAppDataLayout } from "../src/main/app/paths.js";

const usableSecrets = { encryptionAvailable: true, insecureFallbackAllowed: false };

describe("app environment", () => {
  it("describes the packaged build and its folders", () => {
    expect(
      createAppEnvironment({
        version: "2.2.0",
        platform: "win32",
        arch: "x64",
        dataDirectory: "C:\\Users\\alex\\AppData\\Roaming\\Shadow SSH",
        logDirectory: "C:\\Users\\alex\\AppData\\Roaming\\Shadow SSH\\logs",
        isPackaged: true,
        buildChannel: "production",
        secrets: usableSecrets
      })
    ).toEqual({
      version: "2.2.0",
      platform: "windows",
      arch: "x64",
      dataDirectory: "C:\\Users\\alex\\AppData\\Roaming\\Shadow SSH",
      logDirectory: "C:\\Users\\alex\\AppData\\Roaming\\Shadow SSH\\logs",
      secretsBackend: "Windows DPAPI",
      isDevBuild: false
    });
  });

  it("marks unpackaged and development-channel builds as dev builds", () => {
    const base = { version: "2.2.0", platform: "darwin" as const, arch: "arm64" as const, dataDirectory: "/d", logDirectory: "/d/logs", secrets: usableSecrets };
    expect(createAppEnvironment({ ...base, isPackaged: false }).isDevBuild).toBe(true);
    expect(createAppEnvironment({ ...base, isPackaged: true, buildChannel: "development" }).isDevBuild).toBe(true);
  });

  it("names the secrets backend the store really uses", () => {
    expect(describeSecretsBackend("darwin", usableSecrets)).toBe("macOS Keychain");
    expect(describeSecretsBackend("linux", { ...usableSecrets, selectedBackend: "gnome_libsecret" })).toBe("Linux keyring");
    expect(describeSecretsBackend("linux", { ...usableSecrets, selectedBackend: "basic_text" })).toBe("unavailable");
    expect(describeSecretsBackend("linux", { encryptionAvailable: true, selectedBackend: "basic_text", insecureFallbackAllowed: true })).toBe(
      "Linux keyring"
    );
    expect(describeSecretsBackend("win32", { encryptionAvailable: false, insecureFallbackAllowed: false })).toBe("unavailable");
  });
});

describe("TUN status", () => {
  const ready: TunEnvironmentFacts = { supported: true, elevated: true, wintunFound: true, searchedPaths: ["C:\\app", "C:\\data"] };

  it("is unsupported away from Windows", () => {
    const status = deriveTunStatus({
      environment: { supported: false, elevated: false, wintunFound: false, searchedPaths: [] },
      platform: "darwin",
      enabled: true,
      sessionState: "Connected",
      tunActive: false,
      sessionTunSetting: true
    });
    expect(status).toMatchObject({ supported: false, active: false, appliesOnNextConnect: false });
    expect(status.lastFailure).toBeUndefined();
  });

  it("says what is missing before and during a session", () => {
    const base = { platform: "win32" as const, enabled: true, tunActive: false };
    expect(
      deriveTunStatus({ ...base, environment: { ...ready, elevated: false }, sessionState: "Disconnected" }).lastFailure
    ).toBe(TUN_FAILURE_NOT_ELEVATED);
    expect(
      deriveTunStatus({ ...base, environment: { ...ready, wintunFound: false }, sessionState: "Disconnected" }).lastFailure
    ).toBe(TUN_FAILURE_NO_WINTUN);
    expect(deriveTunStatus({ ...base, environment: ready, sessionState: "Disconnected" }).lastFailure).toBeUndefined();
    expect(deriveTunStatus({ ...base, environment: ready, sessionState: "Connected", sessionTunSetting: true }).lastFailure).toBe(
      TUN_FAILURE_GENERIC
    );
  });

  it("reports an active adapter only for a live session", () => {
    const active = deriveTunStatus({
      environment: ready,
      platform: "win32",
      enabled: true,
      sessionState: "Connected",
      tunActive: true,
      sessionTunSetting: true
    });
    expect(active).toMatchObject({ active: true, appliesOnNextConnect: false });
    expect(active.lastFailure).toBeUndefined();
    expect(
      deriveTunStatus({ environment: ready, platform: "win32", enabled: true, sessionState: "Disconnected", tunActive: true }).active
    ).toBe(false);
  });

  it("flags a setting changed during the session as applying on the next connect", () => {
    expect(
      deriveTunStatus({
        environment: ready,
        platform: "win32",
        enabled: false,
        sessionState: "Connected",
        tunActive: true,
        sessionTunSetting: true
      }).appliesOnNextConnect
    ).toBe(true);
    expect(
      deriveTunStatus({
        environment: ready,
        platform: "win32",
        enabled: false,
        sessionState: "Disconnected",
        tunActive: false,
        sessionTunSetting: true
      }).appliesOnNextConnect
    ).toBe(false);
  });

  it("stays quiet about failures until the first probe finishes", () => {
    const status = deriveTunStatus({ platform: "win32", enabled: true, sessionState: "Disconnected", tunActive: false });
    expect(status).toMatchObject({ supported: true, elevated: false, wintunFound: false, searchedPaths: [] });
    expect(status.lastFailure).toBeUndefined();
  });
});

describe("app data layout", () => {
  it("keeps storage, logs, routing, xray and updates inside the data folder", () => {
    const root = path.join("/data", "Shadow SSH");
    expect(resolveAppDataLayout(root)).toEqual({
      dataDirectory: root,
      storageDirectory: path.join(root, "storage"),
      storePath: path.join(root, "storage", "app-store.v1.json"),
      logDirectory: path.join(root, "logs"),
      mainLogPath: path.join(root, "logs", "main.log"),
      routingDirectory: path.join(root, "routing"),
      xrayRuntimeDirectory: path.join(root, "xray"),
      updatesDirectory: path.join(root, "updates")
    });
  });
});
