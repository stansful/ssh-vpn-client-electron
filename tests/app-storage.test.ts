import { generateKeyPairSync } from "node:crypto";
import { copyFile, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SshBinaryWriter } from "../src/core/ssh/binary.js";
import { SSH_KEY_FIXTURES } from "./ssh-key-fixtures.js";
import {
  createDefaultStore,
  DEFAULT_CUSTOM_THEME,
  LEGACY_DEFAULT_SIGNAL_COLORS,
  LEGACY_PUBLIC_PROXY_LIST_URLS,
  PUBLIC_PROXY_LIST_URL,
  RUSSIA_INSIDE_PROXY_LIST_URL,
  RUSSIA_OUTSIDE_DIRECT_LIST_URL,
  STORE_SCHEMA_VERSION
} from "../src/shared/defaults.js";

vi.mock("electron", () => ({
  app: {
    getPath: () => path.join(os.tmpdir(), "shadow-ssh-test-user-data")
  },
  safeStorage: {
    isEncryptionAvailable: () => false,
    encryptString: (value: string) => Buffer.from(value, "utf8"),
    decryptString: (value: Buffer) => value.toString("utf8")
  }
}));

const {
  AppStorage,
  STORAGE_WRITE_BLOCKED_MESSAGE,
  UNSUPPORTED_PROXY_PROFILE_MESSAGE,
  assertSerializedJsonWithinLimit,
  assertStoredProxyProfileCapacity,
  CoalescingAtomicJsonWriter,
  isProductionSecretStorageRuntime,
  isSafeStorageBackendUsable,
  readJsonFileWithLimit,
  renameWithRetry,
  writeJsonAtomic
} = await import("../src/main/storage/app-storage.js");

describe("AppStorage persistence", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it("defaults startup auto-connect to enabled", () => {
    const defaults = createDefaultStore().settings;

    expect(defaults.autoConnectOnStartup).toBe(true);
    expect(defaults.lastConnectedTransport).toBe("ssh");
  });

  it("rejects Linux safeStorage basic_text unless insecure storage was explicitly allowed", () => {
    expect(isSafeStorageBackendUsable(true, "linux", "basic_text", false)).toBe(false);
    expect(isSafeStorageBackendUsable(true, "linux", "basic_text", true)).toBe(true);
    expect(isSafeStorageBackendUsable(true, "linux", "gnome_libsecret", false)).toBe(true);
    expect(isSafeStorageBackendUsable(true, "darwin", undefined, false)).toBe(true);
  });

  it("treats packaged Electron as production even when NODE_ENV is absent at runtime", () => {
    expect(isProductionSecretStorageRuntime(true, undefined)).toBe(true);
    expect(isProductionSecretStorageRuntime(false, "production")).toBe(true);
    expect(isProductionSecretStorageRuntime(false, undefined)).toBe(false);
  });

  it("defaults the Russia inside proxy list to disabled", () => {
    const proxyList = createDefaultStore().routingProxyList;

    expect(proxyList.enabled).toBe(false);
    expect(proxyList.sourceUrl).toBe(RUSSIA_INSIDE_PROXY_LIST_URL);
    expect(proxyList.domains).toEqual([]);
  });

  it("defaults the Russia outside direct list to disabled", () => {
    const directList = createDefaultStore().routingDirectList;

    expect(directList.enabled).toBe(false);
    expect(directList.sourceUrl).toBe(RUSSIA_OUTSIDE_DIRECT_LIST_URL);
    expect(directList.domains).toEqual([]);
  });

  it("migrates the temporary routingBypassList field into the proxy list", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const legacyStore = {
      ...createDefaultStore(),
      routingProxyList: undefined,
      routingBypassList: {
        enabled: true,
        sourceUrl: RUSSIA_INSIDE_PROXY_LIST_URL,
        domains: ["gosuslugi.ru", ".ru"],
        updatedAt: "2026-07-04T00:00:00.000Z"
      }
    };
    await writeFile(path.join(dir, "app-store.v1.json"), `${JSON.stringify(legacyStore, null, 2)}\n`, "utf8");

    const storage = new AppStorage(dir);
    await storage.init();

    expect(storage.getStore().routingProxyList).toEqual({
      enabled: true,
      sourceUrl: RUSSIA_INSIDE_PROXY_LIST_URL,
      domains: [".ru", "gosuslugi.ru"],
      updatedAt: "2026-07-04T00:00:00.000Z"
    });
  });

  it("uses independent temp files for concurrent atomic writes", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const filePath = path.join(dir, "store.json");

    await Promise.all(Array.from({ length: 24 }, (_, index) => writeJsonAtomic(filePath, { index })));

    const parsed = JSON.parse(await readFile(filePath, "utf8")) as { index: number };
    expect(Number.isInteger(parsed.index)).toBe(true);
    expect(parsed.index).toBeGreaterThanOrEqual(0);
    expect(parsed.index).toBeLessThan(24);
    expect((await readdir(dir)).filter((name) => name.endsWith(".tmp"))).toEqual([]);
  });

  it("coalesces only queued writes and captures every JSON snapshot synchronously", async () => {
    const writes: string[] = [];
    let releaseFirst!: () => void;
    const firstWriteGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const writer = new CoalescingAtomicJsonWriter("store.json", async (_filePath, serialized) => {
      writes.push(serialized);
      if (writes.length === 1) {
        await firstWriteGate;
      }
    });
    const firstValue = { index: 1 };

    const first = writer.write(firstValue);
    firstValue.index = 99;
    const second = writer.write({ index: 2 });
    const third = writer.write({ index: 3 });
    let queuedCallResolved = false;
    void second.then(() => {
      queuedCallResolved = true;
    });
    await Promise.resolve();

    expect(queuedCallResolved).toBe(false);
    releaseFirst();
    await Promise.all([first, second, third]);

    expect(writes.map((serialized) => (JSON.parse(serialized) as { index: number }).index)).toEqual([1, 3]);
    expect(queuedCallResolved).toBe(true);
  });

  it("bounds persisted JSON reads and the aggregate proxy profile collection", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const filePath = path.join(dir, "bounded.json");
    await writeFile(filePath, JSON.stringify({ value: "too large" }), "utf8");

    await expect(readJsonFileWithLimit(filePath, 4, "Test store")).rejects.toThrow("byte limit");
    expect(() => assertSerializedJsonWithinLimit(JSON.stringify({ value: "too large" }), 4, "Test store")).toThrow(
      "byte limit"
    );
    expect(() => assertStoredProxyProfileCapacity(9_999, 1)).not.toThrow();
    expect(() => assertStoredProxyProfileCapacity(10_000, 1)).toThrow("profile limit");
  });

  it("rejects an oversized queued snapshot before invoking the atomic writer", async () => {
    const writeAtomic = vi.fn(async () => undefined);
    const writer = new CoalescingAtomicJsonWriter("store.json", writeAtomic, {
      maxBytes: 16,
      label: "Test store"
    });

    expect(() => writer.write({ value: "this snapshot is too large" })).toThrow("byte limit");
    expect(writeAtomic).not.toHaveBeenCalled();
  });

  it("serializes concurrent settings persistence", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const defaults = createDefaultStore().settings;

    await Promise.all(
      Array.from({ length: 24 }, (_, index) =>
        storage.updateSettings({
          ...defaults,
          checkEndpoint: `example-${index}.com:443`,
          diagnosticsExpanded: index % 2 === 0,
          terminalExpanded: index % 3 === 0
        })
      )
    );

    const persisted = JSON.parse(await readFile(path.join(dir, "app-store.v1.json"), "utf8")) as ReturnType<typeof createDefaultStore>;
    expect(persisted.settings).toEqual(storage.getStore().settings);
    expect((await readdir(dir)).filter((name) => name.endsWith(".tmp"))).toEqual([]);
    if (process.platform !== "win32") {
      expect((await stat(path.join(dir, "app-store.v1.json"))).mode & 0o777).toBe(0o600);
      expect((await stat(path.join(dir, "secret-store.v1.json"))).mode & 0o777).toBe(0o600);
    }
  });

  it("turns tunnel-adapter capture on for stores written before the setting worked", async () => {
    // The build that first shipped the setting persisted it as `false` and
    // could never act on it - the native helper crashed at start-up - so that
    // stored value records nothing the user chose. Everything else in the old
    // store must survive.
    const dir = await makeTempDir(cleanupDirs);
    const legacy = createDefaultStore();
    await writeFile(
      path.join(dir, "app-store.v1.json"),
      JSON.stringify({
        ...legacy,
        schemaVersion: 1,
        settings: { ...legacy.settings, tunDataplaneEnabled: false, checkEndpoint: "example.com:443" }
      }),
      "utf8"
    );

    const storage = new AppStorage(dir);
    await storage.init();

    expect(storage.getSettings().tunDataplaneEnabled).toBe(true);
    expect(storage.getSettings().checkEndpoint).toBe("example.com:443");
    expect(storage.getStore().schemaVersion).toBe(STORE_SCHEMA_VERSION);
  });

  it("keeps a tunnel-adapter choice made after the migration", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const current = createDefaultStore();
    await writeFile(
      path.join(dir, "app-store.v1.json"),
      JSON.stringify({
        ...current,
        schemaVersion: 2,
        settings: { ...current.settings, tunDataplaneEnabled: false }
      }),
      "utf8"
    );

    const storage = new AppStorage(dir);
    await storage.init();

    expect(storage.getSettings().tunDataplaneEnabled).toBe(false);
  });

  it("does not atomically rewrite unchanged stores on subsequent startup", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const first = new AppStorage(dir);
    await first.init();
    const storePath = path.join(dir, "app-store.v1.json");
    const secretPath = path.join(dir, "secret-store.v1.json");
    const storeBefore = await stat(storePath);
    const secretsBefore = await stat(secretPath);

    const second = new AppStorage(dir);
    await second.init();
    const storeAfter = await stat(storePath);
    const secretsAfter = await stat(secretPath);

    expect(storeAfter.ino).toBe(storeBefore.ino);
    expect(storeAfter.mtimeMs).toBe(storeBefore.mtimeMs);
    expect(secretsAfter.ino).toBe(secretsBefore.ino);
    expect(secretsAfter.mtimeMs).toBe(secretsBefore.mtimeMs);
  });

  it("merges settings patches without replacing unrelated preferences", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const before = storage.getStore().settings;

    const store = await storage.updateSettings({
      sidebarCollapsed: !before.sidebarCollapsed,
      customTheme: { ...before.customTheme, accent: { r: 1, g: 2, b: 3 } }
    });

    expect(store.settings.sidebarCollapsed).toBe(!before.sidebarCollapsed);
    expect(store.settings.customTheme.accent).toEqual({ r: 1, g: 2, b: 3 });
    expect(store.settings.checkEndpoint).toBe(before.checkEndpoint);
    expect(store.settings.startWithWindowsInTray).toBe(before.startWithWindowsInTray);
    expect(store.settings.releaseRendererInTrayEnabled).toBe(before.releaseRendererInTrayEnabled);
  });

  it("returns a detached settings branch without cloning large store collections", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();

    const settings = storage.getSettings();
    settings.customTheme.accent.r = 255;

    expect(storage.getSettings().customTheme.accent.r).not.toBe(255);
  });

  it("updates large proxy imports without duplicating existing fingerprints", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const links = Array.from(
      { length: 400 },
      (_, index) => `vless://client-${index}@proxy-${index}.example.com:443?type=tcp&security=tls#profile-${index}`
    ).join("\n");

    const first = await storage.importProxyProfiles({ text: links, source: "clipboard" });
    const secretPath = path.join(dir, "secret-store.v1.json");
    const secretsBefore = await stat(secretPath);
    const originalIds = new Set(first.store.proxyProfiles.map((profile) => profile.id));
    const second = await storage.importProxyProfiles({ text: links, source: "clipboard" });
    const secretsAfter = await stat(secretPath);

    expect(first.result.imported).toBe(400);
    expect(second.result.updated).toBe(400);
    expect(second.store.proxyProfiles).toHaveLength(400);
    expect(new Set(second.store.proxyProfiles.map((profile) => profile.id))).toEqual(originalIds);
    expect(secretsAfter.ino).toBe(secretsBefore.ino);
    expect(secretsAfter.mtimeMs).toBe(secretsBefore.mtimeMs);
  });

  it("stores private-key passphrase on the SSH key entity", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const keyPem = generatePrivateKeyPem();

    let store = await storage.upsertKey({ name: "deploy", privateKey: keyPem, privateKeyPassphrase: "key-passphrase" });
    const key = store.sshKeys[0];
    expect(key?.privateKeyPassphraseSecretId).toBeTruthy();

    store = await storage.upsertConfig({
      name: "server",
      host: "ssh.example.com",
      port: 22,
      username: "root",
      authType: "private-key",
      privateKeyId: key?.id,
      expectedServerFingerprint: "",
      keepaliveIntervalSec: 120,
      note: ""
    });
    const config = store.sshConfigs[0];
    expect(config?.privateKeyPassphraseSecretId).toBeUndefined();
    expect(config ? storage.resolveServiceSecrets(config).privateKeyPassphrase : undefined).toBe("key-passphrase");
  });

  it("reads a saved private key for main-process clipboard copy", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const keyPem = generatePrivateKeyPem();

    const store = await storage.upsertKey({ name: "copyable", privateKey: keyPem, privateKeyPassphrase: "" });
    const key = store.sshKeys[0];

    expect(key ? storage.readPrivateKeyText(key.id) : undefined).toBe(keyPem.trimEnd());
  });

  it("persists metadata deletion before removing its unreferenced secret", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const store = await storage.upsertConfig({
      name: "password server",
      host: "ssh.example.com",
      port: 22,
      username: "root",
      authType: "password",
      password: "secret",
      expectedServerFingerprint: "",
      keepaliveIntervalSec: 120,
      note: ""
    });
    const config = store.sshConfigs[0];
    expect(config?.passwordSecretId).toBeTruthy();

    if (config) {
      await storage.deleteConfig(config.id);
    }

    const persistedStore = JSON.parse(await readFile(path.join(dir, "app-store.v1.json"), "utf8")) as ReturnType<typeof createDefaultStore>;
    const persistedSecrets = JSON.parse(await readFile(path.join(dir, "secret-store.v1.json"), "utf8")) as {
      secrets: Record<string, unknown>;
    };
    expect(persistedStore.sshConfigs).toEqual([]);
    expect(config?.passwordSecretId ? persistedSecrets.secrets[config.passwordSecretId] : undefined).toBeUndefined();
  });

  it("removes an orphaned secret left by an interrupted post-delete cleanup", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const store = await storage.upsertConfig({
      name: "password server",
      host: "ssh.example.com",
      port: 22,
      username: "root",
      authType: "password",
      password: "secret",
      expectedServerFingerprint: "",
      keepaliveIntervalSec: 120,
      note: ""
    });
    const secretId = store.sshConfigs[0]?.passwordSecretId;
    await writeFile(
      path.join(dir, "app-store.v1.json"),
      `${JSON.stringify({ ...store, sshConfigs: [], selectedConfigId: undefined }, null, 2)}\n`,
      "utf8"
    );

    const recovered = new AppStorage(dir);
    await recovered.init();

    const persistedSecrets = JSON.parse(await readFile(path.join(dir, "secret-store.v1.json"), "utf8")) as {
      secrets: Record<string, unknown>;
    };
    expect(secretId ? persistedSecrets.secrets[secretId] : undefined).toBeUndefined();
  });

  it("migrates legacy proxy settings names to Xray settings", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const legacySettings = { ...createDefaultStore().settings } as Record<string, unknown>;
    delete legacySettings.autoConnectOnStartup;
    delete legacySettings.releaseRendererInTrayEnabled;
    delete legacySettings.lastConnectedTransport;
    delete legacySettings.xrayConsentAccepted;
    delete legacySettings.showXrayWarningOnEnter;
    delete legacySettings.xrayRiskBannerExpanded;
    const legacyStore = {
      ...createDefaultStore(),
      settings: {
        ...legacySettings,
        activeGlobalTab: "opensource",
        openSourceConsentAccepted: true,
        showOpenSourceWarningOnEnter: false,
        openSourceRiskBannerExpanded: false
      }
    };
    await writeFile(path.join(dir, "app-store.v1.json"), `${JSON.stringify(legacyStore, null, 2)}\n`, "utf8");

    const storage = new AppStorage(dir);
    await storage.init();

    expect(storage.getStore().settings.activeGlobalTab).toBe("xray");
    expect(storage.getStore().settings.releaseRendererInTrayEnabled).toBe(true);
    expect(storage.getStore().settings.lastConnectedTransport).toBe("xray");
    expect(storage.getStore().settings.xrayConsentAccepted).toBe(true);
    expect(storage.getStore().settings.showXrayWarningOnEnter).toBe(false);
    expect(storage.getStore().settings.xrayRiskBannerExpanded).toBe(false);
  });

  it("migrates legacy config private-key passphrases onto SSH keys", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const keyPem = generatePrivateKeyPem();

    let store = await storage.upsertKey({ name: "legacy", privateKey: keyPem, privateKeyPassphrase: "legacy-passphrase" });
    const key = store.sshKeys[0];
    const passphraseSecretId = key?.privateKeyPassphraseSecretId;
    expect(passphraseSecretId).toBeTruthy();
    store = await storage.upsertConfig({
      name: "legacy-server",
      host: "ssh.example.com",
      port: 22,
      username: "root",
      authType: "private-key",
      privateKeyId: key?.id,
      expectedServerFingerprint: "",
      keepaliveIntervalSec: 120,
      note: ""
    });

    const legacyStore = {
      ...store,
      sshKeys: store.sshKeys.map((candidate) =>
        candidate.id === key?.id ? { ...candidate, privateKeyPassphraseSecretId: undefined } : candidate
      ),
      sshConfigs: store.sshConfigs.map((config) =>
        config.privateKeyId === key?.id ? { ...config, privateKeyPassphraseSecretId: passphraseSecretId } : config
      )
    };
    await writeFile(path.join(dir, "app-store.v1.json"), `${JSON.stringify(legacyStore, null, 2)}\n`, "utf8");

    const migrated = new AppStorage(dir);
    await migrated.init();
    const migratedStore = migrated.getStore();
    const migratedKey = migratedStore.sshKeys.find((candidate) => candidate.id === key?.id);
    const migratedConfig = migratedStore.sshConfigs.find((candidate) => candidate.privateKeyId === key?.id);
    expect(migratedKey?.privateKeyPassphraseSecretId).toBe(passphraseSecretId);
    expect(migratedConfig?.privateKeyPassphraseSecretId).toBeUndefined();
    expect(migratedConfig ? migrated.resolveServiceSecrets(migratedConfig).privateKeyPassphrase : undefined).toBe("legacy-passphrase");
  });
});

describe("AppStorage recovery", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it("blocks every write while the store could not be read, and leaves the file untouched", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storePath = path.join(dir, "app-store.v1.json");
    await writeFile(storePath, "{ this is not json", "utf8");

    const storage = new AppStorage(dir);
    await expect(storage.init()).rejects.toThrow();

    expect(storage.isInitialized).toBe(false);
    expect(storage.storePath).toBe(storePath);
    expect(storage.dataDirectory).toBe(dir);
    const writes: Array<() => Promise<unknown>> = [
      () => storage.updateSettings({ sidebarCollapsed: true }),
      () => storage.updateRoutingMode("selected-rules"),
      () => storage.updateRoutingRules([]),
      () => storage.upsertConfig({
        name: "server",
        host: "ssh.example.com",
        port: 22,
        username: "root",
        authType: "password",
        password: "secret",
        expectedServerFingerprint: "",
        keepaliveIntervalSec: 120,
        note: ""
      }),
      () => storage.deleteConfig("missing"),
      () => storage.selectConfig("missing"),
      () => storage.upsertKey({ name: "key", privateKey: generatePrivateKeyPem() }),
      () => storage.deleteKey("missing"),
      () => storage.importProxyProfiles({ text: "vless://id@proxy.example.com:443?type=tcp&security=tls#a", source: "clipboard" }),
      () => storage.upsertProxyProfile({ name: "", rawUri: "vless://id@proxy.example.com:443?type=tcp&security=tls#a" }),
      () => storage.selectProxyProfile("missing"),
      () => storage.toggleProxyProfilePin("missing"),
      () => storage.renameProxyProfile("missing", "name"),
      () => storage.deleteProxyProfile("missing"),
      () => storage.deleteUnpinnedProxyProfiles(),
      () => storage.updateRoutingProxyList(createDefaultStore().routingProxyList),
      () => storage.updateRoutingDirectList(createDefaultStore().routingDirectList),
      () => storage.setRoutingProxyListEnabled(true),
      () => storage.setRoutingDirectListEnabled(true)
    ];
    for (const write of writes) {
      await expect(write()).rejects.toThrow(STORAGE_WRITE_BLOCKED_MESSAGE);
    }
    expect(await readFile(storePath, "utf8")).toBe("{ this is not json");
  });

  it("starts fresh by moving both files aside as dated backups", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storePath = path.join(dir, "app-store.v1.json");
    const secretPath = path.join(dir, "secret-store.v1.json");
    await writeFile(storePath, "{ broken", "utf8");
    await writeFile(secretPath, JSON.stringify({ schemaVersion: 1, secrets: {} }), "utf8");
    const storage = new AppStorage(dir);
    await expect(storage.init()).rejects.toThrow();

    const backups = await storage.startFresh();

    expect(backups).toHaveLength(2);
    expect(path.basename(backups[0] ?? "")).toMatch(/^app-store\.v1\.unreadable-\d{8}-\d{6}\.json$/u);
    expect(path.basename(backups[1] ?? "")).toMatch(/^secret-store\.v1\.unreadable-\d{8}-\d{6}\.json$/u);
    expect(await readFile(backups[0] ?? "", "utf8")).toBe("{ broken");
    expect(storage.isInitialized).toBe(true);
    expect(storage.getStore()).toEqual(createDefaultStore());
    const persisted = JSON.parse(await readFile(storePath, "utf8")) as { schemaVersion: number };
    expect(persisted.schemaVersion).toBe(STORE_SCHEMA_VERSION);
    await expect(storage.updateSettings({ sidebarCollapsed: true })).resolves.toMatchObject({
      settings: { sidebarCollapsed: true }
    });
  });

  it("never overwrites an earlier backup taken in the same second", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await writeFile(path.join(dir, "app-store.v1.json"), "first", "utf8");
    await expect(storage.init()).rejects.toThrow();
    const first = await storage.startFresh();
    await writeFile(path.join(dir, "app-store.v1.json"), "second", "utf8");

    const second = await storage.startFresh();

    const firstStoreBackup = first.find((backup) => path.basename(backup).startsWith("app-store"));
    const secondStoreBackup = second.find((backup) => path.basename(backup).startsWith("app-store"));
    expect(firstStoreBackup).toBeDefined();
    expect(secondStoreBackup).toBeDefined();
    expect(secondStoreBackup).not.toBe(firstStoreBackup);
    expect(await readFile(firstStoreBackup ?? "", "utf8")).toBe("first");
    expect(await readFile(secondStoreBackup ?? "", "utf8")).toBe("second");
  });

  it("reports a store that is valid JSON but not an object as unreadable", async () => {
    const dir = await makeTempDir(cleanupDirs);
    await writeFile(path.join(dir, "app-store.v1.json"), "null", "utf8");

    const storage = new AppStorage(dir);

    await expect(storage.init()).rejects.toThrow("Application store has an unexpected format.");
    expect(storage.isInitialized).toBe(false);
  });
});

describe("AppStorage schema 3", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it("moves the old default signal colours to the new palette and keeps picked colours", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const legacy = createDefaultStore();
    const legacySettings = { ...legacy.settings } as Record<string, unknown>;
    delete legacySettings.notifyTunnelChanges;
    delete legacySettings.notifyUpdateDownloaded;
    delete legacySettings.notifyStillRunningInTray;
    delete legacySettings.notifyOnlyWhenHidden;
    delete legacySettings.stillRunningNoticeShown;
    await writeFile(
      path.join(dir, "app-store.v1.json"),
      JSON.stringify({
        ...legacy,
        schemaVersion: 2,
        settings: {
          ...legacySettings,
          customTheme: {
            ...legacy.settings.customTheme,
            accent: { r: 10, g: 20, b: 30 },
            success: LEGACY_DEFAULT_SIGNAL_COLORS.success,
            danger: LEGACY_DEFAULT_SIGNAL_COLORS.danger
          }
        }
      }),
      "utf8"
    );

    const storage = new AppStorage(dir);
    await storage.init();
    const settings = storage.getSettings();

    expect(settings.customTheme.accent).toEqual({ r: 10, g: 20, b: 30 });
    expect(settings.customTheme.success).toEqual(DEFAULT_CUSTOM_THEME.success);
    expect(settings.customTheme.danger).toEqual(DEFAULT_CUSTOM_THEME.danger);
    expect(settings.notifyTunnelChanges).toBe(true);
    expect(settings.notifyUpdateDownloaded).toBe(true);
    expect(settings.notifyStillRunningInTray).toBe(true);
    expect(settings.notifyOnlyWhenHidden).toBe(true);
    expect(settings.stillRunningNoticeShown).toBe(false);
    expect(storage.getStore().schemaVersion).toBe(STORE_SCHEMA_VERSION);
  });

  it("keeps a legacy colour picked after the migration", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const current = createDefaultStore();
    await writeFile(
      path.join(dir, "app-store.v1.json"),
      JSON.stringify({
        ...current,
        schemaVersion: 3,
        settings: {
          ...current.settings,
          notifyOnlyWhenHidden: false,
          customTheme: { ...current.settings.customTheme, accent: LEGACY_DEFAULT_SIGNAL_COLORS.accent }
        }
      }),
      "utf8"
    );

    const storage = new AppStorage(dir);
    await storage.init();

    expect(storage.getSettings().customTheme.accent).toEqual(LEGACY_DEFAULT_SIGNAL_COLORS.accent);
    expect(storage.getSettings().notifyOnlyWhenHidden).toBe(false);
  });

  it("records the key type and format when a key is saved", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const rsa = generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey.export({ format: "pem", type: "pkcs1" }).toString();

    let store = await storage.upsertKey({ name: "ed", privateKey: generatePrivateKeyPem() });
    store = await storage.upsertKey({ name: "rsa", privateKey: rsa });

    expect(store.sshKeys.map((key) => [key.name, key.keyType, key.keyFormat, key.encryptedOpenSsh])).toEqual([
      ["ed", "ed25519", "pkcs8", false],
      ["rsa", "rsa", "pem", false]
    ]);

    // Renaming keeps what was detected from the saved text.
    const renamed = await storage.upsertKey({ id: store.sshKeys[1]?.id, name: "rsa-renamed" });
    expect(renamed.sshKeys[1]).toMatchObject({ name: "rsa-renamed", keyType: "rsa", keyFormat: "pem" });
  });

  it("learns the type of an encrypted PKCS#8 key from its saved passphrase", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const encrypted = generateKeyPairSync("ed25519").privateKey.export({
      format: "pem",
      type: "pkcs8",
      cipher: "aes-256-cbc",
      passphrase: "hunter2"
    }).toString();

    let store = await storage.upsertKey({ name: "locked", privateKey: encrypted });
    expect(store.sshKeys[0]).toMatchObject({ keyType: "unknown", keyFormat: "pkcs8" });

    store = await storage.upsertKey({ id: store.sshKeys[0]?.id, name: "locked", privateKeyPassphrase: "hunter2" });
    expect(store.sshKeys[0]).toMatchObject({ keyType: "ed25519", keyFormat: "pkcs8" });
  });

  it("backfills key metadata for keys saved by an older build", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const store = await storage.upsertKey({ name: "old", privateKey: generatePrivateKeyPem() });
    const legacyStore = {
      ...store,
      // JSON drops undefined fields, which is how an older build wrote keys.
      sshKeys: store.sshKeys.map((key) => ({ ...key, keyType: undefined, keyFormat: undefined, encryptedOpenSsh: undefined }))
    };
    await writeFile(path.join(dir, "app-store.v1.json"), JSON.stringify(legacyStore), "utf8");

    const reopened = new AppStorage(dir);
    await reopened.init();

    expect(reopened.getStore().sshKeys[0]).toMatchObject({ keyType: "ed25519", keyFormat: "pkcs8", encryptedOpenSsh: false });
    const persisted = JSON.parse(await readFile(path.join(dir, "app-store.v1.json"), "utf8")) as ReturnType<typeof createDefaultStore>;
    expect(persisted.sshKeys[0]?.keyType).toBe("ed25519");
  });

  it("flags a security-key (FIDO) key saved before such keys were told apart, once", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    await storage.upsertKey({ name: "fido", privateKey: securityKeyText() });
    const store = await storage.upsertKey({ name: "plain", privateKey: SSH_KEY_FIXTURES.ecdsaP256Unencrypted.privateKey });
    expect(store.sshKeys.map((key) => key.securityKey)).toEqual([true, false]);
    // 2.6.1 recorded both as plain ECDSA keys, with no securityKey at all.
    const legacyStore = { ...store, sshKeys: store.sshKeys.map((key) => ({ ...key, securityKey: undefined })) };
    await writeFile(path.join(dir, "app-store.v1.json"), JSON.stringify(legacyStore), "utf8");

    const reopened = new AppStorage(dir);
    await reopened.init();

    expect(reopened.getStore().sshKeys.map((key) => [key.name, key.keyType, key.securityKey])).toEqual([
      ["fido", "ecdsa", true],
      ["plain", "ecdsa", false]
    ]);
    const persisted = JSON.parse(await readFile(path.join(dir, "app-store.v1.json"), "utf8")) as ReturnType<typeof createDefaultStore>;
    expect(persisted.sshKeys.map((key) => key.securityKey)).toEqual([true, false]);
    // A rename keeps what was found.
    const renamed = await reopened.upsertKey({ id: persisted.sshKeys[1]?.id, name: "plain-renamed" });
    expect(renamed.sshKeys[1]).toMatchObject({ name: "plain-renamed", securityKey: false });
  });

  it("records, and backfills once, an encrypted key the SSH core cannot open", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const store = await storage.upsertKey({
      name: "chacha",
      privateKey: SSH_KEY_FIXTURES.ed25519ChaCha20Poly1305.privateKey,
      privateKeyPassphrase: "pass123"
    });
    expect(store.sshKeys[0]).toMatchObject({
      encryptedOpenSsh: true,
      securityKey: false,
      unsupportedOpenSshCipher: "chacha20-poly1305@openssh.com"
    });
    // A rename keeps it.
    const renamed = await storage.upsertKey({ id: store.sshKeys[0]?.id, name: "chacha-renamed" });
    expect(renamed.sshKeys[0]?.unsupportedOpenSshCipher).toBe("chacha20-poly1305@openssh.com");
    // 2.6.1 saved the key with its passphrase and recorded nothing of this.
    const legacyStore = {
      ...renamed,
      sshKeys: renamed.sshKeys.map((key) => ({ ...key, securityKey: undefined, unsupportedOpenSshCipher: undefined }))
    };
    await writeFile(path.join(dir, "app-store.v1.json"), JSON.stringify(legacyStore), "utf8");

    const reopened = new AppStorage(dir);
    await reopened.init();

    expect(reopened.getStore().sshKeys[0]).toMatchObject({ securityKey: false, unsupportedOpenSshCipher: "chacha20-poly1305@openssh.com" });
  });

  it("returns every failed import line with its line number, up to 500", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const lines = [
      "vless://id@proxy.example.com:443?type=tcp&security=tls#good",
      ...Array.from({ length: 600 }, (_, index) => `not-a-link-${index}`)
    ];

    const { result } = await storage.importProxyProfiles({ text: lines.join("\n"), source: "clipboard" });

    expect(result.imported).toBe(1);
    expect(result.failed).toBe(600);
    expect(result.errors).toHaveLength(500);
    expect(result.errors[0]).toMatch(/^Line 2: /u);
    expect(result.errors[499]).toMatch(/^Line 501: /u);
  });

  it("checks a changed tunnel check endpoint and leaves a stored one alone", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const current = createDefaultStore();
    await writeFile(
      path.join(dir, "app-store.v1.json"),
      JSON.stringify({ ...current, settings: { ...current.settings, checkEndpoint: "https://youtube.com:443" } }),
      "utf8"
    );
    const storage = new AppStorage(dir);
    await storage.init();

    await expect(storage.updateSettings({ checkEndpoint: "https://example.com" })).rejects.toThrow(
      "Enter host:port without https:// or a path — for example youtube.com:443."
    );
    await expect(storage.updateSettings({ ...storage.getSettings(), sidebarCollapsed: true })).resolves.toMatchObject({
      settings: { sidebarCollapsed: true, checkEndpoint: "https://youtube.com:443" }
    });
    await expect(storage.updateSettings({ checkEndpoint: " db.example.org:5432 " })).resolves.toMatchObject({
      settings: { checkEndpoint: "db.example.org:5432" }
    });
  });

  it("refuses to select a profile Xray cannot run and never picks one automatically", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const { store } = await storage.importProxyProfiles({
      text: [
        "vless://id@quic.example.com:443?type=quic&security=tls#unsupported",
        "vless://id@ok.example.com:443?type=tcp&security=tls#supported"
      ].join("\n"),
      source: "clipboard"
    });
    const unsupported = store.proxyProfiles.find((profile) => profile.transport === "unknown");
    const supported = store.proxyProfiles.find((profile) => profile.transport === "tcp");

    expect(store.selectedProxyProfileId).toBe(supported?.id);
    await expect(storage.selectProxyProfile(unsupported?.id ?? "")).rejects.toThrow(UNSUPPORTED_PROXY_PROFILE_MESSAGE);
    expect(storage.getStore().selectedProxyProfileId).toBe(supported?.id);
  });

  it("remembers the last public list refresh even after its profiles are removed", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const { store } = await storage.importProxyProfiles({
      text: ["vless://id@a.example.com:443?type=tcp&security=tls#a", "vless://id@b.example.com:443?type=tcp&security=tls#b", "vless://id@b.example.com:443?type=tcp&security=tls#b"].join("\n"),
      source: "remote",
      sourceUrl: "https://lists.example.com/public.txt"
    });
    expect(store.publicProxyRefresh).toMatchObject({ listed: 2 });
    expect(Number.isFinite(Date.parse(store.publicProxyRefresh?.at ?? ""))).toBe(true);

    await storage.deleteUnpinnedProxyProfiles();
    const reopened = new AppStorage(dir);
    await reopened.init();
    expect(reopened.getStore().proxyProfiles).toEqual([]);
    expect(reopened.getStore().publicProxyRefresh).toEqual(store.publicProxyRefresh);

    await storage.importProxyProfiles({ text: "vless://id@c.example.com:443?type=tcp&security=tls#c", source: "clipboard" });
    expect(storage.getStore().publicProxyRefresh).toEqual(store.publicProxyRefresh);
  });
});

describe("AppStorage profiles Xray 26 can no longer run", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it("marks a saved HTTP/2 profile unsupported on load and moves the selection off it", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const first = new AppStorage(dir);
    await first.init();
    await first.importProxyProfiles({
      text: [
        "vless://11111111-1111-4111-8111-111111111111@h2.example.com:443?type=ws&security=tls#was-h2",
        "vless://11111111-1111-4111-8111-111111111111@ws.example.com:443?type=ws&security=tls#ws"
      ].join("\n"),
      source: "clipboard"
    });

    // An h2 profile as builds before Xray 26 saved it: transport "http", selected.
    const storePath = path.join(dir, "app-store.v1.json");
    const saved = JSON.parse(await readFile(storePath, "utf8")) as ReturnType<typeof createDefaultStore>;
    const h2 = saved.proxyProfiles.find((profile) => profile.name === "was-h2")!;
    saved.proxyProfiles = saved.proxyProfiles.map((profile) =>
      profile.id === h2.id ? { ...profile, transport: "http", isSelected: true } : { ...profile, isSelected: false }
    );
    saved.selectedProxyProfileId = h2.id;
    await writeFile(storePath, `${JSON.stringify(saved, null, 2)}\n`, "utf8");

    const reopened = new AppStorage(dir);
    await reopened.init();
    const store = reopened.getStore();
    expect(store.proxyProfiles.find((profile) => profile.id === h2.id)).toMatchObject({ transport: "unknown", isSelected: false });
    expect(store.proxyProfiles.find((profile) => profile.name === "ws")?.isSelected).toBe(true);
    await expect(reopened.selectProxyProfile(h2.id)).rejects.toThrow(UNSUPPORTED_PROXY_PROFILE_MESSAGE);
  });

  it("rewrites what earlier versions saved in forms that no longer work", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const first = new AppStorage(dir);
    await first.init();
    await first.importProxyProfiles({
      text: "vless://11111111-1111-4111-8111-111111111111@xn--e1afmkfd.xn--p1ai:443?type=ws&security=tls#idn",
      source: "clipboard"
    });
    const storePath = path.join(dir, "app-store.v1.json");
    const saved = JSON.parse(await readFile(storePath, "utf8")) as ReturnType<typeof createDefaultStore>;
    // An internationalised host as the parser used to store it, and an IP
    // rule with the zero-padded prefix the rules form used to accept.
    saved.proxyProfiles = saved.proxyProfiles.map((profile) => ({ ...profile, host: "%d0%bf%d1%80%d0%b8%d0%bc%d0%b5%d1%80.%d1%80%d1%84" }));
    saved.routingRules = [{ id: "r", type: "ip", value: "91.108.4.0/022", enabled: true, createdAt: "a", updatedAt: "a" }];
    await writeFile(storePath, `${JSON.stringify(saved, null, 2)}\n`, "utf8");

    const reopened = new AppStorage(dir);
    await reopened.init();
    const store = reopened.getStore();
    expect(store.proxyProfiles[0]?.host).toBe("xn--e1afmkfd.xn--p1ai");
    expect(store.routingRules[0]?.value).toBe("91.108.4.0/22");
  });

  it("relabels a trojan profile saved as plaintext when its link names no security, since it connects over TLS", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const first = new AppStorage(dir);
    await first.init();
    await first.importProxyProfiles({
      text: ["trojan://pw@gfw.example.com:443?sni=gfw.example.com#gfw", "trojan://pw@plain.example.com:80?security=none#plain"].join("\n"),
      source: "clipboard"
    });
    // As builds before the trojan-gfw fix saved both.
    const storePath = path.join(dir, "app-store.v1.json");
    const saved = JSON.parse(await readFile(storePath, "utf8")) as ReturnType<typeof createDefaultStore>;
    saved.proxyProfiles = saved.proxyProfiles.map((profile) => ({ ...profile, security: "none" }));
    await writeFile(storePath, `${JSON.stringify(saved, null, 2)}\n`, "utf8");

    const reopened = new AppStorage(dir);
    await reopened.init();
    const security = Object.fromEntries(reopened.getStore().proxyProfiles.map((profile) => [profile.name, profile.security]));
    expect(security).toEqual({ gfw: "tls", plain: "none" });
    // Written back, so the next start reads it as it is.
    const written = JSON.parse(await readFile(storePath, "utf8")) as ReturnType<typeof createDefaultStore>;
    expect(written.proxyProfiles.find((profile) => profile.name === "gfw")?.security).toBe("tls");
  });

  it("moves profiles from the former public list URL to the current one, so a refresh marks the gone ones stale", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const kept = "vless://11111111-1111-4111-8111-111111111111@kept.example.com:443?type=ws&security=tls#kept";
    const gone = "vless://11111111-1111-4111-8111-111111111111@gone.example.com:443?type=ws&security=tls#gone";
    const first = new AppStorage(dir);
    await first.init();
    await first.importProxyProfiles({ text: [kept, gone].join("\n"), source: "remote", sourceUrl: LEGACY_PUBLIC_PROXY_LIST_URLS[0] });

    const reopened = new AppStorage(dir);
    await reopened.init();
    expect(reopened.getStore().proxyProfiles.map((profile) => profile.sourceUrl)).toEqual([PUBLIC_PROXY_LIST_URL, PUBLIC_PROXY_LIST_URL]);

    const { store } = await reopened.importProxyProfiles({ text: kept, source: "remote", sourceUrl: PUBLIC_PROXY_LIST_URL });
    expect(store.proxyProfiles.find((profile) => profile.name === "kept")?.isStale).toBe(false);
    expect(store.proxyProfiles.find((profile) => profile.name === "gone")?.isStale).toBe(true);
  });
});

describe("AppStorage Hysteria 2 profiles", () => {
  const cleanupDirs: string[] = [];
  const HOP_LINK = "hysteria2://pw@example.com:443,20000-30000/?sni=real.example.com#hop";

  afterEach(async () => {
    await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it("treats hy2:// and hysteria2:// spellings of one link as one profile and picks it automatically", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();

    const first = await storage.importProxyProfiles({ text: "hy2://pw@example.com?sni=a#Helsinki", source: "clipboard" });
    const second = await storage.importProxyProfiles({ text: "hysteria2://pw@example.com:443/?sni=a#Helsinki", source: "clipboard" });

    expect(first.result).toMatchObject({ imported: 1, updated: 0, failed: 0 });
    expect(second.result).toMatchObject({ imported: 0, updated: 1, failed: 0 });
    expect(second.store.proxyProfiles).toHaveLength(1);
    const [profile] = second.store.proxyProfiles;
    expect(profile).toMatchObject({
      name: "Helsinki",
      protocol: "hysteria2",
      host: "example.com",
      port: 443,
      transport: "hysteria",
      security: "tls",
      flow: "",
      isSelected: true
    });
    expect(profile?.id).toBe(first.store.proxyProfiles[0]?.id);
    expect(profile).not.toHaveProperty("hopPorts");
    expect(second.store.selectedProxyProfileId).toBe(profile?.id);
    expect(storage.resolveProxySecrets(profile!).rawUri).toBe("hysteria2://pw@example.com:443/?sni=a#Helsinki");
  });

  it("keeps user:password links that differ only by password as two profiles", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();

    const { store, result } = await storage.importProxyProfiles({
      text: ["hy2://user:one@example.com#shared", "hy2://user:two@example.com#shared"].join("\n"),
      source: "clipboard"
    });

    expect(result).toMatchObject({ imported: 2, updated: 0 });
    expect(new Set(store.proxyProfiles.map((profile) => profile.fingerprint)).size).toBe(2);
  });

  it("stores the hop list and keeps it across a restart", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();

    const { store } = await storage.importProxyProfiles({ text: HOP_LINK, source: "clipboard" });
    expect(store.proxyProfiles[0]).toMatchObject({ port: 443, hopPorts: "443,20000-30000" });

    const reopened = new AppStorage(dir);
    await reopened.init();
    expect(reopened.getStore().proxyProfiles[0]).toMatchObject({ port: 443, hopPorts: "443,20000-30000", isSelected: true });
    const persisted = JSON.parse(await readFile(path.join(dir, "app-store.v1.json"), "utf8")) as ReturnType<typeof createDefaultStore>;
    expect(persisted.proxyProfiles[0]?.hopPorts).toBe("443,20000-30000");
  });

  it("drops a stored hop list when the profile's new link has none", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const created = await storage.upsertProxyProfile({ name: "", rawUri: HOP_LINK });
    const id = created.proxyProfiles[0]?.id ?? "";
    expect(created.proxyProfiles[0]?.hopPorts).toBe("443,20000-30000");

    const edited = await storage.upsertProxyProfile({ id, name: "", rawUri: "hy2://pw@example.com:8443?sni=real.example.com#plain" });

    expect(edited.proxyProfiles).toHaveLength(1);
    expect(edited.proxyProfiles[0]).toMatchObject({ id, port: 8443 });
    expect(edited.proxyProfiles[0]).not.toHaveProperty("hopPorts");
    const persistedText = await readFile(path.join(dir, "app-store.v1.json"), "utf8");
    expect(persistedText).not.toContain("hopPorts");
    const reopened = new AppStorage(dir);
    await reopened.init();
    expect(reopened.getStore().proxyProfiles[0]).not.toHaveProperty("hopPorts");
  });

  it("does not carry a stale hop list over when a link is imported again", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const link = "hy2://pw@example.com?sni=real.example.com#plain";
    const first = new AppStorage(dir);
    await first.init();
    await first.importProxyProfiles({ text: link, source: "clipboard" });
    // A store whose profile kept a hop list its link no longer has.
    const storePath = path.join(dir, "app-store.v1.json");
    const persisted = JSON.parse(await readFile(storePath, "utf8")) as ReturnType<typeof createDefaultStore>;
    persisted.proxyProfiles[0] = { ...persisted.proxyProfiles[0]!, hopPorts: "443,20000-30000" };
    await writeFile(storePath, JSON.stringify(persisted), "utf8");
    const storage = new AppStorage(dir);
    await storage.init();
    expect(storage.getStore().proxyProfiles[0]?.hopPorts).toBe("443,20000-30000");

    const { store, result } = await storage.importProxyProfiles({ text: link, source: "clipboard" });

    expect(result).toMatchObject({ imported: 0, updated: 1 });
    expect(store.proxyProfiles[0]).not.toHaveProperty("hopPorts");
  });

  it("imports an insecure=1 link without a pin and lets it be selected", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const { store, result } = await storage.importProxyProfiles({
      text: ["vless://id@ok.example.com:443?type=tcp&security=tls#first", "hy2://pw@example.com?insecure=1#self-signed"].join("\n"),
      source: "clipboard"
    });
    const hysteria = store.proxyProfiles.find((profile) => profile.protocol === "hysteria2");

    expect(result).toMatchObject({ imported: 2, failed: 0 });
    expect(hysteria).toMatchObject({ name: "self-signed", transport: "hysteria", security: "tls" });
    await expect(storage.selectProxyProfile(hysteria?.id ?? "")).resolves.toMatchObject({ selectedProxyProfileId: hysteria?.id });
  });

  it("marks an insecure=1 link without a pin, from Import links and the public list, and keeps the mark across a restart", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();

    const { store } = await storage.importProxyProfiles({
      text: ["hy2://pw@a.example.com?insecure=1#self-signed", `hy2://pw@b.example.com?insecure=1&pinSHA256=${"ab".repeat(32)}#pinned`, "vless://id@c.example.com:443?type=tcp&security=tls&allowInsecure=1#vless"].join("\n"),
      source: "clipboard"
    });
    const byName = (profiles: readonly { name: string }[], name: string) => profiles.find((profile) => profile.name === name);
    expect(byName(store.proxyProfiles, "self-signed")).toMatchObject({ insecureWithoutPin: true });
    expect(byName(store.proxyProfiles, "pinned")).not.toHaveProperty("insecureWithoutPin");
    expect(byName(store.proxyProfiles, "vless")).not.toHaveProperty("insecureWithoutPin");

    const refreshed = await storage.importProxyProfiles({
      text: "hysteria2://pw@d.example.com?allowInsecure=1#public-hy2",
      source: "remote",
      sourceUrl: "https://example.com/list.txt"
    });
    expect(byName(refreshed.store.proxyProfiles, "public-hy2")).toMatchObject({ source: "remote", insecureWithoutPin: true });

    const persisted = JSON.parse(await readFile(path.join(dir, "app-store.v1.json"), "utf8")) as ReturnType<typeof createDefaultStore>;
    expect(persisted.proxyProfiles.filter((profile) => profile.insecureWithoutPin).map((profile) => profile.name)).toEqual(["self-signed", "public-hy2"]);
    // Only `true` is written: the other profiles have no key at all.
    expect(persisted.proxyProfiles.filter((profile) => "insecureWithoutPin" in profile)).toHaveLength(2);
    const reopened = new AppStorage(dir);
    await reopened.init();
    expect(byName(reopened.getStore().proxyProfiles, "self-signed")).toMatchObject({ insecureWithoutPin: true });
    expect(byName(reopened.getStore().proxyProfiles, "public-hy2")).toMatchObject({ insecureWithoutPin: true });
  });

  it("drops the mark when the profile is saved again with a pinned link", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const created = await storage.upsertProxyProfile({ name: "", rawUri: "hy2://pw@example.com?insecure=1#self-signed" });
    const id = created.proxyProfiles[0]?.id ?? "";
    expect(created.proxyProfiles[0]).toMatchObject({ insecureWithoutPin: true });

    const edited = await storage.upsertProxyProfile({ id, name: "", rawUri: `hy2://pw@example.com?insecure=1&pinSHA256=${"ab".repeat(32)}#self-signed` });

    expect(edited.proxyProfiles).toHaveLength(1);
    expect(edited.proxyProfiles[0]).toMatchObject({ id, name: "self-signed" });
    expect(edited.proxyProfiles[0]).not.toHaveProperty("insecureWithoutPin");
    expect(await readFile(path.join(dir, "app-store.v1.json"), "utf8")).not.toContain("insecureWithoutPin");
    const reopened = new AppStorage(dir);
    await reopened.init();
    expect(reopened.getStore().proxyProfiles[0]).not.toHaveProperty("insecureWithoutPin");
  });

  it("does not carry a stale mark over when a link is imported again, and adds a missing one", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const plain = "hy2://pw@a.example.com?sni=real.example.com#plain";
    const insecure = "hy2://pw@b.example.com?insecure=1#self-signed";
    const first = new AppStorage(dir);
    await first.init();
    await first.importProxyProfiles({ text: [plain, insecure].join("\n"), source: "clipboard" });
    // A store whose marks disagree with the links: one stale, one missing.
    const storePath = path.join(dir, "app-store.v1.json");
    const persisted = JSON.parse(await readFile(storePath, "utf8")) as ReturnType<typeof createDefaultStore>;
    persisted.proxyProfiles = persisted.proxyProfiles.map((profile) => {
      if (profile.name === "plain") {
        return { ...profile, insecureWithoutPin: true };
      }
      const rest = { ...profile };
      delete rest.insecureWithoutPin;
      return rest;
    });
    await writeFile(storePath, JSON.stringify(persisted), "utf8");
    const storage = new AppStorage(dir);
    await storage.init();

    const { store, result } = await storage.importProxyProfiles({ text: [plain, insecure].join("\n"), source: "clipboard" });

    expect(result).toMatchObject({ imported: 0, updated: 2 });
    expect(store.proxyProfiles.find((profile) => profile.name === "plain")).not.toHaveProperty("insecureWithoutPin");
    expect(store.proxyProfiles.find((profile) => profile.name === "self-signed")).toMatchObject({ insecureWithoutPin: true });
  });
});

describe("AppStorage proxy profile rename", () => {
  const cleanupDirs: string[] = [];
  const NAMED = "vless://11111111-1111-4111-8111-111111111111@named.example.com:443?type=tcp&security=tls#Amsterdam";
  const UNNAMED = "vless://11111111-1111-4111-8111-111111111111@unnamed.example.com:443?type=tcp&security=tls";

  afterEach(async () => {
    await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  async function storageWith(text: string, sourceUrl?: string) {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const { store } = await storage.importProxyProfiles(sourceUrl ? { text, source: "remote", sourceUrl } : { text, source: "clipboard" });
    return { dir, storage, profiles: store.proxyProfiles };
  }

  it("saves one trimmed line of at most 64 characters and leaves the link, selection and pin alone", async () => {
    const { dir, storage, profiles: [before] } = await storageWith(NAMED);

    const store = await storage.renameProxyProfile(before!.id, "  Home\tserver\n#1\u0085 a\u0000b  ");
    const renamed = store.proxyProfiles[0]!;
    expect(renamed).toEqual({ ...before, name: "Home server #1  a b", updatedAt: renamed.updatedAt });
    expect(Date.parse(renamed.updatedAt)).toBeGreaterThanOrEqual(Date.parse(before!.updatedAt));
    expect(storage.resolveProxySecrets(renamed).rawUri).toBe(NAMED);

    const emoji = await storage.renameProxyProfile(before!.id, "😀".repeat(70));
    expect(emoji.proxyProfiles[0]?.name).toBe("😀".repeat(64));
    const cut = await storage.renameProxyProfile(before!.id, `${"x".repeat(63)} yz`);
    expect(cut.proxyProfiles[0]?.name).toBe("x".repeat(63));

    const reopened = new AppStorage(dir);
    await reopened.init();
    expect(reopened.getStore().proxyProfiles[0]?.name).toBe("x".repeat(63));
  });

  it("brings back the link's own name, or protocol-host:port, for a blank name", async () => {
    const { storage, profiles } = await storageWith([NAMED, UNNAMED].join("\n"));
    const [named, unnamed] = profiles;
    await storage.renameProxyProfile(named!.id, "Custom");
    await storage.renameProxyProfile(unnamed!.id, "Custom");

    await storage.renameProxyProfile(named!.id, "   ");
    const store = await storage.renameProxyProfile(unnamed!.id, "\n\t");

    expect(store.proxyProfiles.map((profile) => profile.name)).toEqual(["Amsterdam", "vless-unnamed.example.com:443"]);
  });

  it("does not write the store when the name stays the same", async () => {
    const { dir, storage, profiles: [profile] } = await storageWith(NAMED);
    await storage.renameProxyProfile(profile!.id, "Custom");
    const storePath = path.join(dir, "app-store.v1.json");
    const before = await stat(storePath);

    const store = await storage.renameProxyProfile(profile!.id, " Custom ");
    const after = await stat(storePath);

    expect(store.proxyProfiles[0]?.name).toBe("Custom");
    expect(after.ino).toBe(before.ino);
    expect(after.mtimeMs).toBe(before.mtimeMs);
  });

  it("refuses a profile that does not exist and a name that is not text", async () => {
    const { storage, profiles: [profile] } = await storageWith(NAMED);

    await expect(storage.renameProxyProfile("missing", "Custom")).rejects.toThrow("Proxy profile does not exist.");
    await expect(storage.renameProxyProfile(profile!.id, 42 as unknown as string)).rejects.toThrow("Proxy profile name is invalid.");
    expect(() => storage.readProxyProfileShareLink("missing")).toThrow("Proxy profile does not exist.");
  });

  it("keeps the new name when its public list is refreshed with the same link", async () => {
    const sourceUrl = "https://lists.example.com/public.txt";
    const { storage, profiles: [profile] } = await storageWith(NAMED, sourceUrl);
    await storage.renameProxyProfile(profile!.id, "My server");

    const { store, result } = await storage.importProxyProfiles({ text: NAMED, source: "remote", sourceUrl });

    expect(result).toMatchObject({ imported: 0, updated: 1 });
    expect(store.proxyProfiles).toHaveLength(1);
    expect(store.proxyProfiles[0]).toMatchObject({ id: profile!.id, name: "My server", isStale: false, fingerprint: profile!.fingerprint });
  });

  it("copies the saved link with the profile's current name written in", async () => {
    const { storage, profiles: [profile] } = await storageWith(NAMED);
    expect(storage.readProxyProfileShareLink(profile!.id)).toBe(NAMED);

    await storage.renameProxyProfile(profile!.id, "Home server");

    expect(storage.readProxyProfileShareLink(profile!.id)).toBe(NAMED.replace("#Amsterdam", "#Home%20server"));
    expect(storage.resolveProxySecrets(storage.getStore().proxyProfiles[0]!).rawUri).toBe(NAMED);
  });

  it("brings back a long or multi-line link name as import saved it, so Copy link returns the saved link", async () => {
    const longName = "🇳🇱 Amsterdam | 1 Gbps | Netflix, YouTube, ChatGPT | t.me/SomeChannel-2026 #12";
    const long = `vless://11111111-1111-4111-8111-111111111111@long.example.com:443?type=tcp&security=tls#${encodeURIComponent(longName)}`;
    const lines = "vless://11111111-1111-4111-8111-111111111111@lines.example.com:443?type=tcp&security=tls#Line%0Atwo%09three";
    const { storage, profiles } = await storageWith([long, lines].join("\n"));
    expect(profiles.map((profile) => profile.name)).toEqual([longName, "Line\ntwo\tthree"]);

    for (const [index, profile] of profiles.entries()) {
      await storage.renameProxyProfile(profile.id, "Mine");
      const store = await storage.renameProxyProfile(profile.id, "");

      expect(store.proxyProfiles[index]?.name).toBe(profile.name);
      expect(storage.readProxyProfileShareLink(profile.id)).toBe([long, lines][index]);
    }
  });

  it("falls back to protocol-host:port for a blank name when the saved link can't be read", async () => {
    const { dir, storage, profiles: [profile] } = await storageWith(NAMED);
    await storage.renameProxyProfile(profile!.id, "Custom");
    // The development secret key is bound to the folder, as after an app folder move.
    const moved = await makeTempDir(cleanupDirs);
    for (const file of ["app-store.v1.json", "secret-store.v1.json"]) {
      await copyFile(path.join(dir, file), path.join(moved, file));
    }
    const reopened = new AppStorage(moved);
    await reopened.init();
    expect(() => reopened.readProxyProfileShareLink(profile!.id)).toThrow();

    const store = await reopened.renameProxyProfile(profile!.id, "");

    expect(store.proxyProfiles[0]?.name).toBe("vless-named.example.com:443");
  });

  it("writes the name into a vmess link's ps through the saved secret", async () => {
    const payload = { v: "2", ps: "Tokyo", add: "vmess.example.com", port: "443", id: "11111111-1111-4111-8111-111111111111", aid: "0", net: "ws", type: "none", path: "/ws", tls: "tls" };
    const link = `vmess://${Buffer.from(JSON.stringify(payload), "utf8").toString("base64")}`;
    const { storage, profiles: [profile] } = await storageWith(link);

    await storage.renameProxyProfile(profile!.id, "Home server");
    const copied = storage.readProxyProfileShareLink(profile!.id);

    expect(JSON.parse(Buffer.from(copied.slice("vmess://".length), "base64").toString("utf8"))).toEqual({ ...payload, ps: "Home server" });
    expect(storage.resolveProxySecrets(storage.getStore().proxyProfiles[0]!).rawUri).toBe(link);
  });

  it("copies the saved link as it is when the new name can't be written into it", async () => {
    // At the 64 KiB link limit, a longer name would make the link unreadable.
    const head = "vless://11111111-1111-4111-8111-111111111111@big.example.com:443?type=tcp&security=tls&padding=";
    const big = `${head}${"a".repeat(64 * 1024 - head.length - 2)}#a`;
    const { storage, profiles: [profile] } = await storageWith(big);

    await storage.renameProxyProfile(profile!.id, "Home server");

    expect(storage.getStore().proxyProfiles[0]?.name).toBe("Home server");
    expect(storage.readProxyProfileShareLink(profile!.id)).toBe(big);
  });
});

describe("AppStorage durable writes", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  type WriterSeam = { writeAtomic: (filePath: string, serialized: string) => Promise<void> };
  /** Makes the next `count` writes of one file fail, as a full disk or a locked file would. */
  function failWrites(storage: InstanceType<typeof AppStorage>, file: "storeWriter" | "secretsWriter", count = Number.POSITIVE_INFINITY): void {
    const writer = (storage as unknown as Record<string, WriterSeam>)[file]!;
    const original = writer.writeAtomic;
    let failures = 0;
    writer.writeAtomic = async (filePath, serialized) => {
      if (failures < count) {
        failures += 1;
        throw Object.assign(new Error("ENOSPC: no space left on device"), { code: "ENOSPC" });
      }
      await original(filePath, serialized);
    };
  }

  async function readStoreFile(dir: string): Promise<ReturnType<typeof createDefaultStore>> {
    return JSON.parse(await readFile(path.join(dir, "app-store.v1.json"), "utf8")) as ReturnType<typeof createDefaultStore>;
  }

  it("keeps no change in memory whose save failed", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    failWrites(storage, "storeWriter");

    await expect(storage.updateSettings({ theme: "dark" })).rejects.toThrow("no space left");
    await expect(storage.updateRoutingMode("selected-rules")).rejects.toThrow("no space left");
    await expect(
      storage.updateRoutingRules([{ id: "r", type: "domain", value: "example.com", enabled: true, createdAt: "a", updatedAt: "a" }])
    ).rejects.toThrow("no space left");

    const store = storage.getStore();
    expect(store.settings.theme).toBe("system");
    expect(store.routingMode).toBe("proxy-all");
    expect(store.routingRules).toEqual([]);
    expect(await readStoreFile(dir)).toEqual(store);
  });

  it("runs changes one at a time, so a failed save never takes another change with it", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    failWrites(storage, "storeWriter", 1);

    const [first, second] = await Promise.allSettled([
      storage.updateSettings({ theme: "dark" }),
      storage.updateSettings({ sidebarCollapsed: true })
    ]);

    expect(first.status).toBe("rejected");
    expect(second.status).toBe("fulfilled");
    const settings = storage.getSettings();
    expect(settings.theme).toBe("system");
    expect(settings.sidebarCollapsed).toBe(true);
    expect((await readStoreFile(dir)).settings).toEqual(settings);
  });

  it("saves imported links before any profile that needs them appears", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    failWrites(storage, "secretsWriter", 1);

    await expect(
      storage.importProxyProfiles({ text: "vless://id@proxy.example.com:443?type=tcp&security=tls#a", source: "clipboard" })
    ).rejects.toThrow("no space left");
    expect(storage.getStore().proxyProfiles).toEqual([]);
    expect(Object.keys((storage as unknown as { secrets: { secrets: Record<string, unknown> } }).secrets.secrets)).toEqual([]);

    const { store } = await storage.importProxyProfiles({ text: "vless://id@proxy.example.com:443?type=tcp&security=tls#a", source: "clipboard" });
    expect(store.proxyProfiles).toHaveLength(1);
    expect(storage.resolveProxySecrets(store.proxyProfiles[0]!).rawUri).toContain("proxy.example.com");
  });

  it("takes a key or password saved over its record back with a store write that failed", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const original = generatePrivateKeyPem().trim();
    const withKey = await storage.upsertKey({ name: "work", privateKey: original });
    const key = withKey.sshKeys[0]!;
    const withServer = await storage.upsertConfig({
      name: "srv",
      host: "old.example.com",
      port: 22,
      username: "root",
      authType: "password",
      password: "old-pass",
      expectedServerFingerprint: "",
      keepaliveIntervalSec: 120,
      note: ""
    });
    const server = withServer.sshConfigs[0]!;

    // The secrets file takes the new key; the store, with its fingerprint and
    // type, does not.
    failWrites(storage, "storeWriter", 1);
    await expect(storage.upsertKey({ id: key.id, name: "work", privateKey: SSH_KEY_FIXTURES.rsa.privateKey })).rejects.toThrow("no space left");
    expect(storage.getStore().sshKeys[0]).toMatchObject({ fingerprint: key.fingerprint, keyType: key.keyType });
    expect(storage.readPrivateKeyText(key.id)).toBe(original);

    failWrites(storage, "storeWriter", 1);
    await expect(storage.upsertConfig({ ...server, host: "new.example.com", password: "new-pass" })).rejects.toThrow("no space left");
    expect(storage.getStore().sshConfigs[0]?.host).toBe("old.example.com");
    expect(storage.resolveServiceSecrets(storage.getStore().sshConfigs[0]!).password).toBe("old-pass");

    // And the files agree after a restart.
    const reopened = new AppStorage(dir);
    await reopened.init();
    expect(reopened.readPrivateKeyText(key.id)).toBe(original);
    expect(reopened.getStore().sshKeys[0]?.fingerprint).toBe(key.fingerprint);
    expect(reopened.resolveServiceSecrets(reopened.getStore().sshConfigs[0]!).password).toBe("old-pass");
  });

  it("writes the secrets file back on the next save when putting it back failed too", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const original = generatePrivateKeyPem().trim();
    const key = (await storage.upsertKey({ name: "work", privateKey: original })).sshKeys[0]!;

    // The new key reaches the secrets file, the store write fails, and so
    // does the write that should have put the old key back.
    failWrites(storage, "storeWriter", 1);
    const secretsWriter = (storage as unknown as Record<string, WriterSeam>).secretsWriter!;
    const writeAtomic = secretsWriter.writeAtomic;
    let secretWrites = 0;
    secretsWriter.writeAtomic = async (filePath, serialized) => {
      secretWrites += 1;
      if (secretWrites === 2) {
        throw Object.assign(new Error("EBUSY: resource busy or locked"), { code: "EBUSY" });
      }
      await writeAtomic(filePath, serialized);
    };
    await expect(storage.upsertKey({ id: key.id, name: "work", privateKey: SSH_KEY_FIXTURES.rsa.privateKey })).rejects.toThrow("no space left");
    expect(storage.readPrivateKeyText(key.id)).toBe(original);

    // A save that touches only the store still puts the secrets file right.
    await storage.updateSettings({ theme: "dark" });

    const reopened = new AppStorage(dir);
    await reopened.init();
    expect(reopened.readPrivateKeyText(key.id)).toBe(original);
    expect(reopened.getStore().sshKeys[0]).toMatchObject({ fingerprint: key.fingerprint, keyType: key.keyType });
    expect(reopened.getSettings().theme).toBe("dark");
  });

  it("puts a deleted server back when its deletion could not be saved", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const created = await storage.upsertConfig({
      name: "server",
      host: "ssh.example.com",
      port: 22,
      username: "root",
      authType: "password",
      password: "secret",
      expectedServerFingerprint: "",
      keepaliveIntervalSec: 120,
      note: ""
    });
    failWrites(storage, "storeWriter", 1);

    await expect(storage.deleteConfig(created.sshConfigs[0]!.id)).rejects.toThrow("no space left");

    expect(storage.getStore().sshConfigs).toEqual(created.sshConfigs);
    expect(storage.getStore().selectedConfigId).toBe(created.selectedConfigId);
  });

  it("refuses a server that names a key that no longer exists, and an unknown routing mode", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();

    await expect(
      storage.upsertConfig({
        name: "server",
        host: "ssh.example.com",
        port: 22,
        username: "root",
        authType: "private-key",
        privateKeyId: "deleted-key",
        expectedServerFingerprint: "",
        keepaliveIntervalSec: 120,
        note: ""
      })
    ).rejects.toThrow("The selected SSH key no longer exists.");
    await expect(storage.updateRoutingMode("bogus" as never)).rejects.toThrow("Routing mode is invalid.");
    expect(storage.getStore().sshConfigs).toEqual([]);
  });

  it("keeps the list switch a refresh did not ask to change, and the domains a switch did not touch", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const list = createDefaultStore().routingProxyList;

    await storage.updateRoutingProxyList({ ...list, enabled: true, domains: ["a.example"] });
    await storage.setRoutingProxyListEnabled(false);
    // A refresh that started before the switch finishes now: its domains land, the switch stays off.
    await storage.updateRoutingProxyList({ sourceUrl: list.sourceUrl, domains: ["a.example", "b.example"], updatedAt: "2026-10-01T00:00:00.000Z" });

    expect(storage.getStore().routingProxyList).toMatchObject({ enabled: false, domains: ["a.example", "b.example"] });
    await storage.setRoutingProxyListEnabled(true);
    expect(storage.getStore().routingProxyList).toMatchObject({ enabled: true, domains: ["a.example", "b.example"] });

    await storage.updateRoutingDirectList({ ...createDefaultStore().routingDirectList, domains: ["c.example"] });
    await storage.setRoutingDirectListEnabled(true);
    await storage.updateRoutingDirectList({ sourceUrl: createDefaultStore().routingDirectList.sourceUrl, domains: ["d.example"] });
    expect(storage.getStore().routingDirectList).toMatchObject({ enabled: true, domains: ["d.example"] });
  });

  it("retries a rename Windows refuses while a scanner holds the file", async () => {
    const attempts: string[] = [];
    const sleeps: number[] = [];
    const busy = (code: string) => Object.assign(new Error(code), { code });
    const rename = async (): Promise<void> => {
      attempts.push("rename");
      if (attempts.length <= 2) {
        throw busy(attempts.length === 1 ? "EPERM" : "EBUSY");
      }
    };

    await renameWithRetry("a.tmp", "a.json", { platform: "win32", rename, sleep: async (ms) => void sleeps.push(ms) });

    expect(attempts).toHaveLength(3);
    expect(sleeps).toEqual([10, 25]);
  });

  it("gives up after the last retry, and never retries other errors or other systems", async () => {
    const failing = (code: string) => async (): Promise<void> => {
      throw Object.assign(new Error(code), { code });
    };
    const sleep = async (): Promise<void> => undefined;

    await expect(renameWithRetry("a", "b", { platform: "win32", rename: failing("EACCES"), sleep, delaysMs: [1, 1] })).rejects.toThrow("EACCES");
    const once = vi.fn(failing("ENOENT"));
    await expect(renameWithRetry("a", "b", { platform: "win32", rename: once, sleep })).rejects.toThrow("ENOENT");
    expect(once).toHaveBeenCalledTimes(1);
    const posix = vi.fn(failing("EPERM"));
    await expect(renameWithRetry("a", "b", { platform: "linux", rename: posix, sleep })).rejects.toThrow("EPERM");
    expect(posix).toHaveBeenCalledTimes(1);
  });

  it("writes the file through to disk and leaves no temp file", async () => {
    const dir = await makeTempDir(cleanupDirs);
    const filePath = path.join(dir, "nested", "store.json");

    await writeJsonAtomic(filePath, { durable: true });

    expect(JSON.parse(await readFile(filePath, "utf8"))).toEqual({ durable: true });
    expect((await readdir(path.dirname(filePath))).filter((name) => name.endsWith(".tmp"))).toEqual([]);
  });
});

describe("AppStorage SSH host key trust on first use", () => {
  const cleanupDirs: string[] = [];
  const KEY_A = `SHA256:${"A".repeat(43)}`;
  const KEY_B = `SHA256:${"B".repeat(43)}`;

  afterEach(async () => {
    await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  async function storageWithServer(fingerprint = ""): Promise<{
    storage: InstanceType<typeof AppStorage>;
    dir: string;
    id: string;
  }> {
    const dir = await makeTempDir(cleanupDirs);
    const storage = new AppStorage(dir);
    await storage.init();
    const store = await storage.upsertConfig(serverInput({ expectedServerFingerprint: fingerprint }));
    const id = store.sshConfigs[0]?.id ?? "";
    return { storage, dir, id };
  }

  function serverInput(overrides: Partial<Parameters<InstanceType<typeof AppStorage>["upsertConfig"]>[0]> = {}): Parameters<InstanceType<typeof AppStorage>["upsertConfig"]>[0] {
    return {
      name: "server",
      host: "ssh.example.com",
      port: 22,
      username: "root",
      authType: "password",
      password: "secret",
      expectedServerFingerprint: "",
      keepaliveIntervalSec: 120,
      note: "",
      ...overrides
    };
  }

  it("saves the first key of an unpinned server, once, and keeps it on disk", async () => {
    const { storage, dir, id } = await storageWithServer();

    await expect(storage.trustHostKeyOnFirstUse({ configId: id, host: "SSH.example.com", port: 22, fingerprint: KEY_A })).resolves.toBe(true);
    // Only the user replaces a trusted key.
    await expect(storage.trustHostKeyOnFirstUse({ configId: id, host: "ssh.example.com", port: 22, fingerprint: KEY_B })).resolves.toBe(false);

    const config = storage.getStore().sshConfigs[0];
    expect(config?.trustedHostKeyFingerprint).toBe(KEY_A);
    expect(Number.isFinite(Date.parse(config?.trustedHostKeyAt ?? ""))).toBe(true);
    const reopened = new AppStorage(dir);
    await reopened.init();
    expect(reopened.getStore().sshConfigs[0]?.trustedHostKeyFingerprint).toBe(KEY_A);
  });

  it("saves the key's type with it, keeps it through an edit, and drops one it cannot read", async () => {
    const { storage, dir, id } = await storageWithServer();
    await storage.trustHostKeyOnFirstUse({ configId: id, host: "ssh.example.com", port: 22, fingerprint: KEY_A, keyType: "ssh-ed25519" });
    expect(storage.getStore().sshConfigs[0]).toMatchObject({ trustedHostKeyFingerprint: KEY_A, trustedHostKeyType: "ssh-ed25519" });

    const store = await storage.upsertConfig(serverInput({ id, name: "renamed" }));
    expect(store.sshConfigs[0]).toMatchObject({ trustedHostKeyFingerprint: KEY_A, trustedHostKeyType: "ssh-ed25519" });

    const storePath = path.join(dir, "app-store.v1.json");
    const saved = JSON.parse(await readFile(storePath, "utf8")) as ReturnType<typeof createDefaultStore>;
    saved.sshConfigs = saved.sshConfigs.map((config) => ({ ...config, trustedHostKeyType: "ecdsa-sha2-nistp256" }));
    await writeFile(storePath, `${JSON.stringify(saved, null, 2)}\n`, "utf8");
    const reopened = new AppStorage(dir);
    await reopened.init();
    const config = reopened.getStore().sshConfigs[0];
    expect(config?.trustedHostKeyFingerprint).toBe(KEY_A);
    expect(config).not.toHaveProperty("trustedHostKeyType");

    // A type that is not one the client verifies is not saved at all.
    const other = await storageWithServer();
    await other.storage.trustHostKeyOnFirstUse({ configId: other.id, host: "ssh.example.com", port: 22, fingerprint: KEY_A, keyType: "x" });
    expect(other.storage.getStore().sshConfigs[0]).not.toHaveProperty("trustedHostKeyType");
  });

  it("saves nothing for a pinned server, another address, or something that is not a fingerprint", async () => {
    const pinned = await storageWithServer(KEY_B);
    await expect(pinned.storage.trustHostKeyOnFirstUse({ configId: pinned.id, host: "ssh.example.com", port: 22, fingerprint: KEY_A })).resolves.toBe(false);

    const { storage, id } = await storageWithServer();
    // The session ran against the address the server had before an edit.
    await expect(storage.trustHostKeyOnFirstUse({ configId: id, host: "old.example.com", port: 22, fingerprint: KEY_A })).resolves.toBe(false);
    await expect(storage.trustHostKeyOnFirstUse({ configId: id, host: "ssh.example.com", port: 2222, fingerprint: KEY_A })).resolves.toBe(false);
    await expect(storage.trustHostKeyOnFirstUse({ configId: id, host: "ssh.example.com", port: 22, fingerprint: "not-a-fingerprint" })).resolves.toBe(false);
    await expect(storage.trustHostKeyOnFirstUse({ configId: "missing", host: "ssh.example.com", port: 22, fingerprint: KEY_A })).resolves.toBe(false);
    expect(storage.getStore().sshConfigs[0]?.trustedHostKeyFingerprint).toBeUndefined();
  });

  it("keeps the trusted key through an edit that leaves the address and the pin alone", async () => {
    const { storage, id } = await storageWithServer();
    await storage.trustHostKeyOnFirstUse({ configId: id, host: "ssh.example.com", port: 22, fingerprint: KEY_A });

    const store = await storage.upsertConfig(serverInput({ id, name: "renamed", note: "moved racks", host: "SSH.EXAMPLE.COM " }));
    expect(store.sshConfigs[0]).toMatchObject({ name: "renamed", trustedHostKeyFingerprint: KEY_A });
  });

  it("forgets the trusted key when the host or the port changes", async () => {
    for (const change of [{ host: "other.example.com" }, { port: 2222 }]) {
      const { storage, id } = await storageWithServer();
      await storage.trustHostKeyOnFirstUse({ configId: id, host: "ssh.example.com", port: 22, fingerprint: KEY_A });
      const store = await storage.upsertConfig(serverInput({ id, ...change }));
      expect(store.sshConfigs[0]?.trustedHostKeyFingerprint, JSON.stringify(change)).toBeUndefined();
      expect(store.sshConfigs[0]?.trustedHostKeyAt).toBeUndefined();
    }
  });

  it("forgets the trusted key when a fingerprint is pinned, and does not bring it back when the pin is cleared", async () => {
    const { storage, id } = await storageWithServer();
    await storage.trustHostKeyOnFirstUse({ configId: id, host: "ssh.example.com", port: 22, fingerprint: KEY_A });

    let store = await storage.upsertConfig(serverInput({ id, expectedServerFingerprint: KEY_B }));
    expect(store.sshConfigs[0]).toMatchObject({ expectedServerFingerprint: KEY_B });
    expect(store.sshConfigs[0]?.trustedHostKeyFingerprint).toBeUndefined();

    // Clearing the pin means: learn the next key afresh.
    store = await storage.upsertConfig(serverInput({ id, expectedServerFingerprint: "" }));
    expect(store.sshConfigs[0]?.trustedHostKeyFingerprint).toBeUndefined();
    await expect(storage.trustHostKeyOnFirstUse({ configId: id, host: "ssh.example.com", port: 22, fingerprint: KEY_B })).resolves.toBe(true);
  });

  it("saves a pinned key's type once a session verified the pin, and keeps it only as long as the pin", async () => {
    const { storage, dir, id } = await storageWithServer(KEY_B);
    // Another key than the pin, or a type the client does not verify, saves nothing.
    await expect(storage.rememberPinnedHostKeyType({ configId: id, fingerprint: KEY_A, keyType: "ssh-rsa" })).resolves.toBe(false);
    await expect(storage.rememberPinnedHostKeyType({ configId: id, fingerprint: KEY_B, keyType: "x" })).resolves.toBe(false);
    await expect(storage.rememberPinnedHostKeyType({ configId: "missing", fingerprint: KEY_B, keyType: "ssh-rsa" })).resolves.toBe(false);
    expect(storage.getStore().sshConfigs[0]).not.toHaveProperty("pinnedHostKeyType");

    await expect(storage.rememberPinnedHostKeyType({ configId: id, fingerprint: KEY_B, keyType: "ssh-rsa" })).resolves.toBe(true);
    await expect(storage.rememberPinnedHostKeyType({ configId: id, fingerprint: KEY_B, keyType: "ssh-rsa" })).resolves.toBe(false);
    const reopened = new AppStorage(dir);
    await reopened.init();
    expect(reopened.getStore().sshConfigs[0]?.pinnedHostKeyType).toBe("ssh-rsa");

    // A fingerprint names one key, so the type stays with the pin through any edit.
    let store = await storage.upsertConfig(serverInput({ id, name: "renamed", host: "other.example.com", expectedServerFingerprint: KEY_B }));
    expect(store.sshConfigs[0]?.pinnedHostKeyType).toBe("ssh-rsa");
    // Another pin, or none, starts without one.
    store = await storage.upsertConfig(serverInput({ id, expectedServerFingerprint: KEY_A }));
    expect(store.sshConfigs[0]).not.toHaveProperty("pinnedHostKeyType");
    await storage.rememberPinnedHostKeyType({ configId: id, fingerprint: KEY_A, keyType: "ssh-ed25519" });
    store = await storage.upsertConfig(serverInput({ id, expectedServerFingerprint: "" }));
    expect(store.sshConfigs[0]).not.toHaveProperty("pinnedHostKeyType");
  });

  it("takes the trusted key's type when the user pins that key", async () => {
    const { storage, id } = await storageWithServer();
    await storage.trustHostKeyOnFirstUse({ configId: id, host: "ssh.example.com", port: 22, fingerprint: KEY_A, keyType: "ssh-ed25519" });

    const store = await storage.upsertConfig(serverInput({ id, expectedServerFingerprint: KEY_A }));
    expect(store.sshConfigs[0]).toMatchObject({ expectedServerFingerprint: KEY_A, pinnedHostKeyType: "ssh-ed25519" });
    expect(store.sshConfigs[0]?.trustedHostKeyFingerprint).toBeUndefined();
  });

  it("drops a pinned key's type it cannot read, or one left without a pin, when it loads the store", async () => {
    const { storage, dir } = await storageWithServer(KEY_B);
    await storage.upsertConfig(serverInput({ name: "unpinned" }));
    const storePath = path.join(dir, "app-store.v1.json");
    const saved = JSON.parse(await readFile(storePath, "utf8")) as ReturnType<typeof createDefaultStore>;
    saved.sshConfigs = saved.sshConfigs.map((config) => ({ ...config, pinnedHostKeyType: config.expectedServerFingerprint ? "ecdsa-sha2-nistp256" : "ssh-rsa" }));
    await writeFile(storePath, `${JSON.stringify(saved, null, 2)}\n`, "utf8");

    const reopened = new AppStorage(dir);
    await reopened.init();
    for (const config of reopened.getStore().sshConfigs) {
      expect(config, config.name).not.toHaveProperty("pinnedHostKeyType");
    }
  });

  it("drops a saved trusted key that is not a fingerprint when it loads the store", async () => {
    const { storage, dir, id } = await storageWithServer();
    await storage.trustHostKeyOnFirstUse({ configId: id, host: "ssh.example.com", port: 22, fingerprint: KEY_A });
    const storePath = path.join(dir, "app-store.v1.json");
    const saved = JSON.parse(await readFile(storePath, "utf8")) as ReturnType<typeof createDefaultStore>;
    saved.sshConfigs = saved.sshConfigs.map((config) => ({ ...config, trustedHostKeyFingerprint: "garbage", trustedHostKeyAt: "2026-01-01T00:00:00.000Z" }));
    await writeFile(storePath, `${JSON.stringify(saved, null, 2)}\n`, "utf8");

    const reopened = new AppStorage(dir);
    await reopened.init();
    const config = reopened.getStore().sshConfigs[0];
    expect(config).not.toHaveProperty("trustedHostKeyFingerprint");
    expect(config).not.toHaveProperty("trustedHostKeyAt");
    // Learned again on the next connection.
    await expect(reopened.trustHostKeyOnFirstUse({ configId: id, host: "ssh.example.com", port: 22, fingerprint: KEY_A })).resolves.toBe(true);
  });
});

async function makeTempDir(cleanupDirs: string[]): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-storage-"));
  cleanupDirs.push(dir);
  return dir;
}

function generatePrivateKeyPem(): string {
  const { privateKey } = generateKeyPairSync("ed25519");
  return privateKey.export({ format: "pem", type: "pkcs8" }).toString();
}

function securityKeyText(): string {
  const envelope = Buffer.concat([
    Buffer.from("openssh-key-v1\0", "utf8"),
    new SshBinaryWriter()
      .string("none")
      .string("none")
      .string(Buffer.alloc(0))
      .uint32(1)
      .string(new SshBinaryWriter().string("sk-ecdsa-sha2-nistp256@openssh.com").string("nistp256").string(Buffer.alloc(65, 4)).string("ssh:").toBuffer())
      .string(Buffer.alloc(64, 2))
      .toBuffer()
  ]);
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${envelope.toString("base64").match(/.{1,70}/gu)?.join("\n") ?? ""}\n-----END OPENSSH PRIVATE KEY-----`;
}
