import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createDefaultStore,
  DEFAULT_CUSTOM_THEME,
  LEGACY_DEFAULT_SIGNAL_COLORS,
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
      () => storage.deleteProxyProfile("missing"),
      () => storage.deleteUnpinnedProxyProfiles(),
      () => storage.updateRoutingProxyList(createDefaultStore().routingProxyList),
      () => storage.updateRoutingDirectList(createDefaultStore().routingDirectList)
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

async function makeTempDir(cleanupDirs: string[]): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-storage-"));
  cleanupDirs.push(dir);
  return dir;
}

function generatePrivateKeyPem(): string {
  const { privateKey } = generateKeyPairSync("ed25519");
  return privateKey.export({ format: "pem", type: "pkcs8" }).toString();
}
