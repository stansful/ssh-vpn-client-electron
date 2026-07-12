import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createDefaultStore, RUSSIA_INSIDE_PROXY_LIST_URL, RUSSIA_OUTSIDE_DIRECT_LIST_URL } from "../src/shared/defaults.js";

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

async function makeTempDir(cleanupDirs: string[]): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-storage-"));
  cleanupDirs.push(dir);
  return dir;
}

function generatePrivateKeyPem(): string {
  const { privateKey } = generateKeyPairSync("ed25519");
  return privateKey.export({ format: "pem", type: "pkcs8" }).toString();
}
