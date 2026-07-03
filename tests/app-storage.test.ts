import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createDefaultStore } from "../src/shared/defaults.js";

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

const { AppStorage, writeJsonAtomic } = await import("../src/main/storage/app-storage.js");

describe("AppStorage persistence", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
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
