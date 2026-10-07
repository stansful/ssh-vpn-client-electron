import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type * as FsPromises from "node:fs/promises";
import type { AppStore } from "../src/shared/types.js";

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

/** Lets a test make one particular rename fail, as a locked file on Windows would. */
const fsControl = vi.hoisted(() => ({
  failRename: undefined as ((from: string, to: string) => boolean) | undefined
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof FsPromises>();
  return {
    ...actual,
    rename: async (from: string, to: string) => {
      if (fsControl.failRename?.(String(from), String(to))) {
        throw Object.assign(new Error(`EBUSY: resource busy or locked, rename '${String(from)}'`), { code: "EBUSY" });
      }
      return actual.rename(from, to);
    }
  };
});

const { AppStorage, StorageUnreadableError } = await import("../src/main/storage/app-storage.js");

const cleanupDirs: string[] = [];

afterEach(async () => {
  fsControl.failRename = undefined;
  await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-recovery-"));
  cleanupDirs.push(dir);
  return dir;
}

function generatePrivateKeyPem(): string {
  const { privateKey } = generateKeyPairSync("ed25519");
  return privateKey.export({ format: "pem", type: "pkcs8" }).toString();
}

/** A data folder with a server (password), a key, a profile and a rule. */
async function seedDataFolder(dir: string): Promise<void> {
  const storage = new AppStorage(dir);
  await storage.init();
  await storage.upsertConfig({
    name: "Frankfurt-01",
    host: "ssh.example.com",
    port: 22,
    username: "root",
    authType: "password",
    password: "secret",
    expectedServerFingerprint: "",
    keepaliveIntervalSec: 120,
    note: ""
  });
  await storage.upsertKey({ name: "work-ed25519", privateKey: generatePrivateKeyPem() });
  await storage.importProxyProfiles({ text: "vless://id@proxy.example.com:443?type=tcp&security=tls#de-fra", source: "clipboard" });
  const now = new Date().toISOString();
  await storage.updateRoutingRules([{ id: "rule-1", type: "domain", value: "youtube.com", enabled: true, createdAt: now, updatedAt: now }]);
}

const storeFile = (dir: string): string => path.join(dir, "app-store.v1.json");
const secretFile = (dir: string): string => path.join(dir, "secret-store.v1.json");

describe("AppStorage recovery", () => {
  it("never deletes secrets when the store is missing; they are set aside instead", async () => {
    const dir = await makeTempDir();
    await seedDataFolder(dir);
    const secretsBefore = await readFile(secretFile(dir), "utf8");
    // The store was moved by hand, or a recovery stopped between its renames.
    await rm(storeFile(dir));

    const storage = new AppStorage(dir);
    await storage.init();

    const backups = (await readdir(dir)).filter((name) => /^secret-store\.v1\.orphaned-\d{8}-\d{6}\.json$/u.test(name));
    expect(backups).toHaveLength(1);
    expect(await readFile(path.join(dir, backups[0] ?? ""), "utf8")).toBe(secretsBefore);
    expect(storage.isInitialized).toBe(true);
  });

  it("moves the secret file first and puts it back when the store can't be moved", async () => {
    const dir = await makeTempDir();
    await seedDataFolder(dir);
    const secretsBefore = await readFile(secretFile(dir), "utf8");
    await writeFile(storeFile(dir), "{ broken", "utf8");
    const storage = new AppStorage(dir);
    await expect(storage.init()).rejects.toThrow(StorageUnreadableError);
    fsControl.failRename = (from, to) => from === storeFile(dir) && to.includes(".unreadable-");

    await expect(storage.startFresh()).rejects.toThrow(/EBUSY/u);

    // Both files are where they were, so the next start cannot purge the secrets.
    expect(await readFile(secretFile(dir), "utf8")).toBe(secretsBefore);
    expect(await readFile(storeFile(dir), "utf8")).toBe("{ broken");
    expect((await readdir(dir)).filter((name) => name.includes(".unreadable-"))).toEqual([]);
    expect(storage.isInitialized).toBe(false);

    // The other way round: the secret file is locked, so the store must not move alone.
    fsControl.failRename = (from, to) => from === secretFile(dir) && to.includes(".unreadable-");
    await expect(storage.startFresh()).rejects.toThrow(/EBUSY/u);
    expect(await readFile(storeFile(dir), "utf8")).toBe("{ broken");
    expect(await readFile(secretFile(dir), "utf8")).toBe(secretsBefore);
  });

  it("keeps using data it read when writing it back fails, and leaves the files alone", async () => {
    const dir = await makeTempDir();
    await seedDataFolder(dir);
    const stored = JSON.parse(await readFile(storeFile(dir), "utf8")) as { schemaVersion: number };
    // An older schema always differs from its migrated form, so init writes.
    const legacyText = JSON.stringify({ ...stored, schemaVersion: 2 });
    await writeFile(storeFile(dir), legacyText, "utf8");
    fsControl.failRename = (_from, to) => to === storeFile(dir);

    const storage = new AppStorage(dir);
    const result = await storage.init();

    expect(result.writeError?.message).toMatch(/EBUSY/u);
    expect(storage.isInitialized).toBe(true);
    expect(storage.getStore().sshConfigs.map((config) => config.name)).toEqual(["Frankfurt-01"]);
    expect(await readFile(storeFile(dir), "utf8")).toBe(legacyText);

    // The next change writes everything again.
    fsControl.failRename = undefined;
    await storage.updateSettings({ sidebarCollapsed: true });
    expect((JSON.parse(await readFile(storeFile(dir), "utf8")) as { schemaVersion: number }).schemaVersion).toBeGreaterThan(2);
  });

  it("names the unreadable file and moves only it when the secret store alone is broken", async () => {
    const dir = await makeTempDir();
    await seedDataFolder(dir);
    const storeBefore = JSON.parse(await readFile(storeFile(dir), "utf8")) as AppStore;
    await writeFile(secretFile(dir), "{ broken", "utf8");
    const storage = new AppStorage(dir);

    const error = await storage.init().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(StorageUnreadableError);
    expect((error as InstanceType<typeof StorageUnreadableError>).files).toEqual(["secrets"]);
    expect((error as InstanceType<typeof StorageUnreadableError>).filePath).toBe(secretFile(dir));

    const backups = await storage.startFresh();

    expect(backups.map((backup) => path.basename(backup))).toEqual([expect.stringMatching(/^secret-store\.v1\.unreadable-\d{8}-\d{6}\.json$/u)]);
    expect(await readFile(backups[0] ?? "", "utf8")).toBe("{ broken");
    const store = storage.getStore();
    expect(store.routingRules).toEqual(storeBefore.routingRules);
    expect(store.sshConfigs.map((config) => [config.name, config.passwordSecretId])).toEqual([["Frankfurt-01", undefined]]);
    // Keys and profiles are nothing without their secret.
    expect(store.sshKeys).toEqual([]);
    expect(store.proxyProfiles).toEqual([]);
    expect(store.selectedProxyProfileId).toBeUndefined();
    await expect(storage.updateSettings({ sidebarCollapsed: true })).resolves.toBeDefined();
  });
});
