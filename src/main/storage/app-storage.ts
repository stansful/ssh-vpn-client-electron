import { app, safeStorage } from "electron";
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createDefaultStore, STORE_SCHEMA_VERSION } from "../../shared/defaults.js";
import type {
  AppSettings,
  AppStore,
  RoutingMode,
  RoutingRule,
  SshServiceSecrets,
  SshConfig,
  SshKeyMetadata,
  UpsertSshConfigInput,
  UpsertSshKeyInput
} from "../../shared/types.js";

type SecretKind = "ssh-password" | "private-key" | "private-key-passphrase";

interface SecretRecord {
  id: string;
  kind: SecretKind;
  backend: "electron-safe-storage" | "aes-256-gcm-dev-fallback";
  ciphertext: string;
  createdAt: string;
  updatedAt: string;
}

interface SecretStore {
  schemaVersion: number;
  secrets: Record<string, SecretRecord>;
}

export class AppStorage {
  private readonly dataDir: string;
  private readonly storePath: string;
  private readonly secretPath: string;
  private store: AppStore = createDefaultStore();
  private secrets: SecretStore = { schemaVersion: 1, secrets: {} };

  constructor(dataDir = path.join(app.getPath("userData"), "storage")) {
    this.dataDir = dataDir;
    this.storePath = path.join(dataDir, "app-store.v1.json");
    this.secretPath = path.join(dataDir, "secret-store.v1.json");
  }

  async init(): Promise<void> {
    await mkdir(this.dataDir, { recursive: true });
    this.store = normalizeStore(await readJson<AppStore>(this.storePath, createDefaultStore()));
    this.secrets = await readJson<SecretStore>(this.secretPath, { schemaVersion: 1, secrets: {} });
    await this.persistStore();
    await this.persistSecrets();
  }

  getStore(): AppStore {
    return structuredClone(this.store);
  }

  async upsertConfig(input: UpsertSshConfigInput): Promise<AppStore> {
    const now = new Date().toISOString();
    const existing = input.id ? this.store.sshConfigs.find((config) => config.id === input.id) : undefined;
    const passwordSecretId =
      input.password !== undefined && input.password.length > 0
        ? await this.saveSecret("ssh-password", input.password, existing?.passwordSecretId)
        : existing?.passwordSecretId;
    const passphraseSecretId =
      input.privateKeyPassphrase !== undefined && input.privateKeyPassphrase.length > 0
        ? await this.saveSecret("private-key-passphrase", input.privateKeyPassphrase, existing?.privateKeyPassphraseSecretId)
        : existing?.privateKeyPassphraseSecretId;

    const config: SshConfig = {
      id: existing?.id ?? randomUUID(),
      name: input.name.trim(),
      host: input.host.trim(),
      port: Number(input.port),
      username: input.username.trim(),
      authType: input.authType,
      passwordSecretId,
      privateKeyId: input.authType === "private-key" ? input.privateKeyId : undefined,
      privateKeyPassphraseSecretId: input.authType === "private-key" ? passphraseSecretId : undefined,
      expectedServerFingerprint: input.expectedServerFingerprint.trim(),
      keepaliveIntervalSec: Number(input.keepaliveIntervalSec),
      note: input.note.trim(),
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    };

    if (existing) {
      this.store.sshConfigs = this.store.sshConfigs.map((candidate) => (candidate.id === config.id ? config : candidate));
    } else {
      this.store.sshConfigs = [...this.store.sshConfigs, config];
    }

    if (!this.store.selectedConfigId) {
      this.store.selectedConfigId = config.id;
    }

    await this.persistStore();
    return this.getStore();
  }

  async deleteConfig(id: string): Promise<AppStore> {
    const existing = this.store.sshConfigs.find((config) => config.id === id);
    if (!existing) {
      return this.getStore();
    }

    this.store.sshConfigs = this.store.sshConfigs.filter((config) => config.id !== id);
    if (this.store.selectedConfigId === id) {
      this.store.selectedConfigId = this.store.sshConfigs[0]?.id;
    }

    await Promise.all([
      existing.passwordSecretId ? this.deleteSecret(existing.passwordSecretId) : Promise.resolve(),
      existing.privateKeyPassphraseSecretId ? this.deleteSecret(existing.privateKeyPassphraseSecretId) : Promise.resolve()
    ]);
    await this.persistStore();
    return this.getStore();
  }

  async selectConfig(id: string): Promise<AppStore> {
    if (!this.store.sshConfigs.some((config) => config.id === id)) {
      throw new Error("SSH configuration does not exist.");
    }
    this.store.selectedConfigId = id;
    await this.persistStore();
    return this.getStore();
  }

  async upsertKey(input: UpsertSshKeyInput): Promise<AppStore> {
    const now = new Date().toISOString();
    const existing = input.id ? this.store.sshKeys.find((key) => key.id === input.id) : undefined;
    if (!existing && !input.privateKey) {
      throw new Error("Private key is required for a new key.");
    }

    const privateKeySecretId =
      input.privateKey !== undefined && input.privateKey.length > 0
        ? await this.saveSecret("private-key", input.privateKey, existing?.privateKeySecretId)
        : existing?.privateKeySecretId;

    if (!privateKeySecretId) {
      throw new Error("Private key secret is missing.");
    }

    const key: SshKeyMetadata = {
      id: existing?.id ?? randomUUID(),
      name: input.name.trim(),
      privateKeySecretId,
      fingerprint: input.privateKey ? fingerprintSecret(input.privateKey) : existing?.fingerprint ?? "",
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    };

    if (existing) {
      this.store.sshKeys = this.store.sshKeys.map((candidate) => (candidate.id === key.id ? key : candidate));
    } else {
      this.store.sshKeys = [...this.store.sshKeys, key];
    }

    await this.persistStore();
    return this.getStore();
  }

  async deleteKey(id: string): Promise<AppStore> {
    if (this.store.sshConfigs.some((config) => config.privateKeyId === id)) {
      throw new Error("This private key is used by at least one SSH configuration.");
    }

    const existing = this.store.sshKeys.find((key) => key.id === id);
    if (existing) {
      this.store.sshKeys = this.store.sshKeys.filter((key) => key.id !== id);
      await this.deleteSecret(existing.privateKeySecretId);
      await this.persistStore();
    }

    return this.getStore();
  }

  async updateSettings(settings: AppSettings): Promise<AppStore> {
    this.store.settings = settings;
    await this.persistStore();
    return this.getStore();
  }

  async updateRoutingMode(mode: RoutingMode): Promise<AppStore> {
    this.store.routingMode = mode;
    await this.persistStore();
    return this.getStore();
  }

  async updateRoutingRules(rules: RoutingRule[]): Promise<AppStore> {
    this.store.routingRules = rules;
    await this.persistStore();
    return this.getStore();
  }

  resolveServiceSecrets(config: SshConfig): SshServiceSecrets {
    return {
      password: config.passwordSecretId ? this.readSecret(config.passwordSecretId) : undefined,
      privateKey: config.privateKeyId ? this.readPrivateKeySecret(config.privateKeyId) : undefined,
      privateKeyPassphrase: config.privateKeyPassphraseSecretId ? this.readSecret(config.privateKeyPassphraseSecretId) : undefined
    };
  }

  private async saveSecret(kind: SecretKind, value: string, existingId?: string): Promise<string> {
    const now = new Date().toISOString();
    const id = existingId ?? randomUUID();
    const encrypted = encryptSecret(value, this.dataDir);
    this.secrets.secrets[id] = {
      id,
      kind,
      backend: encrypted.backend,
      ciphertext: encrypted.ciphertext,
      createdAt: this.secrets.secrets[id]?.createdAt ?? now,
      updatedAt: now
    };
    await this.persistSecrets();
    return id;
  }

  private async deleteSecret(id: string): Promise<void> {
    delete this.secrets.secrets[id];
    await this.persistSecrets();
  }

  private readSecret(id: string): string {
    const record = this.secrets.secrets[id];
    if (!record) {
      throw new Error("Secret record is missing.");
    }
    return decryptSecretForService(record, this.dataDir);
  }

  private readPrivateKeySecret(privateKeyId: string): string | undefined {
    const key = this.store.sshKeys.find((candidate) => candidate.id === privateKeyId);
    return key ? this.readSecret(key.privateKeySecretId) : undefined;
  }

  private async persistStore(): Promise<void> {
    await writeJsonAtomic(this.storePath, this.store);
  }

  private async persistSecrets(): Promise<void> {
    await writeJsonAtomic(this.secretPath, this.secrets);
  }
}

function normalizeStore(input: AppStore): AppStore {
  const defaults = createDefaultStore();
  return {
    ...defaults,
    ...input,
    schemaVersion: STORE_SCHEMA_VERSION,
    settings: {
      ...defaults.settings,
      ...input.settings,
      customTheme: {
        ...defaults.settings.customTheme,
        ...input.settings?.customTheme
      }
    },
    sshConfigs: Array.isArray(input.sshConfigs) ? input.sshConfigs : [],
    sshKeys: Array.isArray(input.sshKeys) ? input.sshKeys : [],
    routingRules: Array.isArray(input.routingRules) ? input.routingRules : []
  };
}

function encryptSecret(value: string, dataDir: string): Pick<SecretRecord, "backend" | "ciphertext"> {
  if (safeStorage.isEncryptionAvailable()) {
    return {
      backend: "electron-safe-storage",
      ciphertext: safeStorage.encryptString(value).toString("base64")
    };
  }

  if (process.env.NODE_ENV === "production" && process.env.SHADOW_SSH_ALLOW_INSECURE_SECRET_FALLBACK !== "1") {
    throw new Error("Secure storage is unavailable in production.");
  }

  const key = createFallbackKey(dataDir);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    backend: "aes-256-gcm-dev-fallback",
    ciphertext: `${iv.toString("base64")}.${tag.toString("base64")}.${encrypted.toString("base64")}`
  };
}

export function decryptSecretForService(record: SecretRecord, dataDir: string): string {
  if (record.backend === "electron-safe-storage") {
    return safeStorage.decryptString(Buffer.from(record.ciphertext, "base64"));
  }

  const [ivRaw, tagRaw, encryptedRaw] = record.ciphertext.split(".");
  if (!ivRaw || !tagRaw || !encryptedRaw) {
    throw new Error("Invalid encrypted secret payload.");
  }

  const decipher = createDecipheriv("aes-256-gcm", createFallbackKey(dataDir), Buffer.from(ivRaw, "base64"));
  decipher.setAuthTag(Buffer.from(tagRaw, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(encryptedRaw, "base64")), decipher.final()]).toString("utf8");
}

async function readJson<T>(filePath: string, fallback: T): Promise<T> {
  try {
    return JSON.parse(await readFile(filePath, "utf8")) as T;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return fallback;
    }
    throw error;
  }
}

async function writeJsonAtomic(filePath: string, value: unknown): Promise<void> {
  const tmpPath = `${filePath}.${process.pid}.tmp`;
  await writeFile(tmpPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  await rename(tmpPath, filePath);
}

function createFallbackKey(dataDir: string): Buffer {
  const username = os.userInfo().username;
  return createHash("sha256").update(`shadow-ssh:${dataDir}:${os.hostname()}:${username}`).digest();
}

function fingerprintSecret(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("base64").slice(0, 43)}`;
}
