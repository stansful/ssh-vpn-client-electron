import { app, safeStorage } from "electron";
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseProxyShareLink, parseProxyShareLinks } from "../../core/proxy/share-link-parser.js";
import { assertSshPrivateKeyText, normalizeSshPrivateKeyText } from "../../core/ssh/private-key.js";
import { createDefaultStore, RUSSIA_INSIDE_PROXY_LIST_URL, RUSSIA_OUTSIDE_DIRECT_LIST_URL, STORE_SCHEMA_VERSION } from "../../shared/defaults.js";
import type {
  ImportProxyProfilesInput,
  ImportProxyProfilesResult,
  AppSettings,
  AppStore,
  ProxyProfile,
  ProxyServiceSecrets,
  RoutingDirectList,
  RoutingMode,
  RoutingProxyList,
  RoutingRule,
  SshServiceSecrets,
  SshConfig,
  SshKeyMetadata,
  UpsertProxyProfileInput,
  UpsertSshConfigInput,
  UpsertSshKeyInput
} from "../../shared/types.js";

type SecretKind = "ssh-password" | "private-key" | "private-key-passphrase" | "proxy-uri";

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
  private storePersistQueue: Promise<void> = Promise.resolve();
  private secretsPersistQueue: Promise<void> = Promise.resolve();

  constructor(dataDir = path.join(app.getPath("userData"), "storage")) {
    this.dataDir = dataDir;
    this.storePath = path.join(dataDir, "app-store.v1.json");
    this.secretPath = path.join(dataDir, "secret-store.v1.json");
  }

  async init(): Promise<void> {
    await mkdir(this.dataDir, { recursive: true });
    this.store = normalizeStore(await readJson<AppStore>(this.storePath, createDefaultStore()));
    this.secrets = await readJson<SecretStore>(this.secretPath, { schemaVersion: 1, secrets: {} });
    this.migrateConfigPassphrasesToKeys();
    this.ensureProxySelection();
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

    const config: SshConfig = {
      id: existing?.id ?? randomUUID(),
      name: input.name.trim(),
      host: input.host.trim(),
      port: Number(input.port),
      username: input.username.trim(),
      authType: input.authType,
      passwordSecretId,
      privateKeyId: input.authType === "private-key" ? input.privateKeyId : undefined,
      privateKeyPassphraseSecretId: undefined,
      expectedServerFingerprint: input.expectedServerFingerprint.trim(),
      keepaliveIntervalSec: Math.max(60, Number(input.keepaliveIntervalSec)),
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
    const normalizedPrivateKey =
      input.privateKey !== undefined && input.privateKey.length > 0 ? normalizeSshPrivateKeyText(input.privateKey) : undefined;
    if (normalizedPrivateKey !== undefined) {
      assertSshPrivateKeyText(normalizedPrivateKey);
    }

    const privateKeySecretId =
      normalizedPrivateKey !== undefined
        ? await this.saveSecret("private-key", normalizedPrivateKey, existing?.privateKeySecretId)
        : existing?.privateKeySecretId;
    const privateKeyPassphraseSecretId =
      input.privateKeyPassphrase !== undefined && input.privateKeyPassphrase.length > 0
        ? await this.saveSecret("private-key-passphrase", input.privateKeyPassphrase, existing?.privateKeyPassphraseSecretId)
        : existing?.privateKeyPassphraseSecretId;

    if (!privateKeySecretId) {
      throw new Error("Private key secret is missing.");
    }

    const key: SshKeyMetadata = {
      id: existing?.id ?? randomUUID(),
      name: input.name.trim(),
      privateKeySecretId,
      privateKeyPassphraseSecretId,
      fingerprint: normalizedPrivateKey ? fingerprintSecret(normalizedPrivateKey) : existing?.fingerprint ?? "",
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
      await Promise.all([
        this.deleteSecret(existing.privateKeySecretId),
        existing.privateKeyPassphraseSecretId ? this.deleteSecret(existing.privateKeyPassphraseSecretId) : Promise.resolve()
      ]);
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

  async updateRoutingProxyList(list: RoutingProxyList): Promise<AppStore> {
    this.store.routingProxyList = {
      enabled: list.enabled,
      sourceUrl: list.sourceUrl.trim() || RUSSIA_INSIDE_PROXY_LIST_URL,
      domains: normalizeDomainList(list.domains),
      updatedAt: list.updatedAt
    };
    await this.persistStore();
    return this.getStore();
  }

  async updateRoutingDirectList(list: RoutingDirectList): Promise<AppStore> {
    this.store.routingDirectList = {
      enabled: list.enabled,
      sourceUrl: list.sourceUrl.trim() || RUSSIA_OUTSIDE_DIRECT_LIST_URL,
      domains: normalizeDomainList(list.domains),
      updatedAt: list.updatedAt
    };
    await this.persistStore();
    return this.getStore();
  }

  async upsertProxyProfile(input: UpsertProxyProfileInput): Promise<AppStore> {
    const parsed = parseProxyShareLink(input.rawUri.trim());
    const now = new Date().toISOString();
    const existingById = input.id ? this.store.proxyProfiles.find((profile) => profile.id === input.id) : undefined;
    const existingByFingerprint = this.store.proxyProfiles.find((profile) => profile.fingerprint === parsed.fingerprint);
    const existing = existingById ?? existingByFingerprint;
    const rawUriSecretId = await this.saveSecret("proxy-uri", parsed.rawUri, existing?.rawUriSecretId);
    const profile: ProxyProfile = {
      id: existing?.id ?? randomUUID(),
      name: input.name.trim() || parsed.name,
      protocol: parsed.protocol,
      host: parsed.host,
      port: parsed.port,
      transport: parsed.transport,
      security: parsed.security,
      flow: parsed.flow,
      source: input.source ?? existing?.source ?? "manual",
      sourceUrl: existing?.sourceUrl,
      rawUriSecretId,
      fingerprint: parsed.fingerprint,
      isSelected: existing?.isSelected ?? false,
      isPinned: existing?.isPinned ?? false,
      isStale: false,
      lastTestStatus: existing?.lastTestStatus ?? "unknown",
      lastLatencyMs: existing?.lastLatencyMs,
      lastTestAt: existing?.lastTestAt,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      lastSeenAt: now
    };

    this.store.proxyProfiles = existing
      ? this.store.proxyProfiles.map((candidate) => (candidate.id === existing.id ? profile : candidate))
      : [...this.store.proxyProfiles, profile];
    this.ensureProxySelection();
    await this.persistStore();
    return this.getStore();
  }

  async importProxyProfiles(input: ImportProxyProfilesInput): Promise<{ store: AppStore; result: ImportProxyProfilesResult }> {
    const parsed = parseProxyShareLinks(input.text);
    const now = new Date().toISOString();
    let imported = 0;
    let updated = 0;

    for (const profileInput of parsed.profiles) {
      const existing = this.store.proxyProfiles.find((profile) => profile.fingerprint === profileInput.fingerprint);
      const rawUriSecretId = await this.saveSecret("proxy-uri", profileInput.rawUri, existing?.rawUriSecretId, false);
      const profile: ProxyProfile = {
        id: existing?.id ?? randomUUID(),
        name: existing?.name || profileInput.name,
        protocol: profileInput.protocol,
        host: profileInput.host,
        port: profileInput.port,
        transport: profileInput.transport,
        security: profileInput.security,
        flow: profileInput.flow,
        source: input.source,
        sourceUrl: input.sourceUrl,
        rawUriSecretId,
        fingerprint: profileInput.fingerprint,
        isSelected: existing?.isSelected ?? false,
        isPinned: existing?.isPinned ?? false,
        isStale: false,
        lastTestStatus: existing?.lastTestStatus ?? "unknown",
        lastLatencyMs: existing?.lastLatencyMs,
        lastTestAt: existing?.lastTestAt,
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
        lastSeenAt: now
      };
      if (existing) {
        updated += 1;
        this.store.proxyProfiles = this.store.proxyProfiles.map((candidate) => (candidate.id === existing.id ? profile : candidate));
      } else {
        imported += 1;
        this.store.proxyProfiles = [...this.store.proxyProfiles, profile];
      }
    }

    if (input.source === "remote" && input.sourceUrl) {
      const fingerprints = new Set(parsed.profiles.map((profile) => profile.fingerprint));
      this.store.proxyProfiles = this.store.proxyProfiles.map((profile) =>
        profile.source === "remote" && profile.sourceUrl === input.sourceUrl && !fingerprints.has(profile.fingerprint)
          ? { ...profile, isStale: true, updatedAt: now }
          : profile
      );
    }

    if (parsed.profiles.length > 0) {
      await this.persistSecrets();
    }
    this.ensureProxySelection();
    await this.persistStore();
    const result: ImportProxyProfilesResult = {
      imported,
      updated,
      skipped: parsed.skipped,
      failed: parsed.errors.length,
      errors: parsed.errors.slice(0, 20)
    };
    return { store: this.getStore(), result };
  }

  async selectProxyProfile(id: string): Promise<AppStore> {
    if (!this.store.proxyProfiles.some((profile) => profile.id === id)) {
      throw new Error("Proxy profile does not exist.");
    }
    this.store.selectedProxyProfileId = id;
    this.store.proxyProfiles = this.store.proxyProfiles.map((profile) => ({ ...profile, isSelected: profile.id === id }));
    await this.persistStore();
    return this.getStore();
  }

  async toggleProxyProfilePin(id: string): Promise<AppStore> {
    this.store.proxyProfiles = this.store.proxyProfiles.map((profile) =>
      profile.id === id ? { ...profile, isPinned: !profile.isPinned, updatedAt: new Date().toISOString() } : profile
    );
    await this.persistStore();
    return this.getStore();
  }

  async deleteProxyProfile(id: string): Promise<AppStore> {
    const existing = this.store.proxyProfiles.find((profile) => profile.id === id);
    if (!existing) {
      return this.getStore();
    }
    this.store.proxyProfiles = this.store.proxyProfiles.filter((profile) => profile.id !== id);
    await this.deleteSecret(existing.rawUriSecretId);
    this.ensureProxySelection();
    await this.persistStore();
    return this.getStore();
  }

  async deleteUnpinnedProxyProfiles(): Promise<AppStore> {
    const deleted = this.store.proxyProfiles.filter((profile) => !profile.isPinned);
    this.store.proxyProfiles = this.store.proxyProfiles.filter((profile) => profile.isPinned);
    for (const profile of deleted) {
      await this.deleteSecret(profile.rawUriSecretId, false);
    }
    if (deleted.length > 0) {
      await this.persistSecrets();
    }
    this.ensureProxySelection();
    await this.persistStore();
    return this.getStore();
  }

  resolveServiceSecrets(config: SshConfig): SshServiceSecrets {
    return {
      password: config.passwordSecretId ? this.readSecret(config.passwordSecretId) : undefined,
      privateKey: config.privateKeyId ? this.readPrivateKeySecret(config.privateKeyId) : undefined,
      privateKeyPassphrase: config.privateKeyId
        ? this.readPrivateKeyPassphraseSecret(config.privateKeyId) ?? (config.privateKeyPassphraseSecretId ? this.readSecret(config.privateKeyPassphraseSecretId) : undefined)
        : undefined
    };
  }

  resolveProxySecrets(profile: ProxyProfile): ProxyServiceSecrets {
    return {
      rawUri: this.readSecret(profile.rawUriSecretId)
    };
  }

  readPrivateKeyText(privateKeyId: string): string {
    const privateKey = this.readPrivateKeySecret(privateKeyId);
    if (!privateKey) {
      throw new Error("SSH key does not exist.");
    }
    return privateKey;
  }

  private async saveSecret(kind: SecretKind, value: string, existingId?: string, persist = true): Promise<string> {
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
    if (persist) {
      await this.persistSecrets();
    }
    return id;
  }

  private async deleteSecret(id: string, persist = true): Promise<void> {
    delete this.secrets.secrets[id];
    if (persist) {
      await this.persistSecrets();
    }
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

  private readPrivateKeyPassphraseSecret(privateKeyId: string): string | undefined {
    const key = this.store.sshKeys.find((candidate) => candidate.id === privateKeyId);
    return key?.privateKeyPassphraseSecretId ? this.readSecret(key.privateKeyPassphraseSecretId) : undefined;
  }

  private migrateConfigPassphrasesToKeys(): void {
    const usedPassphraseSecretIds = new Set<string>();
    this.store.sshKeys = this.store.sshKeys.map((key) => {
      if (key.privateKeyPassphraseSecretId) {
        usedPassphraseSecretIds.add(key.privateKeyPassphraseSecretId);
        return key;
      }
      const configPassphrase = this.store.sshConfigs.find(
        (config) => config.privateKeyId === key.id && config.privateKeyPassphraseSecretId
      )?.privateKeyPassphraseSecretId;
      if (!configPassphrase) {
        return key;
      }
      usedPassphraseSecretIds.add(configPassphrase);
      return { ...key, privateKeyPassphraseSecretId: configPassphrase };
    });

    this.store.sshConfigs = this.store.sshConfigs.map((config) => {
      if (!config.privateKeyPassphraseSecretId) {
        return config;
      }
      if (!usedPassphraseSecretIds.has(config.privateKeyPassphraseSecretId)) {
        delete this.secrets.secrets[config.privateKeyPassphraseSecretId];
      }
      return { ...config, privateKeyPassphraseSecretId: undefined };
    });
  }

  private ensureProxySelection(): void {
    const selectable = this.store.proxyProfiles.filter((profile) => !profile.isStale);
    const selectedExists = selectable.some((profile) => profile.id === this.store.selectedProxyProfileId);
    const selectedId = selectedExists ? this.store.selectedProxyProfileId : selectable[0]?.id;
    this.store.selectedProxyProfileId = selectedId;
    this.store.proxyProfiles = this.store.proxyProfiles.map((profile) => ({
      ...profile,
      isSelected: Boolean(selectedId) && profile.id === selectedId
    }));
  }

  private async persistStore(): Promise<void> {
    const write = this.storePersistQueue.then(() => writeJsonAtomic(this.storePath, this.store));
    this.storePersistQueue = write.catch(() => undefined);
    await write;
  }

  private async persistSecrets(): Promise<void> {
    const write = this.secretsPersistQueue.then(() => writeJsonAtomic(this.secretPath, this.secrets));
    this.secretsPersistQueue = write.catch(() => undefined);
    await write;
  }
}

function normalizeStore(input: AppStore): AppStore {
  const defaults = createDefaultStore();
  const rawSettings = input.settings as unknown as ({ activeGlobalTab?: string } & Record<string, unknown>) | undefined;
  const inputSettings = (input.settings ?? {}) as Partial<AppSettings> & {
    openSourceConsentAccepted?: boolean;
    showOpenSourceWarningOnEnter?: boolean;
    openSourceRiskBannerExpanded?: boolean;
  };
  const activeGlobalTab = rawSettings?.activeGlobalTab === "opensource"
    ? "xray"
    : rawSettings?.activeGlobalTab === "xray" || rawSettings?.activeGlobalTab === "ssh"
      ? rawSettings.activeGlobalTab
      : defaults.settings.activeGlobalTab;
  const lastConnectedTransport = inputSettings.lastConnectedTransport === "xray" || inputSettings.lastConnectedTransport === "ssh"
    ? inputSettings.lastConnectedTransport
    : activeGlobalTab;
  return {
    ...defaults,
    ...input,
    schemaVersion: STORE_SCHEMA_VERSION,
    settings: {
      ...defaults.settings,
      ...inputSettings,
      activeGlobalTab,
      lastConnectedTransport,
      xrayConsentAccepted: inputSettings.xrayConsentAccepted ?? inputSettings.openSourceConsentAccepted ?? defaults.settings.xrayConsentAccepted,
      showXrayWarningOnEnter: inputSettings.showXrayWarningOnEnter ?? inputSettings.showOpenSourceWarningOnEnter ?? defaults.settings.showXrayWarningOnEnter,
      xrayRiskBannerExpanded: inputSettings.xrayRiskBannerExpanded ?? inputSettings.openSourceRiskBannerExpanded ?? defaults.settings.xrayRiskBannerExpanded,
      customTheme: {
        ...defaults.settings.customTheme,
        ...inputSettings.customTheme
      }
    },
    sshConfigs: Array.isArray(input.sshConfigs) ? input.sshConfigs : [],
    sshKeys: Array.isArray(input.sshKeys) ? input.sshKeys : [],
    proxyProfiles: Array.isArray(input.proxyProfiles) ? input.proxyProfiles : [],
    selectedProxyProfileId: input.selectedProxyProfileId,
    routingRules: Array.isArray(input.routingRules) ? input.routingRules : [],
    routingProxyList: normalizeRoutingProxyList(input.routingProxyList ?? (input as AppStore & { routingBypassList?: unknown }).routingBypassList, defaults.routingProxyList),
    routingDirectList: normalizeRoutingDirectList(input.routingDirectList, defaults.routingDirectList)
  };
}

function normalizeRoutingProxyList(input: unknown, defaults: RoutingProxyList): RoutingProxyList {
  const candidate = input as Partial<RoutingProxyList> | undefined;
  return {
    enabled: Boolean(candidate?.enabled),
    sourceUrl: typeof candidate?.sourceUrl === "string" && candidate.sourceUrl.trim() ? candidate.sourceUrl.trim() : defaults.sourceUrl,
    domains: normalizeDomainList(candidate?.domains),
    updatedAt: typeof candidate?.updatedAt === "string" ? candidate.updatedAt : undefined
  };
}

function normalizeRoutingDirectList(input: unknown, defaults: RoutingDirectList): RoutingDirectList {
  const candidate = input as Partial<RoutingDirectList> | undefined;
  return {
    enabled: Boolean(candidate?.enabled),
    sourceUrl: typeof candidate?.sourceUrl === "string" && candidate.sourceUrl.trim() ? candidate.sourceUrl.trim() : defaults.sourceUrl,
    domains: normalizeDomainList(candidate?.domains),
    updatedAt: typeof candidate?.updatedAt === "string" ? candidate.updatedAt : undefined
  };
}

function normalizeDomainList(input: unknown): string[] {
  if (!Array.isArray(input)) {
    return [];
  }
  return Array.from(
    new Set(
      input
        .filter((domain): domain is string => typeof domain === "string")
        .map((domain) => domain.trim().toLowerCase())
        .filter(Boolean)
    )
  ).sort((left, right) => left.localeCompare(right));
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

export async function writeJsonAtomic(filePath: string, value: unknown): Promise<void> {
  const tmpPath = `${filePath}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(tmpPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    await rename(tmpPath, filePath);
  } catch (error) {
    await rm(tmpPath, { force: true }).catch(() => undefined);
    throw error;
  }
}

function createFallbackKey(dataDir: string): Buffer {
  const username = os.userInfo().username;
  return createHash("sha256").update(`shadow-ssh:${dataDir}:${os.hostname()}:${username}`).digest();
}

function fingerprintSecret(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("base64").slice(0, 43)}`;
}
