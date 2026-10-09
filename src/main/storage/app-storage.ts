import { app, safeStorage } from "electron";
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { access, chmod, mkdir, open, rename, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { withShareLinkName } from "../../core/proxy/share-link-name.js";
import { parseProxyShareLink, parseProxyShareLinks } from "../../core/proxy/share-link-parser.js";
import { assertSshPrivateKeyText, detectSshKeyMetadata, normalizeSshPrivateKeyText } from "../../core/ssh/private-key.js";
import {
  createDefaultStore,
  DEFAULT_CUSTOM_THEME,
  LEGACY_DEFAULT_SIGNAL_COLORS,
  LEGACY_PUBLIC_PROXY_LIST_URLS,
  PUBLIC_PROXY_LIST_URL,
  RUSSIA_INSIDE_PROXY_LIST_URL,
  RUSSIA_OUTSIDE_DIRECT_LIST_URL,
  STORE_SCHEMA_VERSION
} from "../../shared/defaults.js";
import { normalizeProxyProfileName, validateCheckEndpoint, validateSshServerFingerprint } from "../../shared/validation.js";
import type {
  ImportProxyProfilesInput,
  ImportProxyProfilesResult,
  AppSettings,
  AppStore,
  CustomTheme,
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

const MAX_ROUTING_RULES = 10_000;
const MAX_ROUTING_DOMAINS = 20_000;
export const MAX_STORED_PROXY_PROFILES = 10_000;
const MAX_APP_STORE_FILE_BYTES = 32 * 1024 * 1024;
const MAX_SECRET_STORE_FILE_BYTES = 64 * 1024 * 1024;
/** Enough to list every failed line of a large paste; the parser itself stops at its line limit. */
const MAX_IMPORT_ERRORS_RETURNED = 500;
export const STORAGE_WRITE_BLOCKED_MESSAGE =
  "Saved data couldn't be read, so changes are blocked. Recover it on the startup screen first.";
export const UNSUPPORTED_PROXY_PROFILE_MESSAGE =
  "This profile uses an unsupported security mode or transport, so it can't be selected.";

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

/** The two files saved data lives in. */
export type StorageFile = "store" | "secrets";

/**
 * Saved data exists but could not be read or understood. Only this error
 * means "unreadable": recovery moves exactly `files` aside, so a file that
 * read fine is never set aside with it.
 */
export class StorageUnreadableError extends Error {
  constructor(
    readonly files: StorageFile[],
    /** The first file that could not be read, for the recovery screen. */
    readonly filePath: string,
    message: string,
    options?: { cause?: unknown }
  ) {
    super(message, options);
    this.name = "StorageUnreadableError";
  }
}

export interface StorageInitResult {
  /**
   * Everything was read and is in use, but writing its migrated form back
   * failed (a locked file, a full disk). The files on disk are untouched and
   * the next save tries again.
   */
  writeError?: Error;
}

export class AppStorage {
  private readonly dataDir: string;
  private readonly storeFilePath: string;
  private readonly secretPath: string;
  private store: AppStore = createDefaultStore();
  private secrets: SecretStore = { schemaVersion: 1, secrets: {} };
  private secretsRevision = 0;
  /**
   * False until `init` succeeds. A store that could not be read is never
   * written over: the next save would replace whatever the user still had on
   * disk with defaults, so every mutation is refused until it is recovered.
   */
  private initialized = false;
  /** Which files the last `init` could not read; undefined when it read both or never ran. */
  private unreadableFiles: StorageFile[] | undefined;
  private readonly storeWriter: CoalescingAtomicJsonWriter;
  private readonly secretsWriter: CoalescingAtomicJsonWriter;

  constructor(dataDir = path.join(app.getPath("userData"), "storage")) {
    this.dataDir = dataDir;
    this.storeFilePath = path.join(dataDir, "app-store.v1.json");
    this.secretPath = path.join(dataDir, "secret-store.v1.json");
    this.storeWriter = new CoalescingAtomicJsonWriter(this.storeFilePath, writeJsonTextAtomic, {
      maxBytes: MAX_APP_STORE_FILE_BYTES,
      label: "Application store"
    });
    this.secretsWriter = new CoalescingAtomicJsonWriter(this.secretPath, writeJsonTextAtomic, {
      maxBytes: MAX_SECRET_STORE_FILE_BYTES,
      label: "Secret store"
    });
  }

  /** The application store file, for the recovery screen. */
  get storePath(): string {
    return this.storeFilePath;
  }

  /** The folder holding the store and secret files. */
  get dataDirectory(): string {
    return this.dataDir;
  }

  /** Whether `init` succeeded, so the store may be written. */
  get isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Reads both files. A file that exists but cannot be read or understood
   * throws `StorageUnreadableError` and leaves the store blocked for writes;
   * a failure to write the migrated data back does not - it is returned as
   * `writeError` and the data is used as read.
   */
  async init(): Promise<StorageInitResult> {
    return this.load({ dropMissingSecretReferences: false });
  }

  /**
   * Recovery for saved data that cannot be read: the unreadable files are
   * moved aside as `<name>.unreadable-<YYYYMMDD-HHmmss>.json` - never deleted,
   * they may still be repairable by hand - and the app goes on without them.
   * An unreadable store takes the secret file along, because secrets without
   * the store that references them would be removed as orphans; an
   * unreadable secret file alone leaves the store in place, minus the secret
   * references that now point nowhere.
   *
   * Returns the backup paths, the store's first.
   */
  async startFresh(): Promise<string[]> {
    this.initialized = false;
    await Promise.all([this.storeWriter.settled(), this.secretsWriter.settled()]);
    // Without a record of which file failed, both move, as before.
    const files = new Set<StorageFile>(this.unreadableFiles?.length ? this.unreadableFiles : ["store", "secrets"]);
    if (files.has("store")) {
      files.add("secrets");
    }
    const stamp = formatBackupTimestamp(new Date());
    const moved: Array<{ file: StorageFile; from: string; to: string }> = [];
    try {
      // Secrets first: if the store's rename then fails, a store without its
      // secret file only keeps dangling references, while secrets left
      // without their store would be purged as orphans on the next start.
      for (const file of (["secrets", "store"] as const).filter((candidate) => files.has(candidate))) {
        const from = file === "store" ? this.storeFilePath : this.secretPath;
        const to = await moveAside(from, "unreadable", stamp);
        if (to) {
          moved.push({ file, from, to });
        }
      }
    } catch (error) {
      for (const { from, to } of [...moved].reverse()) {
        await rename(to, from).catch(() => undefined);
      }
      throw error;
    }
    this.store = createDefaultStore();
    this.secrets = { schemaVersion: 1, secrets: {} };
    this.secretsRevision += 1;
    await this.load({ dropMissingSecretReferences: !files.has("store") });
    return [...moved.filter((entry) => entry.file === "store"), ...moved.filter((entry) => entry.file !== "store")].map((entry) => entry.to);
  }

  private async load({ dropMissingSecretReferences }: { dropMissingSecretReferences: boolean }): Promise<StorageInitResult> {
    this.initialized = false;
    this.unreadableFiles = undefined;
    await mkdir(this.dataDir, { recursive: true });

    const failures: Array<{ file: StorageFile; filePath: string; error: unknown }> = [];
    let storedStore: { value: AppStore; exists: boolean } | undefined;
    let store: AppStore | undefined;
    try {
      storedStore = await readJsonWithStatus<AppStore>(
        this.storeFilePath,
        createDefaultStore(),
        MAX_APP_STORE_FILE_BYTES,
        "Application store"
      );
      store = normalizeStore(storedStore.value);
    } catch (error) {
      failures.push({ file: "store", filePath: this.storeFilePath, error });
    }
    let storedSecrets: { value: SecretStore; exists: boolean } | undefined;
    let secrets: SecretStore | undefined;
    try {
      storedSecrets = await readJsonWithStatus<SecretStore>(
        this.secretPath,
        { schemaVersion: 1, secrets: {} },
        MAX_SECRET_STORE_FILE_BYTES,
        "Secret store"
      );
      secrets = normalizeSecretStore(storedSecrets.value);
    } catch (error) {
      failures.push({ file: "secrets", filePath: this.secretPath, error });
    }
    if (failures.length > 0 || !storedStore || !store || !storedSecrets || !secrets) {
      throw this.unreadable(failures);
    }

    this.store = store;
    this.secrets = secrets;
    let migration: { secretsChanged: boolean };
    try {
      migration = this.migrateConfigPassphrasesToKeys();
      if (dropMissingSecretReferences) {
        this.dropMissingSecretReferences();
      }
      this.ensureProxySelection();
    } catch (error) {
      // Entries of an unexpected shape inside an otherwise valid file.
      throw this.unreadable([{ file: "store", filePath: this.storeFilePath, error }]);
    }

    let orphansSetAside = false;
    if (!storedStore.exists && storedSecrets.exists && Object.keys(this.secrets.secrets).length > 0) {
      // Every secret would count as an orphan below and be deleted for good,
      // although the store may only be missing for now: moved by hand, or a
      // recovery interrupted between its renames. Keep them aside instead.
      await moveAside(this.secretPath, "orphaned", formatBackupTimestamp(new Date()));
      this.secrets = { schemaVersion: 1, secrets: {} };
      this.secretsRevision += 1;
      orphansSetAside = true;
    }
    const removedOrphanedSecrets = this.removeOrphanedSecrets();
    this.backfillKeyMetadata();

    let writeError: Error | undefined;
    try {
      if (!storedStore.exists || !areJsonValuesEqual(storedStore.value, this.store)) {
        await this.persistStore();
      } else {
        await ensurePrivateFileMode(this.storeFilePath);
      }
      // Secret changes follow store changes; if the store could not be
      // written, the secrets on disk stay as they are too.
      if (!storedSecrets.exists || migration.secretsChanged || removedOrphanedSecrets || orphansSetAside) {
        await this.persistSecrets();
      } else {
        await ensurePrivateFileMode(this.secretPath);
      }
    } catch (error) {
      writeError = error instanceof Error ? error : new Error(String(error));
    }
    this.initialized = true;
    return writeError ? { writeError } : {};
  }

  private unreadable(failures: Array<{ file: StorageFile; filePath: string; error: unknown }>): StorageUnreadableError {
    this.unreadableFiles = failures.map((failure) => failure.file);
    const [first] = failures;
    const describe = (error: unknown): string => (error instanceof Error ? error.message : String(error));
    const message = failures.length > 1
      ? failures.map((failure) => `${failure.file === "store" ? "Application store" : "Secret store"}: ${describe(failure.error)}`).join(" ")
      : describe(first?.error);
    return new StorageUnreadableError(
      failures.map((failure) => failure.file),
      first?.filePath ?? this.storeFilePath,
      message,
      { cause: first?.error }
    );
  }

  /**
   * After an unreadable secret file was set aside, the store still points at
   * secrets that no longer exist. Servers keep everything but the saved
   * password; keys and profiles, which are nothing without their secret, are
   * removed. Rules, lists and settings stay as they were.
   */
  private dropMissingSecretReferences(): void {
    const exists = (id: string | undefined): id is string => id !== undefined && Object.hasOwn(this.secrets.secrets, id);
    this.store.sshKeys = this.store.sshKeys
      .filter((key) => exists(key.privateKeySecretId))
      .map((key) => (key.privateKeyPassphraseSecretId === undefined || exists(key.privateKeyPassphraseSecretId)
        ? key
        : { ...key, privateKeyPassphraseSecretId: undefined }));
    const keyIds = new Set(this.store.sshKeys.map((key) => key.id));
    this.store.sshConfigs = this.store.sshConfigs.map((config) => ({
      ...config,
      passwordSecretId: exists(config.passwordSecretId) ? config.passwordSecretId : undefined,
      privateKeyPassphraseSecretId: exists(config.privateKeyPassphraseSecretId) ? config.privateKeyPassphraseSecretId : undefined,
      privateKeyId: config.privateKeyId !== undefined && keyIds.has(config.privateKeyId) ? config.privateKeyId : undefined
    }));
    this.store.proxyProfiles = this.store.proxyProfiles.filter((profile) => exists(profile.rawUriSecretId));
  }

  getStore(): AppStore {
    return structuredClone(this.store);
  }

  /** Returns only the small settings branch without cloning large profile/rule lists. */
  getSettings(): AppSettings {
    return structuredClone(this.store.settings);
  }

  async upsertConfig(input: UpsertSshConfigInput): Promise<AppStore> {
    this.assertWritable();
    const fingerprintValidation = validateSshServerFingerprint(input.expectedServerFingerprint);
    if (!fingerprintValidation.ok) {
      throw new Error(fingerprintValidation.message);
    }
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
    this.assertWritable();
    const existing = this.store.sshConfigs.find((config) => config.id === id);
    if (!existing) {
      return this.getStore();
    }

    this.store.sshConfigs = this.store.sshConfigs.filter((config) => config.id !== id);
    if (this.store.selectedConfigId === id) {
      this.store.selectedConfigId = this.store.sshConfigs[0]?.id;
    }

    await this.persistStore();
    await this.deleteSecretsIfUnreferenced([
      existing.passwordSecretId,
      existing.privateKeyPassphraseSecretId
    ]);
    return this.getStore();
  }

  async selectConfig(id: string): Promise<AppStore> {
    this.assertWritable();
    if (!this.store.sshConfigs.some((config) => config.id === id)) {
      throw new Error("SSH configuration does not exist.");
    }
    if (this.store.selectedConfigId === id) {
      return this.getStore();
    }
    this.store.selectedConfigId = id;
    await this.persistStore();
    return this.getStore();
  }

  async upsertKey(input: UpsertSshKeyInput): Promise<AppStore> {
    this.assertWritable();
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

    const secretsRevisionBefore = this.secretsRevision;
    const privateKeySecretId =
      normalizedPrivateKey !== undefined
        ? await this.saveSecret("private-key", normalizedPrivateKey, existing?.privateKeySecretId, false)
        : existing?.privateKeySecretId;
    const privateKeyPassphraseSecretId =
      input.privateKeyPassphrase !== undefined && input.privateKeyPassphrase.length > 0
        ? await this.saveSecret("private-key-passphrase", input.privateKeyPassphrase, existing?.privateKeyPassphraseSecretId, false)
        : existing?.privateKeyPassphraseSecretId;

    if (!privateKeySecretId) {
      throw new Error("Private key secret is missing.");
    }
    if (this.secretsRevision !== secretsRevisionBefore) {
      await this.persistSecrets();
    }

    const passphrase = input.privateKeyPassphrase || this.readSecretQuietly(privateKeyPassphraseSecretId);
    const metadata = normalizedPrivateKey !== undefined
      ? detectSshKeyMetadata(normalizedPrivateKey, passphrase)
      : existing && hasKnownKeyMetadata(existing)
        ? { keyType: existing.keyType, keyFormat: existing.keyFormat, encryptedOpenSsh: existing.encryptedOpenSsh }
        : this.detectStoredKeyMetadata(privateKeySecretId, passphrase);
    const key: SshKeyMetadata = {
      id: existing?.id ?? randomUUID(),
      name: input.name.trim(),
      privateKeySecretId,
      privateKeyPassphraseSecretId,
      fingerprint: normalizedPrivateKey ? fingerprintSecret(normalizedPrivateKey) : existing?.fingerprint ?? "",
      ...metadata,
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
    this.assertWritable();
    if (this.store.sshConfigs.some((config) => config.privateKeyId === id)) {
      throw new Error("This private key is used by at least one SSH configuration.");
    }

    const existing = this.store.sshKeys.find((key) => key.id === id);
    if (existing) {
      this.store.sshKeys = this.store.sshKeys.filter((key) => key.id !== id);
      await this.persistStore();
      await this.deleteSecretsIfUnreferenced([
        existing.privateKeySecretId,
        existing.privateKeyPassphraseSecretId
      ]);
    }

    return this.getStore();
  }

  async updateSettings(patch: Partial<AppSettings>): Promise<AppStore> {
    this.assertWritable();
    const checkEndpoint = patch.checkEndpoint?.trim();
    // Only a changed endpoint is checked: a settings patch may carry back an
    // endpoint saved before the rules got stricter, and that must not block
    // every other setting.
    if (checkEndpoint !== undefined && checkEndpoint !== this.store.settings.checkEndpoint) {
      const validation = validateCheckEndpoint(checkEndpoint);
      if (!validation.ok) {
        throw new Error(validation.message);
      }
    }
    const nextSettings: AppSettings = {
      ...this.store.settings,
      ...patch,
      ...(checkEndpoint !== undefined ? { checkEndpoint } : {}),
      customTheme: patch.customTheme
        ? { ...this.store.settings.customTheme, ...patch.customTheme }
        : this.store.settings.customTheme
    };
    if (isDeepStrictEqual(nextSettings, this.store.settings)) {
      return this.getStore();
    }
    this.store.settings = nextSettings;
    await this.persistStore();
    return this.getStore();
  }

  async updateRoutingMode(mode: RoutingMode): Promise<AppStore> {
    this.assertWritable();
    if (mode === this.store.routingMode) {
      return this.getStore();
    }
    this.store.routingMode = mode;
    await this.persistStore();
    return this.getStore();
  }

  async updateRoutingRules(rules: RoutingRule[]): Promise<AppStore> {
    this.assertWritable();
    if (!Array.isArray(rules) || rules.length > MAX_ROUTING_RULES) {
      throw new Error(`Routing rule count exceeds the ${MAX_ROUTING_RULES} rule limit.`);
    }
    if (isDeepStrictEqual(rules, this.store.routingRules)) {
      return this.getStore();
    }
    this.store.routingRules = rules;
    await this.persistStore();
    return this.getStore();
  }

  async updateRoutingProxyList(list: RoutingProxyList): Promise<AppStore> {
    this.assertWritable();
    const nextList: RoutingProxyList = {
      enabled: list.enabled,
      sourceUrl: list.sourceUrl.trim() || RUSSIA_INSIDE_PROXY_LIST_URL,
      domains: normalizeDomainList(list.domains),
      updatedAt: list.updatedAt
    };
    if (isDeepStrictEqual(nextList, this.store.routingProxyList)) {
      return this.getStore();
    }
    this.store.routingProxyList = nextList;
    await this.persistStore();
    return this.getStore();
  }

  async updateRoutingDirectList(list: RoutingDirectList): Promise<AppStore> {
    this.assertWritable();
    const nextList: RoutingDirectList = {
      enabled: list.enabled,
      sourceUrl: list.sourceUrl.trim() || RUSSIA_OUTSIDE_DIRECT_LIST_URL,
      domains: normalizeDomainList(list.domains),
      updatedAt: list.updatedAt
    };
    if (isDeepStrictEqual(nextList, this.store.routingDirectList)) {
      return this.getStore();
    }
    this.store.routingDirectList = nextList;
    await this.persistStore();
    return this.getStore();
  }

  async upsertProxyProfile(input: UpsertProxyProfileInput): Promise<AppStore> {
    this.assertWritable();
    const parsed = parseProxyShareLink(input.rawUri.trim());
    const now = new Date().toISOString();
    const existingById = input.id ? this.store.proxyProfiles.find((profile) => profile.id === input.id) : undefined;
    const existingByFingerprint = this.store.proxyProfiles.find((profile) => profile.fingerprint === parsed.fingerprint);
    const existing = existingById ?? existingByFingerprint;
    assertStoredProxyProfileCapacity(this.store.proxyProfiles.length, existing ? 0 : 1);
    const rawUriSecretId = await this.saveSecret("proxy-uri", parsed.rawUri, existing?.rawUriSecretId);
    const profile: ProxyProfile = {
      id: existing?.id ?? randomUUID(),
      name: input.name.trim() || parsed.name,
      protocol: parsed.protocol,
      host: parsed.host,
      port: parsed.port,
      // Built field by field, so a new link without a hop list or the insecure flag drops the stored one.
      ...(parsed.hopPorts ? { hopPorts: parsed.hopPorts } : {}),
      ...(parsed.insecureWithoutPin ? { insecureWithoutPin: true } : {}),
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
    this.assertWritable();
    const parsed = parseProxyShareLinks(input.text);
    const knownFingerprints = new Set(this.store.proxyProfiles.map((profile) => profile.fingerprint));
    let additionalProfiles = 0;
    for (const profile of parsed.profiles) {
      if (!knownFingerprints.has(profile.fingerprint)) {
        knownFingerprints.add(profile.fingerprint);
        additionalProfiles += 1;
      }
    }
    assertStoredProxyProfileCapacity(this.store.proxyProfiles.length, additionalProfiles);
    const now = new Date().toISOString();
    const secretsRevisionBefore = this.secretsRevision;
    const nextProfiles = [...this.store.proxyProfiles];
    const profilesByFingerprint = new Map(nextProfiles.map((profile) => [profile.fingerprint, profile]));
    const profileIndexById = new Map(nextProfiles.map((profile, index) => [profile.id, index]));
    let imported = 0;
    let updated = 0;

    for (const profileInput of parsed.profiles) {
      const existing = profilesByFingerprint.get(profileInput.fingerprint);
      const rawUriSecretId = await this.saveSecret("proxy-uri", profileInput.rawUri, existing?.rawUriSecretId, false);
      const profile: ProxyProfile = {
        id: existing?.id ?? randomUUID(),
        name: existing?.name || profileInput.name,
        protocol: profileInput.protocol,
        host: profileInput.host,
        port: profileInput.port,
        ...(profileInput.hopPorts ? { hopPorts: profileInput.hopPorts } : {}),
        ...(profileInput.insecureWithoutPin ? { insecureWithoutPin: true } : {}),
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
        const index = profileIndexById.get(existing.id);
        if (index !== undefined) {
          nextProfiles[index] = profile;
        }
      } else {
        imported += 1;
        profileIndexById.set(profile.id, nextProfiles.length);
        nextProfiles.push(profile);
      }
      profilesByFingerprint.set(profile.fingerprint, profile);
    }

    this.store.proxyProfiles = nextProfiles;

    if (input.source === "remote" && input.sourceUrl) {
      const fingerprints = new Set(parsed.profiles.map((profile) => profile.fingerprint));
      this.store.proxyProfiles = this.store.proxyProfiles.map((profile) =>
        profile.source === "remote" && profile.sourceUrl === input.sourceUrl && !fingerprints.has(profile.fingerprint)
          ? { ...profile, isStale: true, updatedAt: now }
          : profile
      );
      // Kept apart from the profiles, which "Remove unpinned" can delete.
      this.store.publicProxyRefresh = { at: now, listed: fingerprints.size };
    }

    if (this.secretsRevision !== secretsRevisionBefore) {
      await this.persistSecrets();
    }
    this.ensureProxySelection();
    await this.persistStore();
    const result: ImportProxyProfilesResult = {
      imported,
      updated,
      skipped: parsed.skipped,
      failed: parsed.errors.length,
      errors: parsed.errors.slice(0, MAX_IMPORT_ERRORS_RETURNED)
    };
    return { store: this.getStore(), result };
  }

  async selectProxyProfile(id: string): Promise<AppStore> {
    this.assertWritable();
    const profile = this.store.proxyProfiles.find((candidate) => candidate.id === id);
    if (!profile) {
      throw new Error("Proxy profile does not exist.");
    }
    if (!isSupportedProxyProfile(profile)) {
      throw new Error(UNSUPPORTED_PROXY_PROFILE_MESSAGE);
    }
    if (this.store.selectedProxyProfileId === id) {
      return this.getStore();
    }
    this.store.selectedProxyProfileId = id;
    this.store.proxyProfiles = this.store.proxyProfiles.map((candidate) => ({ ...candidate, isSelected: candidate.id === id }));
    await this.persistStore();
    return this.getStore();
  }

  async toggleProxyProfilePin(id: string): Promise<AppStore> {
    this.assertWritable();
    if (!this.store.proxyProfiles.some((profile) => profile.id === id)) {
      return this.getStore();
    }
    this.store.proxyProfiles = this.store.proxyProfiles.map((profile) =>
      profile.id === id ? { ...profile, isPinned: !profile.isPinned, updatedAt: new Date().toISOString() } : profile
    );
    await this.persistStore();
    return this.getStore();
  }

  /**
   * Changes only the name: the link, its fingerprint and its source stay as
   * imported, so a refresh of its list still finds the profile (and keeps the
   * name). A blank name brings back the one import gave the link.
   */
  async renameProxyProfile(id: string, name: string): Promise<AppStore> {
    this.assertWritable();
    if (typeof id !== "string" || typeof name !== "string") {
      throw new Error("Proxy profile name is invalid.");
    }
    const existing = this.store.proxyProfiles.find((profile) => profile.id === id);
    if (!existing) {
      throw new Error("Proxy profile does not exist.");
    }
    const nextName = normalizeProxyProfileName(name) || this.linkProfileName(existing);
    if (nextName === existing.name) {
      return this.getStore();
    }
    this.store.proxyProfiles = this.store.proxyProfiles.map((profile) =>
      profile.id === id ? { ...profile, name: nextName, updatedAt: new Date().toISOString() } : profile
    );
    await this.persistStore();
    return this.getStore();
  }

  async deleteProxyProfile(id: string): Promise<AppStore> {
    this.assertWritable();
    const existing = this.store.proxyProfiles.find((profile) => profile.id === id);
    if (!existing) {
      return this.getStore();
    }
    this.store.proxyProfiles = this.store.proxyProfiles.filter((profile) => profile.id !== id);
    this.ensureProxySelection();
    await this.persistStore();
    await this.deleteSecretsIfUnreferenced([existing.rawUriSecretId]);
    return this.getStore();
  }

  async deleteUnpinnedProxyProfiles(): Promise<AppStore> {
    this.assertWritable();
    const deleted = this.store.proxyProfiles.filter((profile) => !profile.isPinned);
    if (deleted.length === 0) {
      return this.getStore();
    }
    this.store.proxyProfiles = this.store.proxyProfiles.filter((profile) => profile.isPinned);
    this.ensureProxySelection();
    await this.persistStore();
    await this.deleteSecretsIfUnreferenced(deleted.map((profile) => profile.rawUriSecretId));
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

  /** The profile's link with its current name written in, for main-process clipboard copy. */
  readProxyProfileShareLink(id: string): string {
    const profile = this.store.proxyProfiles.find((candidate) => candidate.id === id);
    if (!profile) {
      throw new Error("Proxy profile does not exist.");
    }
    const rawUri = this.resolveProxySecrets(profile).rawUri;
    try {
      return withShareLinkName(rawUri, profile.name);
    } catch {
      // The link as saved still connects; only its name differs.
      return rawUri;
    }
  }

  /**
   * The name import gives the saved link, unchanged (so Copy link hands back
   * the link as saved), or the parser's protocol-host:port when the link has
   * none or can't be read (a keychain reset, an app folder moved).
   */
  private linkProfileName(profile: ProxyProfile): string {
    const fallback = `${profile.protocol}-${profile.host}:${profile.port}`;
    try {
      return parseProxyShareLink(this.resolveProxySecrets(profile).rawUri).name || fallback;
    } catch {
      return fallback;
    }
  }

  private async saveSecret(kind: SecretKind, value: string, existingId?: string, persist = true): Promise<string> {
    const id = existingId ?? randomUUID();
    const existing = this.secrets.secrets[id];
    if (existing?.kind === kind && this.secretMatches(existing, value)) {
      return id;
    }
    const now = new Date().toISOString();
    const encrypted = encryptSecret(value, this.dataDir);
    const nextRecord: SecretRecord = {
      id,
      kind,
      backend: encrypted.backend,
      ciphertext: encrypted.ciphertext,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    };
    this.secrets.secrets[id] = nextRecord;
    this.secretsRevision += 1;
    if (persist) {
      try {
        await this.persistSecrets();
      } catch (error) {
        // A rejected size preflight must not leave the current session holding
        // a secret that was never made durable. Do not overwrite a newer
        // concurrent update to the same record.
        if (this.secrets.secrets[id] === nextRecord) {
          if (existing) {
            this.secrets.secrets[id] = existing;
          } else {
            delete this.secrets.secrets[id];
          }
          this.secretsRevision += 1;
        }
        throw error;
      }
    }
    return id;
  }

  private secretMatches(record: SecretRecord, value: string): boolean {
    try {
      return decryptSecretForService(record, this.dataDir) === value;
    } catch {
      // A backend change can make an old record unreadable. Saving the newly
      // supplied value below is the recovery path, so equality is best-effort.
      return false;
    }
  }

  private async deleteSecretsIfUnreferenced(ids: Array<string | undefined>): Promise<void> {
    const referenced = this.referencedSecretIds();
    let changed = false;
    for (const id of new Set(ids.filter((candidate): candidate is string => Boolean(candidate)))) {
      if (!referenced.has(id) && this.secrets.secrets[id]) {
        delete this.secrets.secrets[id];
        this.secretsRevision += 1;
        changed = true;
      }
    }
    if (changed) {
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

  private migrateConfigPassphrasesToKeys(): { secretsChanged: boolean } {
    const usedPassphraseSecretIds = new Set<string>();
    let secretsChanged = false;
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
      if (!usedPassphraseSecretIds.has(config.privateKeyPassphraseSecretId) && this.secrets.secrets[config.privateKeyPassphraseSecretId]) {
        delete this.secrets.secrets[config.privateKeyPassphraseSecretId];
        this.secretsRevision += 1;
        secretsChanged = true;
      }
      return { ...config, privateKeyPassphraseSecretId: undefined };
    });
    return { secretsChanged };
  }

  private ensureProxySelection(): void {
    let firstSelectableId: string | undefined;
    let selectedExists = false;
    for (const profile of this.store.proxyProfiles) {
      // Neither a profile gone from its source nor one Xray cannot run is a
      // useful automatic pick: Connect would fail on it straight away.
      if (profile.isStale || !isSupportedProxyProfile(profile)) {
        continue;
      }
      firstSelectableId ??= profile.id;
      selectedExists ||= profile.id === this.store.selectedProxyProfileId;
    }
    const selectedId = selectedExists ? this.store.selectedProxyProfileId : firstSelectableId;
    this.store.selectedProxyProfileId = selectedId;
    if (this.store.proxyProfiles.some((profile) => profile.isSelected !== (Boolean(selectedId) && profile.id === selectedId))) {
      this.store.proxyProfiles = this.store.proxyProfiles.map((profile) => ({
        ...profile,
        isSelected: Boolean(selectedId) && profile.id === selectedId
      }));
    }
  }

  private removeOrphanedSecrets(): boolean {
    const referenced = this.referencedSecretIds();
    let changed = false;
    for (const id of Object.keys(this.secrets.secrets)) {
      if (!referenced.has(id)) {
        delete this.secrets.secrets[id];
        this.secretsRevision += 1;
        changed = true;
      }
    }
    return changed;
  }

  private referencedSecretIds(): Set<string> {
    const referenced = new Set<string>();
    for (const config of this.store.sshConfigs) {
      if (config.passwordSecretId) {
        referenced.add(config.passwordSecretId);
      }
      if (config.privateKeyPassphraseSecretId) {
        referenced.add(config.privateKeyPassphraseSecretId);
      }
    }
    for (const key of this.store.sshKeys) {
      referenced.add(key.privateKeySecretId);
      if (key.privateKeyPassphraseSecretId) {
        referenced.add(key.privateKeyPassphraseSecretId);
      }
    }
    for (const profile of this.store.proxyProfiles) {
      referenced.add(profile.rawUriSecretId);
    }
    return referenced;
  }

  private assertWritable(): void {
    if (!this.initialized) {
      throw new Error(STORAGE_WRITE_BLOCKED_MESSAGE);
    }
  }

  private readSecretQuietly(id: string | undefined): string | undefined {
    if (!id) {
      return undefined;
    }
    try {
      return this.readSecret(id);
    } catch {
      return undefined;
    }
  }

  private detectStoredKeyMetadata(
    privateKeySecretId: string,
    passphrase: string | undefined
  ): Partial<Pick<SshKeyMetadata, "keyType" | "keyFormat" | "encryptedOpenSsh">> {
    const privateKey = this.readSecretQuietly(privateKeySecretId);
    return privateKey === undefined ? {} : detectSshKeyMetadata(privateKey, passphrase);
  }

  /**
   * Keys saved before their type was recorded get it on the first start that
   * can decrypt them. A key that cannot be decrypted right now is left alone
   * and tried again next time.
   */
  private backfillKeyMetadata(): void {
    if (!this.store.sshKeys.some((key) => key.keyType === undefined)) {
      return;
    }
    this.store.sshKeys = this.store.sshKeys.map((key) => {
      if (key.keyType !== undefined) {
        return key;
      }
      const metadata = this.detectStoredKeyMetadata(
        key.privateKeySecretId,
        this.readSecretQuietly(key.privateKeyPassphraseSecretId)
      );
      return metadata.keyType === undefined ? key : { ...key, ...metadata };
    });
  }

  private async persistStore(): Promise<void> {
    await this.storeWriter.write(this.store);
  }

  private async persistSecrets(): Promise<void> {
    await this.secretsWriter.write(this.secrets);
  }
}

function normalizeStore(input: AppStore): AppStore {
  if (!isPlainObject(input)) {
    throw new Error("Application store has an unexpected format.");
  }
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
  // A store from before the schema knew about tunnel-adapter capture cannot
  // have a meaningful value for it, so the default applies instead of the
  // stored one. Only this one field is reset; everything else is preserved.
  const storedSchemaVersion = typeof input.schemaVersion === "number" ? input.schemaVersion : 0;
  const tunDataplaneEnabled = storedSchemaVersion >= 2 && typeof inputSettings.tunDataplaneEnabled === "boolean"
    ? inputSettings.tunDataplaneEnabled
    : defaults.settings.tunDataplaneEnabled;
  // Xray 26 removed the HTTP/2 transport, so a profile saved with it can no
  // longer run; "unknown" marks it unsupported, as the parsers now do. Profiles
  // from a former public list URL move to the current one, or a refresh would
  // never mark the ones that left the list stale.
  const proxyProfiles = (Array.isArray(input.proxyProfiles) ? input.proxyProfiles : []).map((profile) => {
    if (typeof profile !== "object" || profile === null) {
      return profile;
    }
    let migrated = profile.transport === "http" ? { ...profile, transport: "unknown" as const } : profile;
    if (migrated.sourceUrl && LEGACY_PUBLIC_PROXY_LIST_URLS.includes(migrated.sourceUrl)) {
      migrated = { ...migrated, sourceUrl: PUBLIC_PROXY_LIST_URL };
    }
    return migrated;
  });
  assertStoredProxyProfileCapacity(proxyProfiles.length, 0);
  const routingRules = Array.isArray(input.routingRules) ? input.routingRules : [];
  if (routingRules.length > MAX_ROUTING_RULES) {
    throw new Error(`Routing rule count exceeds the ${MAX_ROUTING_RULES} rule limit.`);
  }
  return {
    ...defaults,
    ...input,
    schemaVersion: STORE_SCHEMA_VERSION,
    settings: {
      ...defaults.settings,
      ...inputSettings,
      activeGlobalTab,
      lastConnectedTransport,
      releaseRendererInTrayEnabled:
        typeof inputSettings.releaseRendererInTrayEnabled === "boolean"
          ? inputSettings.releaseRendererInTrayEnabled
          : defaults.settings.releaseRendererInTrayEnabled,
      xrayConsentAccepted: inputSettings.xrayConsentAccepted ?? inputSettings.openSourceConsentAccepted ?? defaults.settings.xrayConsentAccepted,
      showXrayWarningOnEnter: inputSettings.showXrayWarningOnEnter ?? inputSettings.showOpenSourceWarningOnEnter ?? defaults.settings.showXrayWarningOnEnter,
      xrayRiskBannerExpanded: inputSettings.xrayRiskBannerExpanded ?? inputSettings.openSourceRiskBannerExpanded ?? defaults.settings.xrayRiskBannerExpanded,
      tunDataplaneEnabled,
      notifyTunnelChanges: booleanOr(inputSettings.notifyTunnelChanges, defaults.settings.notifyTunnelChanges),
      notifyUpdateDownloaded: booleanOr(inputSettings.notifyUpdateDownloaded, defaults.settings.notifyUpdateDownloaded),
      notifyStillRunningInTray: booleanOr(inputSettings.notifyStillRunningInTray, defaults.settings.notifyStillRunningInTray),
      notifyOnlyWhenHidden: booleanOr(inputSettings.notifyOnlyWhenHidden, defaults.settings.notifyOnlyWhenHidden),
      stillRunningNoticeShown: booleanOr(inputSettings.stillRunningNoticeShown, defaults.settings.stillRunningNoticeShown),
      customTheme: migrateSignalColors(
        {
          ...defaults.settings.customTheme,
          ...inputSettings.customTheme
        },
        storedSchemaVersion
      )
    },
    sshConfigs: Array.isArray(input.sshConfigs) ? input.sshConfigs : [],
    sshKeys: Array.isArray(input.sshKeys) ? input.sshKeys : [],
    proxyProfiles,
    selectedProxyProfileId: input.selectedProxyProfileId,
    routingRules,
    routingProxyList: normalizeRoutingProxyList(input.routingProxyList ?? (input as AppStore & { routingBypassList?: unknown }).routingBypassList, defaults.routingProxyList),
    routingDirectList: normalizeRoutingDirectList(input.routingDirectList, defaults.routingDirectList),
    publicProxyRefresh: normalizePublicProxyRefresh(input.publicProxyRefresh)
  };
}

function normalizePublicProxyRefresh(value: unknown): AppStore["publicProxyRefresh"] {
  if (!isPlainObject(value)) {
    return undefined;
  }
  const { at, listed } = value as { at?: unknown; listed?: unknown };
  if (typeof at !== "string" || !Number.isFinite(Date.parse(at)) || typeof listed !== "number" || !Number.isInteger(listed) || listed < 0) {
    return undefined;
  }
  return { at, listed };
}

/**
 * Version 3 replaced the default signal colours. A store that still holds the
 * old defaults never chose them, so it follows the new palette; any colour the
 * user picked is kept as it is.
 */
function migrateSignalColors(theme: CustomTheme, storedSchemaVersion: number): CustomTheme {
  if (storedSchemaVersion >= 3) {
    return theme;
  }
  const migrated = { ...theme };
  for (const name of ["accent", "success", "danger"] as const) {
    if (isDeepStrictEqual(theme[name], LEGACY_DEFAULT_SIGNAL_COLORS[name])) {
      migrated[name] = { ...DEFAULT_CUSTOM_THEME[name] };
    }
  }
  return migrated;
}

function booleanOr(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeSecretStore(input: SecretStore): SecretStore {
  if (!isPlainObject(input) || !isPlainObject(input.secrets)) {
    throw new Error("Secret store has an unexpected format.");
  }
  return input;
}

function hasKnownKeyMetadata(key: SshKeyMetadata): boolean {
  return key.keyType !== undefined && key.keyType !== "unknown";
}

/** Xray cannot run a profile whose security mode or transport the parser did not recognise. */
export function isSupportedProxyProfile(profile: Pick<ProxyProfile, "security" | "transport">): boolean {
  return profile.security !== "unknown" && profile.transport !== "unknown";
}

/** Local time, because the user reads it next to the file's own timestamps. */
function formatBackupTimestamp(date: Date): string {
  const pad = (value: number): string => String(value).padStart(2, "0");
  return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
}

/** Renames `filePath` to `<name>.<label>-<stamp>.json`; undefined when there is no file to move. */
async function moveAside(filePath: string, label: "unreadable" | "orphaned", stamp: string): Promise<string | undefined> {
  const parsed = path.parse(filePath);
  for (let attempt = 1; attempt <= 100; attempt += 1) {
    const suffix = attempt === 1 ? "" : `-${attempt}`;
    const backupPath = path.join(parsed.dir, `${parsed.name}.${label}-${stamp}${suffix}${parsed.ext || ".json"}`);
    if (await pathExists(backupPath)) {
      continue;
    }
    try {
      await rename(filePath, backupPath);
      return backupPath;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return undefined;
      }
      throw error;
    }
  }
  throw new Error(`Could not find a free backup name for ${parsed.base}.`);
}

async function pathExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
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
  const domains = new Set<string>();
  for (const value of input) {
    if (typeof value !== "string") {
      continue;
    }
    const domain = value.trim().toLowerCase();
    if (!domain) {
      continue;
    }
    domains.add(domain);
    if (domains.size > MAX_ROUTING_DOMAINS) {
      throw new Error(`Routing domain list exceeds the ${MAX_ROUTING_DOMAINS} domain limit.`);
    }
  }
  return [...domains].sort((left, right) => left.localeCompare(right));
}

function encryptSecret(value: string, dataDir: string): Pick<SecretRecord, "backend" | "ciphertext"> {
  const insecureFallbackAllowed = process.env.SHADOW_SSH_ALLOW_INSECURE_SECRET_FALLBACK === "1";
  const selectedBackend = process.platform === "linux" ? safeStorage.getSelectedStorageBackend?.() : undefined;
  if (isSafeStorageBackendUsable(safeStorage.isEncryptionAvailable(), process.platform, selectedBackend, insecureFallbackAllowed)) {
    return {
      backend: "electron-safe-storage",
      ciphertext: safeStorage.encryptString(value).toString("base64")
    };
  }

  if (isProductionSecretStorageRuntime(app.isPackaged, process.env.NODE_ENV) && !insecureFallbackAllowed) {
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

export function isSafeStorageBackendUsable(
  encryptionAvailable: boolean,
  platform: NodeJS.Platform,
  selectedBackend: string | undefined,
  insecureFallbackAllowed: boolean
): boolean {
  if (!encryptionAvailable) {
    return false;
  }
  return platform !== "linux" || selectedBackend !== "basic_text" || insecureFallbackAllowed;
}

export function isProductionSecretStorageRuntime(isPackaged: boolean | undefined, nodeEnv: string | undefined): boolean {
  // NODE_ENV is a build-process environment variable and is normally absent
  // when a packaged Electron executable is launched later by the user.
  return isPackaged === true || nodeEnv === "production";
}

export function decryptSecretForService(record: SecretRecord, dataDir: string): string {
  const insecureFallbackAllowed = process.env.SHADOW_SSH_ALLOW_INSECURE_SECRET_FALLBACK === "1";
  const productionRuntime = isProductionSecretStorageRuntime(app.isPackaged, process.env.NODE_ENV);
  if (record.backend === "electron-safe-storage") {
    const selectedBackend = process.platform === "linux" ? safeStorage.getSelectedStorageBackend?.() : undefined;
    if (
      productionRuntime &&
      !isSafeStorageBackendUsable(safeStorage.isEncryptionAvailable(), process.platform, selectedBackend, insecureFallbackAllowed)
    ) {
      throw new Error("Secure storage is unavailable in production.");
    }
    return safeStorage.decryptString(Buffer.from(record.ciphertext, "base64"));
  }

  if (productionRuntime && !insecureFallbackAllowed) {
    throw new Error("Refusing to decrypt a development fallback secret in production.");
  }

  const [ivRaw, tagRaw, encryptedRaw] = record.ciphertext.split(".");
  if (!ivRaw || !tagRaw || !encryptedRaw) {
    throw new Error("Invalid encrypted secret payload.");
  }

  const decipher = createDecipheriv("aes-256-gcm", createFallbackKey(dataDir), Buffer.from(ivRaw, "base64"));
  decipher.setAuthTag(Buffer.from(tagRaw, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(encryptedRaw, "base64")), decipher.final()]).toString("utf8");
}

async function readJsonWithStatus<T>(
  filePath: string,
  fallback: T,
  maxBytes: number,
  label: string
): Promise<{ value: T; exists: boolean }> {
  try {
    return { value: await readJsonFileWithLimit<T>(filePath, maxBytes, label), exists: true };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { value: fallback, exists: false };
    }
    throw error;
  }
}

export async function readJsonFileWithLimit<T>(filePath: string, maxBytes: number, label = "JSON file"): Promise<T> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new Error(`${label} byte limit is invalid.`);
  }
  const handle = await open(filePath, "r");
  try {
    const info = await handle.stat();
    if (!info.isFile()) {
      throw new Error(`${label} is not a regular file.`);
    }
    if (info.size > maxBytes) {
      throw new Error(`${label} exceeds the ${maxBytes} byte limit.`);
    }
    const contents = Buffer.allocUnsafe(info.size);
    let offset = 0;
    while (offset < contents.length) {
      const { bytesRead } = await handle.read(contents, offset, contents.length - offset, offset);
      if (bytesRead <= 0) {
        break;
      }
      offset += bytesRead;
    }
    return JSON.parse(contents.subarray(0, offset).toString("utf8")) as T;
  } finally {
    await handle.close();
  }
}

export function assertStoredProxyProfileCapacity(currentCount: number, additionalCount: number): void {
  if (
    !Number.isSafeInteger(currentCount) ||
    !Number.isSafeInteger(additionalCount) ||
    currentCount < 0 ||
    additionalCount < 0 ||
    currentCount + additionalCount > MAX_STORED_PROXY_PROFILES
  ) {
    throw new Error(`Proxy profile count exceeds the ${MAX_STORED_PROXY_PROFILES} profile limit.`);
  }
}

export async function writeJsonAtomic(filePath: string, value: unknown): Promise<void> {
  await writeJsonTextAtomic(filePath, serializeJson(value));
}

async function writeJsonTextAtomic(filePath: string, serialized: string): Promise<void> {
  const tmpPath = `${filePath}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(tmpPath, serialized, { encoding: "utf8", mode: 0o600, flag: "wx" });
    await rename(tmpPath, filePath);
    await chmod(filePath, 0o600);
  } catch (error) {
    await rm(tmpPath, { force: true }).catch(() => undefined);
    throw error;
  }
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function areJsonValuesEqual(left: unknown, right: unknown): boolean {
  if (left === right) {
    return true;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length
      && left.every((value, index) => areJsonValuesEqual(value, right[index]));
  }
  if (!left || !right || typeof left !== "object" || typeof right !== "object") {
    return false;
  }
  const leftRecord = left as Record<string, unknown>;
  const rightRecord = right as Record<string, unknown>;
  const leftKeys = Object.keys(leftRecord).filter((key) => leftRecord[key] !== undefined);
  const rightKeys = Object.keys(rightRecord).filter((key) => rightRecord[key] !== undefined);
  return leftKeys.length === rightKeys.length
    && leftKeys.every((key) => Object.hasOwn(rightRecord, key) && rightRecord[key] !== undefined
      && areJsonValuesEqual(leftRecord[key], rightRecord[key]));
}

interface PendingAtomicJsonWrite {
  serialized: string;
  waiters: Array<{
    resolve: () => void;
    reject: (error: unknown) => void;
  }>;
}

export interface CoalescingAtomicJsonWriterOptions {
  maxBytes?: number;
  label?: string;
}

/**
 * Captures JSON synchronously, then collapses only writes that are already
 * waiting behind an active atomic replace. Every caller resolves after a file
 * version containing state at least as new as its own mutation is durable.
 */
export class CoalescingAtomicJsonWriter {
  private active = false;
  private pending: PendingAtomicJsonWrite | undefined;
  private draining: Promise<void> | undefined;

  constructor(
    private readonly filePath: string,
    private readonly writeAtomic: (filePath: string, serialized: string) => Promise<void> = writeJsonTextAtomic,
    private readonly options: CoalescingAtomicJsonWriterOptions = {}
  ) {}

  write(value: unknown): Promise<void> {
    const serialized = serializeJson(value);
    if (this.options.maxBytes !== undefined) {
      assertSerializedJsonWithinLimit(serialized, this.options.maxBytes, this.options.label ?? "JSON file");
    }
    return new Promise<void>((resolve, reject) => {
      if (this.pending) {
        this.pending.serialized = serialized;
        this.pending.waiters.push({ resolve, reject });
      } else {
        this.pending = { serialized, waiters: [{ resolve, reject }] };
      }
      if (!this.active) {
        this.active = true;
        this.draining = this.drain();
      }
    });
  }

  /** Resolves once no write is queued or in flight. Never rejects. */
  async settled(): Promise<void> {
    while (this.draining) {
      await this.draining;
    }
  }

  private async drain(): Promise<void> {
    try {
      while (this.pending) {
        const batch = this.pending;
        this.pending = undefined;
        try {
          await this.writeAtomic(this.filePath, batch.serialized);
          for (const waiter of batch.waiters) {
            waiter.resolve();
          }
        } catch (error) {
          for (const waiter of batch.waiters) {
            waiter.reject(error);
          }
        }
      }
    } finally {
      this.active = false;
      this.draining = undefined;
      // No await occurs between the last pending check and this assignment,
      // but keep this guard so a future refactor cannot strand a queued write.
      if (this.pending) {
        this.active = true;
        this.draining = this.drain();
      }
    }
  }
}

export function assertSerializedJsonWithinLimit(serialized: string, maxBytes: number, label = "JSON file"): void {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new Error(`${label} byte limit is invalid.`);
  }
  const bytes = Buffer.byteLength(serialized, "utf8");
  if (bytes > maxBytes) {
    throw new Error(`${label} exceeds the ${maxBytes} byte limit.`);
  }
}

async function ensurePrivateFileMode(filePath: string): Promise<void> {
  if (process.platform === "win32") {
    return;
  }
  const info = await stat(filePath);
  if ((info.mode & 0o777) !== 0o600) {
    await chmod(filePath, 0o600);
  }
}

function createFallbackKey(dataDir: string): Buffer {
  const username = os.userInfo().username;
  return createHash("sha256").update(`shadow-ssh:${dataDir}:${os.hostname()}:${username}`).digest();
}

function fingerprintSecret(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("base64").slice(0, 43)}`;
}
