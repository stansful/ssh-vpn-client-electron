import { app, safeStorage } from "electron";
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { chmod, mkdir, open, rename, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { parseProxyShareLink, parseProxyShareLinks } from "../../core/proxy/share-link-parser.js";
import { assertSshPrivateKeyText, normalizeSshPrivateKeyText } from "../../core/ssh/private-key.js";
import { createDefaultStore, RUSSIA_INSIDE_PROXY_LIST_URL, RUSSIA_OUTSIDE_DIRECT_LIST_URL, STORE_SCHEMA_VERSION } from "../../shared/defaults.js";
import { validateSshServerFingerprint } from "../../shared/validation.js";
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

const MAX_ROUTING_RULES = 10_000;
const MAX_ROUTING_DOMAINS = 20_000;
export const MAX_STORED_PROXY_PROFILES = 10_000;
const MAX_APP_STORE_FILE_BYTES = 32 * 1024 * 1024;
const MAX_SECRET_STORE_FILE_BYTES = 64 * 1024 * 1024;

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
  private secretsRevision = 0;
  private readonly storeWriter: CoalescingAtomicJsonWriter;
  private readonly secretsWriter: CoalescingAtomicJsonWriter;

  constructor(dataDir = path.join(app.getPath("userData"), "storage")) {
    this.dataDir = dataDir;
    this.storePath = path.join(dataDir, "app-store.v1.json");
    this.secretPath = path.join(dataDir, "secret-store.v1.json");
    this.storeWriter = new CoalescingAtomicJsonWriter(this.storePath, writeJsonTextAtomic, {
      maxBytes: MAX_APP_STORE_FILE_BYTES,
      label: "Application store"
    });
    this.secretsWriter = new CoalescingAtomicJsonWriter(this.secretPath, writeJsonTextAtomic, {
      maxBytes: MAX_SECRET_STORE_FILE_BYTES,
      label: "Secret store"
    });
  }

  async init(): Promise<void> {
    await mkdir(this.dataDir, { recursive: true });
    const storedStore = await readJsonWithStatus<AppStore>(
      this.storePath,
      createDefaultStore(),
      MAX_APP_STORE_FILE_BYTES,
      "Application store"
    );
    const storedSecrets = await readJsonWithStatus<SecretStore>(
      this.secretPath,
      { schemaVersion: 1, secrets: {} },
      MAX_SECRET_STORE_FILE_BYTES,
      "Secret store"
    );
    this.store = normalizeStore(storedStore.value);
    this.secrets = storedSecrets.value;
    const migration = this.migrateConfigPassphrasesToKeys();
    this.ensureProxySelection();
    const removedOrphanedSecrets = this.removeOrphanedSecrets();

    if (!storedStore.exists || !areJsonValuesEqual(storedStore.value, this.store)) {
      await this.persistStore();
    } else {
      await ensurePrivateFileMode(this.storePath);
    }
    if (!storedSecrets.exists || migration.secretsChanged || removedOrphanedSecrets) {
      await this.persistSecrets();
    } else {
      await ensurePrivateFileMode(this.secretPath);
    }
  }

  getStore(): AppStore {
    return structuredClone(this.store);
  }

  /** Returns only the small settings branch without cloning large profile/rule lists. */
  getSettings(): AppSettings {
    return structuredClone(this.store.settings);
  }

  async upsertConfig(input: UpsertSshConfigInput): Promise<AppStore> {
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
      await this.persistStore();
      await this.deleteSecretsIfUnreferenced([
        existing.privateKeySecretId,
        existing.privateKeyPassphraseSecretId
      ]);
    }

    return this.getStore();
  }

  async updateSettings(patch: Partial<AppSettings>): Promise<AppStore> {
    const nextSettings: AppSettings = {
      ...this.store.settings,
      ...patch,
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
    if (mode === this.store.routingMode) {
      return this.getStore();
    }
    this.store.routingMode = mode;
    await this.persistStore();
    return this.getStore();
  }

  async updateRoutingRules(rules: RoutingRule[]): Promise<AppStore> {
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
      errors: parsed.errors.slice(0, 20)
    };
    return { store: this.getStore(), result };
  }

  async selectProxyProfile(id: string): Promise<AppStore> {
    if (!this.store.proxyProfiles.some((profile) => profile.id === id)) {
      throw new Error("Proxy profile does not exist.");
    }
    if (this.store.selectedProxyProfileId === id) {
      return this.getStore();
    }
    this.store.selectedProxyProfileId = id;
    this.store.proxyProfiles = this.store.proxyProfiles.map((profile) => ({ ...profile, isSelected: profile.id === id }));
    await this.persistStore();
    return this.getStore();
  }

  async toggleProxyProfilePin(id: string): Promise<AppStore> {
    if (!this.store.proxyProfiles.some((profile) => profile.id === id)) {
      return this.getStore();
    }
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
    this.ensureProxySelection();
    await this.persistStore();
    await this.deleteSecretsIfUnreferenced([existing.rawUriSecretId]);
    return this.getStore();
  }

  async deleteUnpinnedProxyProfiles(): Promise<AppStore> {
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
      if (profile.isStale) {
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

  private async persistStore(): Promise<void> {
    await this.storeWriter.write(this.store);
  }

  private async persistSecrets(): Promise<void> {
    await this.secretsWriter.write(this.secrets);
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
  const proxyProfiles = Array.isArray(input.proxyProfiles) ? input.proxyProfiles : [];
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
      customTheme: {
        ...defaults.settings.customTheme,
        ...inputSettings.customTheme
      }
    },
    sshConfigs: Array.isArray(input.sshConfigs) ? input.sshConfigs : [],
    sshKeys: Array.isArray(input.sshKeys) ? input.sshKeys : [],
    proxyProfiles,
    selectedProxyProfileId: input.selectedProxyProfileId,
    routingRules,
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
        void this.drain();
      }
    });
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
      // No await occurs between the last pending check and this assignment,
      // but keep this guard so a future refactor cannot strand a queued write.
      if (this.pending) {
        this.active = true;
        void this.drain();
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
