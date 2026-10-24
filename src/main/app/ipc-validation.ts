import { canonicalIpRuleValue, validateCheckEndpoint, validateRoutingRuleValue } from "../../shared/validation.js";
import type {
  AppSettings,
  AuthType,
  CustomTheme,
  GlobalTab,
  ImportProxyProfilesInput,
  ProxyProfileSource,
  RgbColor,
  RoutingMode,
  RoutingRule,
  RoutingRuleType,
  ThemeMode,
  UpsertSshConfigInput
} from "../../shared/types.js";

/**
 * Checks what the renderer sends before it reaches storage or a service.
 * The renderer is trusted only as far as the IPC gate goes, so its input
 * still gets the shape, enum and range checks the forms already make; every
 * parser throws an Error with a readable message, or returns a clean copy
 * holding only the fields it knows.
 */

export const MAX_ROUTING_RULES = 10_000;
export const MIN_KEEPALIVE_SEC = 60;
export const MAX_KEEPALIVE_SEC = 3600;
const MAX_ID_LENGTH = 256;
const MAX_NAME_LENGTH = 256;
const MAX_HOST_LENGTH = 255;
const MAX_SECRET_LENGTH = 64 * 1024;
const MAX_NOTE_LENGTH = 64 * 1024;
const MAX_IMPORT_TEXT_LENGTH = 32 * 1024 * 1024;
const MAX_URL_LENGTH = 8 * 1024;
const MAX_RULE_VALUE_LENGTH = 1024;
const MAX_TIMESTAMP_LENGTH = 64;

const ROUTING_MODES: readonly RoutingMode[] = ["proxy-all", "selected-rules"];
const ROUTING_RULE_TYPES: readonly RoutingRuleType[] = ["domain", "ip", "process.name"];
const AUTH_TYPES: readonly AuthType[] = ["password", "private-key"];
const THEME_MODES: readonly ThemeMode[] = ["system", "light", "dark", "custom"];
const GLOBAL_TABS: readonly GlobalTab[] = ["ssh", "xray"];
const PROXY_PROFILE_SOURCES: readonly ProxyProfileSource[] = ["manual", "clipboard", "remote"];
const CUSTOM_THEME_COLOURS: ReadonlyArray<keyof CustomTheme> = ["accent", "success", "danger", "background", "surface", "text", "muted", "border"];

type SettingsPatch = Partial<AppSettings>;

/**
 * The settings the renderer may change. `updateCheckCache` belongs to the
 * update checker in main and is not here; `stillRunningNoticeShown` is set by
 * main but harmless to send back.
 */
const SETTINGS_FIELDS: { [K in keyof AppSettings]?: (value: unknown, key: string) => AppSettings[K] } = {
  theme: (value, key) => oneOf(value, THEME_MODES, key),
  customTheme: (value, key) => parseCustomThemePatch(value, key) as CustomTheme,
  diagnosticsExpanded: booleanField,
  terminalExpanded: booleanField,
  // Its format is checked by storage, and only when it changes.
  checkEndpoint: (value, key) => stringField(value, key, MAX_HOST_LENGTH + 8),
  loggingEnabled: booleanField,
  diagnosticsLoggingEnabled: booleanField,
  fileLoggingEnabled: booleanField,
  closeToTrayEnabled: booleanField,
  releaseRendererInTrayEnabled: booleanField,
  startWithWindowsInTray: booleanField,
  autoConnectOnStartup: booleanField,
  sidebarCollapsed: booleanField,
  activeGlobalTab: (value, key) => oneOf(value, GLOBAL_TABS, key),
  lastConnectedTransport: (value, key) => oneOf(value, GLOBAL_TABS, key),
  xrayConsentAccepted: booleanField,
  showXrayWarningOnEnter: booleanField,
  xrayRiskBannerExpanded: booleanField,
  tunDataplaneEnabled: booleanField,
  notifyTunnelChanges: booleanField,
  notifyUpdateDownloaded: booleanField,
  notifyStillRunningInTray: booleanField,
  notifyOnlyWhenHidden: booleanField,
  stillRunningNoticeShown: booleanField
};

/** A settings patch: known keys only, each of its own type. */
export function parseSettingsPatch(value: unknown): SettingsPatch {
  const input = plainObject(value, "Settings");
  const patch: Record<string, unknown> = {};
  for (const [key, field] of Object.entries(input)) {
    if (!Object.hasOwn(SETTINGS_FIELDS, key)) {
      throw new Error(`Unknown setting: ${key}.`);
    }
    if (field === undefined) {
      continue;
    }
    patch[key] = SETTINGS_FIELDS[key as keyof AppSettings]!(field, key);
  }
  return patch as SettingsPatch;
}

export function parseRoutingMode(value: unknown): RoutingMode {
  return oneOf(value, ROUTING_MODES, "Routing mode");
}

/**
 * The whole rule list. A rule's value is checked with the rules the form
 * uses, except for a rule saved earlier and sent back unchanged: values the
 * checks have since grown stricter about must not block every other edit.
 */
export function parseRoutingRules(value: unknown, saved: readonly RoutingRule[] = []): RoutingRule[] {
  if (!Array.isArray(value)) {
    throw new Error("Routing rules must be a list.");
  }
  if (value.length > MAX_ROUTING_RULES) {
    throw new Error(`Routing rule count exceeds the ${MAX_ROUTING_RULES} rule limit.`);
  }
  const savedById = new Map(saved.map((rule) => [rule.id, rule]));
  return value.map((candidate: unknown, index) => {
    const label = `Routing rule ${index + 1}`;
    const input = plainObject(candidate, label);
    const rule: RoutingRule = {
      id: idField(input.id, `${label} id`),
      type: oneOf(input.type, ROUTING_RULE_TYPES, `${label} type`),
      value: stringField(input.value, `${label} value`, MAX_RULE_VALUE_LENGTH),
      enabled: booleanField(input.enabled, `${label} enabled`),
      createdAt: timestampField(input.createdAt),
      updatedAt: timestampField(input.updatedAt)
    };
    if (rule.type === "ip") {
      // A rule an earlier version saved with a zero-padded prefix comes back
      // here when its deletion is undone, after it has left the store.
      rule.value = canonicalIpRuleValue(rule.value);
    }
    const previous = savedById.get(rule.id);
    if (previous?.type !== rule.type || previous.value !== rule.value) {
      const validation = validateRoutingRuleValue(rule.type, rule.value);
      if (!validation.ok) {
        throw new Error(`${rule.value.trim() || label}: ${validation.message ?? "the value is invalid."}`);
      }
    }
    return rule;
  });
}

/** The server form. Whether the key still exists is checked by storage, which owns the keys. */
export function parseUpsertSshConfigInput(value: unknown): UpsertSshConfigInput {
  const input = plainObject(value, "SSH server");
  const authType = oneOf(input.authType, AUTH_TYPES, "Sign-in method");
  const port = input.port;
  if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Enter a port from 1 to 65535.");
  }
  const keepalive = input.keepaliveIntervalSec;
  if (typeof keepalive !== "number" || !Number.isInteger(keepalive) || keepalive < MIN_KEEPALIVE_SEC || keepalive > MAX_KEEPALIVE_SEC) {
    throw new Error(`Keepalive must be a whole number of seconds from ${MIN_KEEPALIVE_SEC} to ${MAX_KEEPALIVE_SEC}.`);
  }
  const host = requiredText(input.host, "Host", MAX_HOST_LENGTH);
  if (/[\s/\\?#@]/u.test(host)) {
    throw new Error("Enter only the server address in Host.");
  }
  const username = requiredText(input.username, "Username", MAX_NAME_LENGTH);
  if (/[\s@]/u.test(username)) {
    throw new Error("Enter only the user name in Username.");
  }
  const id = optional(input.id, (candidate) => idField(candidate, "SSH server id"));
  const password = optional(input.password, (candidate) => stringField(candidate, "Password", MAX_SECRET_LENGTH));
  const privateKeyId = optional(input.privateKeyId, (candidate) => idField(candidate, "SSH key id"));
  return {
    ...(id !== undefined ? { id } : {}),
    name: requiredText(input.name, "Name", MAX_NAME_LENGTH),
    host,
    port,
    username,
    authType,
    ...(password !== undefined ? { password } : {}),
    ...(privateKeyId !== undefined ? { privateKeyId } : {}),
    expectedServerFingerprint: stringField(input.expectedServerFingerprint ?? "", "Fingerprint", 256),
    keepaliveIntervalSec: keepalive,
    note: stringField(input.note ?? "", "Note", MAX_NOTE_LENGTH)
  };
}

export function parseImportProxyProfilesInput(value: unknown): ImportProxyProfilesInput {
  const input = plainObject(value, "Import");
  const sourceUrl = optional(input.sourceUrl, (candidate) => stringField(candidate, "Source URL", MAX_URL_LENGTH));
  return {
    text: stringField(input.text, "Import text", MAX_IMPORT_TEXT_LENGTH),
    source: oneOf(input.source, PROXY_PROFILE_SOURCES, "Import source"),
    ...(sourceUrl !== undefined ? { sourceUrl } : {})
  };
}

/** The endpoint a tunnel check probes; undefined (or blank) means the saved one. */
export function parseCheckEndpointArgument(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new Error("Endpoint must be text.");
  }
  const endpoint = value.trim();
  if (!endpoint) {
    return undefined;
  }
  const validation = validateCheckEndpoint(endpoint);
  if (!validation.ok) {
    throw new Error(validation.message);
  }
  return endpoint;
}

export function parseBoolean(value: unknown, label: string): boolean {
  return booleanField(value, label);
}

function parseCustomThemePatch(value: unknown, key: string): Partial<CustomTheme> {
  const input = plainObject(value, key);
  const theme: Partial<CustomTheme> = {};
  for (const [name, colour] of Object.entries(input)) {
    if (!(CUSTOM_THEME_COLOURS as readonly string[]).includes(name)) {
      throw new Error(`Unknown theme colour: ${name}.`);
    }
    theme[name as keyof CustomTheme] = parseRgbColor(colour, `${key}.${name}`);
  }
  return theme;
}

function parseRgbColor(value: unknown, label: string): RgbColor {
  const input = plainObject(value, label);
  const channel = (candidate: unknown, name: string): number => {
    if (typeof candidate !== "number" || !Number.isFinite(candidate) || candidate < 0 || candidate > 255) {
      throw new Error(`${label}.${name} must be a number from 0 to 255.`);
    }
    return candidate;
  };
  return { r: channel(input.r, "r"), g: channel(input.g, "g"), b: channel(input.b, "b") };
}

function plainObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} is invalid.`);
  }
  return value as Record<string, unknown>;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], label: string): T {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) {
    throw new Error(`${label} must be one of: ${allowed.join(", ")}.`);
  }
  return value as T;
}

function booleanField(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`${label} must be true or false.`);
  }
  return value;
}

function stringField(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") {
    throw new Error(`${label} must be text.`);
  }
  if (value.length > maxLength) {
    throw new Error(`${label} is too long.`);
  }
  return value;
}

function requiredText(value: unknown, label: string, maxLength: number): string {
  const text = stringField(value, label, maxLength).trim();
  if (!text) {
    throw new Error(`${label} is required.`);
  }
  return text;
}

function idField(value: unknown, label: string): string {
  const id = stringField(value, label, MAX_ID_LENGTH);
  if (!id) {
    throw new Error(`${label} is required.`);
  }
  return id;
}

/** Rule timestamps are only shown; one missing or garbled (a hand-written import) becomes now. */
function timestampField(value: unknown): string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_TIMESTAMP_LENGTH ? value : new Date().toISOString();
}

function optional<T>(value: unknown, parse: (value: unknown) => T): T | undefined {
  return value === undefined || value === null ? undefined : parse(value);
}
