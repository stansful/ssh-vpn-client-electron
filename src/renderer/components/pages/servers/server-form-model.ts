import { formatHostPort, shortenMiddle } from "../../../lib/format.js";
import { isValidIpv6 } from "../../../../shared/validation.js";
import type { AuthType, SshConfig, SshKeyMetadata, UpsertSshConfigInput } from "../../../../shared/types.js";

export const DEFAULT_KEEPALIVE_SEC = 120;
export const MIN_KEEPALIVE_SEC = 60;
export const MAX_KEEPALIVE_SEC = 3600;
export const KEEPALIVE_STEP_SEC = 30;

/** What the server form edits. Port stays text while typing; secrets are never prefilled. */
export interface ServerFormValues {
  name: string;
  host: string;
  port: string;
  username: string;
  authType: AuthType;
  /** Empty keeps the saved password. */
  password: string;
  privateKeyId: string;
  fingerprint: string;
  /** NaN while the stepper is empty. */
  keepalive: number;
  note: string;
}

export type ServerField = "name" | "host" | "port" | "username" | "keepalive" | "fingerprint";
export type ServerFieldErrors = Partial<Record<ServerField, string>>;

export function valuesFromConfig(config?: SshConfig, preset: { privateKeyId?: string } = {}): ServerFormValues {
  if (!config) {
    return {
      name: "",
      host: "",
      port: "22",
      username: "",
      authType: preset.privateKeyId ? "private-key" : "password",
      password: "",
      privateKeyId: preset.privateKeyId ?? "",
      fingerprint: "",
      keepalive: DEFAULT_KEEPALIVE_SEC,
      note: ""
    };
  }
  return {
    name: config.name,
    host: config.host,
    port: String(config.port),
    username: config.username,
    authType: config.authType,
    password: "",
    privateKeyId: config.authType === "private-key" ? config.privateKeyId ?? "" : "",
    fingerprint: config.expectedServerFingerprint,
    keepalive: config.keepaliveIntervalSec,
    note: config.note
  };
}

/**
 * The host key the running session saw, offered for pinning only while the
 * form still points at the machine that sent it: once Host or Port change,
 * pinning it would tie that machine's key to another address.
 */
export function observedKeySuggestion(input: {
  observed?: string;
  values: Pick<ServerFormValues, "host" | "port">;
  saved: Pick<SshConfig, "host" | "port">;
  /** `runtime.activeTarget`: the session may still run on an address saved before an earlier edit. */
  activeTarget?: string;
}): string | undefined {
  const { observed, values, saved, activeTarget } = input;
  if (!observed) {
    return undefined;
  }
  const bare = (host: string): string => host.trim().replace(/^\[|\]$/gu, "").toLowerCase();
  if (bare(values.host) !== bare(saved.host) || Number(values.port.trim()) !== saved.port) {
    return undefined;
  }
  if (activeTarget && activeTarget.toLowerCase() !== formatHostPort(bare(saved.host), saved.port)) {
    return undefined;
  }
  return observed;
}

export function toUpsertInput(values: ServerFormValues, id?: string): UpsertSshConfigInput {
  const usesKey = values.authType === "private-key";
  return {
    id,
    name: values.name.trim(),
    host: values.host.trim(),
    port: Number(values.port.trim()),
    username: values.username.trim(),
    authType: values.authType,
    // Only the sign-in shown is saved: a password typed before switching to a key is dropped.
    password: !usesKey && values.password.length > 0 ? values.password : undefined,
    privateKeyId: usesKey && values.privateKeyId ? values.privateKeyId : undefined,
    expectedServerFingerprint: values.fingerprint.trim(),
    keepaliveIntervalSec: values.keepalive,
    note: values.note.trim()
  };
}

/** "root@203.0.113.10:22" — how the server reads in lists, with placeholders while fields are empty. */
export function connectionPreview(values: Pick<ServerFormValues, "username" | "host" | "port">): string {
  const host = values.host.trim() || "host";
  const port = values.port.trim() || "22";
  return `${values.username.trim() || "user"}@${formatHostPort(host, port)}`;
}

export function advancedSummary(values: Pick<ServerFormValues, "keepalive" | "note">): string {
  const keepalive = Number.isFinite(values.keepalive) ? `${values.keepalive} s` : "not set";
  return `Keepalive ${keepalive} · ${values.note.trim() ? "note added" : "no note"}`;
}

export function validateHost(raw: string): string | undefined {
  const host = raw.trim();
  if (!host) {
    return "Enter the server address, for example 203.0.113.10 or vps.example.net.";
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//iu.test(host)) {
    return "Enter the host without ssh:// or a path — for example vps.example.net.";
  }
  if (host.includes("@")) {
    return "Put the user name in Username — the host is only the part after @.";
  }
  if (/\s/u.test(host)) {
    return "Remove the spaces — a host is one word, like vps.example.net.";
  }
  if (/[/\\?#]/u.test(host)) {
    return "Enter only the host, without a path.";
  }
  if (/^\[.*\]$/u.test(host)) {
    return "Enter the IPv6 address without the brackets.";
  }
  if (host.includes(":") && !isValidIpv6(host)) {
    return /^[^:]+:\d+$/u.test(host)
      ? "Put the port in Port — the host is only the part before the colon."
      : "That isn’t a valid IPv6 address. Check it, or use the server’s name.";
  }
  return undefined;
}

export function validatePort(raw: string): string | undefined {
  const port = raw.trim();
  if (!/^\d{1,5}$/u.test(port) || Number(port) < 1 || Number(port) > 65535) {
    return "Enter a port from 1 to 65535. SSH usually uses 22.";
  }
  return undefined;
}

export function validateUsername(raw: string): string | undefined {
  const username = raw.trim();
  if (!username) {
    return "Enter the user name you sign in with, for example root.";
  }
  if (username.includes("@")) {
    return "Enter only the user name — the host goes in Host.";
  }
  if (/\s/u.test(username)) {
    return "A user name can’t contain spaces.";
  }
  return undefined;
}

export function validateKeepalive(value: number): string | undefined {
  if (!Number.isInteger(value) || value < MIN_KEEPALIVE_SEC || value > MAX_KEEPALIVE_SEC) {
    return "Use a whole number of seconds from 60 to 3600.";
  }
  return undefined;
}

/** Field errors that block saving; empty when the form can be saved. */
export function validateServerValues(values: ServerFormValues, knownKeyIds: readonly string[] = []): ServerFieldErrors {
  const errors: ServerFieldErrors = {};
  if (!values.name.trim()) {
    errors.name = "Enter a name, for example Frankfurt-01.";
  }
  const host = validateHost(values.host);
  if (host) {
    errors.host = host;
  }
  const port = validatePort(values.port);
  if (port) {
    errors.port = port;
  }
  const username = validateUsername(values.username);
  if (username) {
    errors.username = username;
  }
  const keepalive = validateKeepalive(values.keepalive);
  if (keepalive) {
    errors.keepalive = keepalive;
  }
  const fingerprint = analyzeFingerprint(values.fingerprint, knownKeyIds);
  if (fingerprint.state === "invalid") {
    errors.fingerprint = fingerprint.message;
  }
  return errors;
}

export interface FingerprintAnalysis {
  state: "empty" | "valid" | "invalid";
  message?: string;
  /** One-click repair: the button label and the corrected value. */
  fix?: { label: string; value: string };
}

const FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/u;
const FINGERPRINT_TOKEN = /SHA256:[A-Za-z0-9+/]{43}(?![A-Za-z0-9+/])/u;
const GENERIC_FINGERPRINT_MESSAGE = "Use the SHA256:… form from ssh-keygen -l, with 43 characters after SHA256:";

/**
 * Checks a host key fingerprint the way the core will (OpenSSH `SHA256:` +
 * 43 base64 characters, case-sensitive) and explains the common slips with a
 * fix where one is safe: a trailing "=", lower-case "sha256:", a whole
 * ssh-keygen line, a missing prefix. A Key ID from SSH keys looks similar but
 * hashes the private key text, so it is called out instead of "fixed".
 */
export function analyzeFingerprint(raw: string, knownKeyIds: readonly string[] = []): FingerprintAnalysis {
  const value = raw.trim();
  if (!value) {
    return { state: "empty" };
  }
  if (FINGERPRINT.test(value)) {
    return { state: "valid" };
  }
  if (knownKeyIds.some((keyId) => keyId && keyId.toLowerCase() === value.toLowerCase())) {
    return {
      state: "invalid",
      message: "That’s a Key ID from SSH keys, not the server’s host key. Get the fingerprint on the server with ssh-keygen -lf."
    };
  }
  if (/\s/u.test(value)) {
    const token = value.match(FINGERPRINT_TOKEN)?.[0];
    return token
      ? { state: "invalid", message: "Paste only the SHA256:… part of that line.", fix: { label: "Keep only the fingerprint", value: token } }
      : { state: "invalid", message: GENERIC_FINGERPRINT_MESSAGE };
  }
  const trailing = value.match(/^(SHA256:[A-Za-z0-9+/]{43})=+$/u);
  if (trailing) {
    return {
      state: "invalid",
      message: "This fingerprint ends with =, so it would never match. Use the SHA256:… form from ssh-keygen -l, with 43 characters after SHA256:",
      fix: { label: "Remove the trailing =", value: trailing[1] }
    };
  }
  const wrongCase = value.match(/^sha256:([A-Za-z0-9+/]{43})=*$/iu);
  if (wrongCase) {
    return {
      state: "invalid",
      message: "Write SHA256 in capitals, the way ssh-keygen -l prints it.",
      fix: { label: "Change to SHA256:", value: `SHA256:${wrongCase[1]}` }
    };
  }
  if (/^MD5:/iu.test(value) || /^(?:[0-9a-f]{2}:){15}[0-9a-f]{2}$/iu.test(value)) {
    return { state: "invalid", message: "That’s an MD5 fingerprint. Pin the SHA256:… one — ssh-keygen -lf prints it by default." };
  }
  const bare = value.match(/^([A-Za-z0-9+/]{43})=*$/u);
  if (bare) {
    return {
      state: "invalid",
      message: "Add SHA256: in front — that’s how ssh-keygen -l prints the fingerprint.",
      fix: { label: "Add SHA256:", value: `SHA256:${bare[1]}` }
    };
  }
  const prefixed = value.match(/^SHA256:([A-Za-z0-9+/]*)=*$/u);
  if (prefixed) {
    const count = prefixed[1].length;
    return {
      state: "invalid",
      message: `A SHA256 fingerprint has 43 characters after SHA256:, this one has ${count}. Copy the whole value from ssh-keygen -l.`
    };
  }
  return { state: "invalid", message: GENERIC_FINGERPRINT_MESSAGE };
}

export type PinState = "pinned" | "will-pin" | "will-unpin" | "not-pinned";

/** The Security group's badge: pinned already, pins on save, unpins on save, or not pinned. */
export function pinState(value: string, saved: string, analysis: FingerprintAnalysis): PinState {
  const trimmed = value.trim();
  if (analysis.state === "valid") {
    return trimmed === saved.trim() ? "pinned" : "will-pin";
  }
  if (analysis.state === "empty" && saved.trim()) {
    return "will-unpin";
  }
  return "not-pinned";
}

function sameNumber(a: number, b: number): boolean {
  return a === b || (Number.isNaN(a) && Number.isNaN(b));
}

/**
 * Whether closing would lose anything that saving would keep. Text compares
 * trimmed (saving trims it), and only the sign-in method shown counts.
 */
export function isServerFormDirty(initial: ServerFormValues, current: ServerFormValues): boolean {
  const same = (a: string, b: string): boolean => a.trim() === b.trim();
  return !(
    same(initial.name, current.name) &&
    same(initial.host, current.host) &&
    same(initial.port, current.port) &&
    same(initial.username, current.username) &&
    initial.authType === current.authType &&
    (current.authType !== "password" || current.password.length === 0) &&
    (current.authType !== "private-key" || initial.privateKeyId === current.privateKeyId) &&
    same(initial.fingerprint, current.fingerprint) &&
    sameNumber(initial.keepalive, current.keepalive) &&
    same(initial.note, current.note)
  );
}

export interface FieldChange {
  label: string;
  from: string;
  to: string;
}

/** What closing the edit form would throw away, field by field (secrets never shown). */
export function describeServerChanges(
  initial: ServerFormValues,
  current: ServerFormValues,
  context: { keys: readonly SshKeyMetadata[]; passwordSaved: boolean }
): FieldChange[] {
  const changes: FieldChange[] = [];
  const text = (label: string, from: string, to: string, empty = "empty"): void => {
    if (from.trim() !== to.trim()) {
      changes.push({ label, from: from.trim() || empty, to: to.trim() || empty });
    }
  };
  text("Name", initial.name, current.name);
  text("Host", initial.host, current.host);
  text("Port", initial.port, current.port);
  text("Username", initial.username, current.username);
  if (initial.authType !== current.authType) {
    changes.push({ label: "Sign in", from: authLabel(initial.authType), to: authLabel(current.authType) });
  }
  if (current.authType === "password" && current.password.length > 0) {
    changes.push({ label: "Password", from: context.passwordSaved ? "saved one" : "none", to: "new one typed" });
  }
  if (current.authType === "private-key" && initial.privateKeyId !== current.privateKeyId) {
    const name = (id: string): string => context.keys.find((key) => key.id === id)?.name ?? "none";
    changes.push({ label: "Private key", from: name(initial.privateKeyId), to: name(current.privateKeyId) });
  }
  if (initial.fingerprint.trim() !== current.fingerprint.trim()) {
    const short = (value: string): string => (value.trim() ? shortenMiddle(value.trim(), 14, 4) : "not pinned");
    changes.push({ label: "Host key", from: short(initial.fingerprint), to: short(current.fingerprint) });
  }
  if (!sameNumber(initial.keepalive, current.keepalive)) {
    const seconds = (value: number): string => (Number.isFinite(value) ? `${value} s` : "empty");
    changes.push({ label: "Keepalive", from: seconds(initial.keepalive), to: seconds(current.keepalive) });
  }
  if (initial.note.trim() !== current.note.trim()) {
    const had = Boolean(initial.note.trim());
    const has = Boolean(current.note.trim());
    changes.push({ label: "Note", from: had ? "saved note" : "no note", to: has ? (had ? "edited" : "added") : "removed" });
  }
  return changes;
}

function authLabel(authType: AuthType): string {
  return authType === "private-key" ? "Private key" : "Password";
}

/** "your PC", "your Mac" or "your computer" for the pinning hint. */
export function deviceNoun(platform: string): string {
  return platform === "windows" ? "your PC" : platform === "macos" ? "your Mac" : "your computer";
}

/** Who encrypts saved secrets, for the password hint. */
export function secretsPhrase(secretsBackend: string): string {
  if (secretsBackend === "Windows DPAPI") {
    return "Encrypted by Windows and kept only on this device.";
  }
  if (secretsBackend === "macOS Keychain") {
    return "Encrypted by your macOS keychain and kept only on this device.";
  }
  if (secretsBackend === "Linux keyring") {
    return "Encrypted by your system keyring and kept only on this device.";
  }
  return "Kept only on this device.";
}
