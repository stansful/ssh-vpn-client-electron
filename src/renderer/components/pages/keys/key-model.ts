import { shortenMiddle } from "../../../lib/format.js";
import type { SshConfig, SshKeyMetadata, SshKeyType } from "../../../../shared/types.js";

const KEY_TYPE_LABELS: Record<SshKeyType, string> = {
  ed25519: "Ed25519",
  rsa: "RSA",
  ecdsa: "ECDSA",
  dsa: "DSA",
  unknown: "Unknown"
};

/** "Ed25519", "RSA"… for the type tag; older keys without metadata read "Unknown". */
export function keyTypeLabel(type: SshKeyType | undefined): string {
  return KEY_TYPE_LABELS[type ?? "unknown"] ?? KEY_TYPE_LABELS.unknown;
}

/** Shadow's own key ID, shortened the way lists show it: "sha256:4f1c9e…a92e". */
export function shortKeyId(fingerprint: string): string {
  return fingerprint ? shortenMiddle(fingerprint, 13, 4) : "—";
}

/** Servers that sign in with this key (deleting the key is blocked while there are any). */
export function serversUsingKey(configs: readonly SshConfig[], keyId: string): SshConfig[] {
  return configs.filter((config) => config.privateKeyId === keyId);
}

/** "A", "A and B", "A, B and C". */
export function joinNames(names: readonly string[]): string {
  if (names.length <= 1) {
    return names[0] ?? "";
  }
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/** Why the key card's Delete is unavailable. */
export function keyLockText(serverNames: readonly string[]): string {
  return `In use by ${joinNames(serverNames)}, so it can’t be deleted. Switch ${serverNames.length === 1 ? "that server" : "those servers"} to another sign-in first.`;
}

/**
 * Keys that save fine but cannot sign in yet: the SSH core loads RSA and
 * Ed25519 keys, and passphrases only for PEM/PKCS#8.
 */
export function keySupportIssue(key: Pick<SshKeyMetadata, "keyType" | "encryptedOpenSsh">): string | undefined {
  if (key.encryptedOpenSsh) {
    return "Passphrase-protected OpenSSH keys can’t sign in yet.";
  }
  if (key.keyType === "ecdsa") {
    return "ECDSA keys can’t sign in yet.";
  }
  if (key.keyType === "dsa") {
    return "DSA keys can’t sign in yet.";
  }
  return undefined;
}

/** Second line of a key in the server form's picker: type, passphrase, Key ID, who uses it. */
export function keyOptionSub(key: SshKeyMetadata, configs: readonly SshConfig[]): string {
  const users = serversUsingKey(configs, key.id).map((config) => config.name);
  return [
    keyTypeLabel(key.keyType),
    key.privateKeyPassphraseSecretId ? "passphrase saved" : undefined,
    `Key ID ${shortKeyId(key.fingerprint)}`,
    users.length > 0 ? `used by ${joinNames(users)}` : "not used by any server"
  ]
    .filter(Boolean)
    .join(" · ");
}

/** The id that appeared in `after` (a key or server just created), if exactly one did. */
export function findAddedId(before: ReadonlyArray<{ id: string }>, after: ReadonlyArray<{ id: string }>): string | undefined {
  const known = new Set(before.map((item) => item.id));
  const added = after.filter((item) => !known.has(item.id));
  return added.length === 1 ? added[0].id : undefined;
}

export function keyDeleteDescription(key: Pick<SshKeyMetadata, "privateKeyPassphraseSecretId">): string {
  return key.privateKeyPassphraseSecretId
    ? "The key and its saved passphrase are removed from this device. This can’t be undone."
    : "The key is removed from this device. This can’t be undone.";
}

export function keyDeletedMessage(key: Pick<SshKeyMetadata, "name" | "privateKeyPassphraseSecretId">): string {
  return `${key.name}${key.privateKeyPassphraseSecretId ? " and its passphrase were" : " was"} removed from this device.`;
}

/** Description of the "Can't delete … yet" dialog. */
export function keyInUseDescription(count: number): string {
  return count === 1
    ? "A server still signs in with this key. Switch it to another key or a password, then delete the key."
    : `${count} servers still sign in with this key. Switch them to another key or a password, then delete the key.`;
}

export interface KeySavedToast {
  title: string;
  message: string;
}

/** Success toast after the key form saved. */
export function keySavedToast(input: {
  mode: "create" | "edit";
  name: string;
  /** A new key text replaced the saved one. */
  replaced: boolean;
  /** Servers that sign in with the key. */
  usedBy: readonly string[];
  /** The key was added from the server form and picked there. */
  pickedFor?: string;
}): KeySavedToast {
  if (input.mode === "create") {
    return input.pickedFor !== undefined
      ? { title: "Key added", message: `${input.name} is picked for ${input.pickedFor || "this server"}.` }
      : { title: "Key added", message: `${input.name} is in SSH keys. Pick it for any server that signs in with a key.` };
  }
  if (input.replaced) {
    if (input.usedBy.length === 0) {
      return { title: "Key replaced", message: `${input.name} now holds the new key.` };
    }
    const single = input.usedBy.length === 1;
    return {
      title: "Key replaced",
      message: `${joinNames(input.usedBy)} ${single ? "signs" : "sign"} in with the new key from ${single ? "its" : "their"} next connect.`
    };
  }
  return { title: "Key saved", message: `${input.name} is up to date.` };
}
