import { describe, expect, it } from "vitest";
import {
  findAddedId,
  joinNames,
  keyDeleteDescription,
  keyDeletedMessage,
  keyInUseDescription,
  keyLockText,
  keyOptionSub,
  keySavedToast,
  keySupportIssue,
  keyTypeLabel,
  serversUsingKey,
  shortKeyId
} from "../src/renderer/components/pages/keys/key-model.js";
import type { SshConfig, SshKeyMetadata } from "../src/shared/types.js";

const at = "2026-10-06T10:00:00.000Z";

function server(id: string, name: string, privateKeyId?: string): SshConfig {
  return {
    id,
    name,
    host: "203.0.113.10",
    port: 22,
    username: "root",
    authType: privateKeyId ? "private-key" : "password",
    privateKeyId,
    expectedServerFingerprint: "",
    keepaliveIntervalSec: 120,
    note: "",
    createdAt: at,
    updatedAt: at
  };
}

function key(overrides: Partial<SshKeyMetadata> = {}): SshKeyMetadata {
  return {
    id: "key-work",
    name: "work-ed25519",
    privateKeySecretId: "secret-work",
    fingerprint: "sha256:4f1c9eAbCdEfGhIjKlMnOpQrStUvWxYz0123456a92e",
    keyType: "ed25519",
    keyFormat: "openssh",
    encryptedOpenSsh: false,
    createdAt: at,
    updatedAt: at,
    ...overrides
  };
}

describe("key presentation", () => {
  it("labels key types and falls back for older keys", () => {
    expect(keyTypeLabel("ed25519")).toBe("Ed25519");
    expect(keyTypeLabel("rsa")).toBe("RSA");
    expect(keyTypeLabel(undefined)).toBe("Unknown");
  });

  it("shortens the Key ID like the boards", () => {
    expect(shortKeyId("sha256:4f1c9eAbCdEfGhIjKlMnOpQrStUvWxYz0123456a92e")).toBe("sha256:4f1c9e…a92e");
    expect(shortKeyId("")).toBe("—");
  });

  it("joins server names in plain English", () => {
    expect(joinNames([])).toBe("");
    expect(joinNames(["A"])).toBe("A");
    expect(joinNames(["A", "B"])).toBe("A and B");
    expect(joinNames(["A", "B", "C"])).toBe("A, B and C");
  });

  it("finds the servers that sign in with a key", () => {
    const configs = [server("ams", "Amsterdam-edge", "key-work"), server("fra", "Frankfurt-01"), server("hel", "Helsinki-backup", "key-home")];
    expect(serversUsingKey(configs, "key-work").map((config) => config.name)).toEqual(["Amsterdam-edge"]);
    expect(serversUsingKey(configs, "key-old")).toEqual([]);
  });

  it("explains why a key in use can't be deleted", () => {
    expect(keyLockText(["Amsterdam-edge"])).toBe("In use by Amsterdam-edge, so it can’t be deleted. Switch that server to another sign-in first.");
    expect(keyLockText(["A", "B"])).toBe("In use by A and B, so it can’t be deleted. Switch those servers to another sign-in first.");
    expect(keyInUseDescription(1)).toMatch(/^A server still signs in/u);
    expect(keyInUseDescription(3)).toMatch(/^3 servers still sign in/u);
  });

  it("names keys that save but can't sign in yet", () => {
    expect(keySupportIssue(key())).toBeUndefined();
    expect(keySupportIssue(key({ keyType: "ecdsa" }))).toMatch(/ECDSA/u);
    expect(keySupportIssue(key({ keyType: "dsa" }))).toMatch(/DSA/u);
    expect(keySupportIssue(key({ encryptedOpenSsh: true }))).toMatch(/Passphrase-protected OpenSSH/u);
  });

  it("builds the picker line with type, passphrase, Key ID and users", () => {
    const configs = [server("ams", "Amsterdam-edge", "key-work")];
    expect(keyOptionSub(key(), configs)).toBe("Ed25519 · Key ID sha256:4f1c9e…a92e · used by Amsterdam-edge");
    expect(keyOptionSub(key({ id: "key-home", keyType: "rsa", privateKeyPassphraseSecretId: "pass" }), configs)).toBe(
      "RSA · passphrase saved · Key ID sha256:4f1c9e…a92e · not used by any server"
    );
  });

  it("finds the one id a save added", () => {
    expect(findAddedId([{ id: "a" }], [{ id: "a" }, { id: "b" }])).toBe("b");
    expect(findAddedId([{ id: "a" }], [{ id: "a" }])).toBeUndefined();
    expect(findAddedId([], [{ id: "a" }, { id: "b" }])).toBeUndefined();
  });

  it("words delete confirmations and results by passphrase state", () => {
    expect(keyDeleteDescription(key())).toBe("The key is removed from this device. This can’t be undone.");
    expect(keyDeleteDescription(key({ privateKeyPassphraseSecretId: "p" }))).toMatch(/and its saved passphrase/u);
    expect(keyDeletedMessage(key())).toBe("work-ed25519 was removed from this device.");
    expect(keyDeletedMessage(key({ privateKeyPassphraseSecretId: "p" }))).toBe("work-ed25519 and its passphrase were removed from this device.");
  });

  it("picks the toast for each save", () => {
    expect(keySavedToast({ mode: "create", name: "k", replaced: false, usedBy: [] }).title).toBe("Key added");
    expect(keySavedToast({ mode: "create", name: "k", replaced: false, usedBy: [], pickedFor: "Warsaw-02" }).message).toBe("k is picked for Warsaw-02.");
    expect(keySavedToast({ mode: "create", name: "k", replaced: false, usedBy: [], pickedFor: "" }).message).toBe("k is picked for this server.");
    expect(keySavedToast({ mode: "edit", name: "home-rsa", replaced: true, usedBy: ["Helsinki-backup"] })).toEqual({
      title: "Key replaced",
      message: "Helsinki-backup signs in with the new key from its next connect."
    });
    expect(keySavedToast({ mode: "edit", name: "k", replaced: true, usedBy: ["A", "B"] }).message).toBe("A and B sign in with the new key from their next connect.");
    expect(keySavedToast({ mode: "edit", name: "home-rsa", replaced: false, usedBy: [] })).toEqual({ title: "Key saved", message: "home-rsa is up to date." });
  });
});
