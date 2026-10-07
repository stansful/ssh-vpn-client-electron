import { describe, expect, it } from "vitest";
import {
  advancedSummary,
  analyzeFingerprint,
  connectionPreview,
  describeServerChanges,
  isServerFormDirty,
  observedKeySuggestion,
  pinState,
  secretsPhrase,
  toUpsertInput,
  validateHost,
  validateServerValues,
  valuesFromConfig,
  type ServerFormValues
} from "../src/renderer/components/pages/servers/server-form-model.js";
import { validateSshServerFingerprint } from "../src/shared/validation.js";
import type { SshConfig, SshKeyMetadata } from "../src/shared/types.js";

const VALID = "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s";
const at = "2026-10-06T10:00:00.000Z";

const frankfurt: SshConfig = {
  id: "fra",
  name: "Frankfurt-01",
  host: "203.0.113.10",
  port: 22,
  username: "root",
  authType: "password",
  passwordSecretId: "pw",
  expectedServerFingerprint: VALID,
  keepaliveIntervalSec: 120,
  note: "",
  createdAt: at,
  updatedAt: at
};

const keys: SshKeyMetadata[] = [
  { id: "key-work", name: "work-ed25519", privateKeySecretId: "s", fingerprint: "sha256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s", createdAt: at, updatedAt: at }
];

function filled(overrides: Partial<ServerFormValues> = {}): ServerFormValues {
  return { ...valuesFromConfig(), name: "Warsaw-02", host: "203.0.113.48", username: "root", ...overrides };
}

describe("analyzeFingerprint", () => {
  it("accepts exactly what the core accepts", () => {
    expect(analyzeFingerprint("")).toEqual({ state: "empty" });
    expect(analyzeFingerprint(`  ${VALID} `)).toEqual({ state: "valid" });
    expect(validateSshServerFingerprint(VALID).ok).toBe(true);
  });

  it("offers to remove a trailing =", () => {
    const analysis = analyzeFingerprint(`${VALID}=`);
    expect(analysis.state).toBe("invalid");
    expect(analysis.message).toMatch(/^This fingerprint ends with =/u);
    expect(analysis.fix).toEqual({ label: "Remove the trailing =", value: VALID });
    expect(validateSshServerFingerprint(analysis.fix!.value).ok).toBe(true);
  });

  it("fixes lower-case sha256 but refuses a Key ID", () => {
    expect(analyzeFingerprint(VALID.replace("SHA256", "sha256")).fix).toEqual({ label: "Change to SHA256:", value: VALID });
    const keyId = analyzeFingerprint(keys[0].fingerprint, keys.map((key) => key.fingerprint));
    expect(keyId.state).toBe("invalid");
    expect(keyId.message).toMatch(/Key ID from SSH keys/u);
    expect(keyId.fix).toBeUndefined();
  });

  it("pulls the fingerprint out of a whole ssh-keygen line", () => {
    const analysis = analyzeFingerprint(`256 ${VALID} root@frankfurt (ED25519)`);
    expect(analysis.fix).toEqual({ label: "Keep only the fingerprint", value: VALID });
  });

  it("adds a missing prefix and explains MD5 and wrong lengths", () => {
    expect(analyzeFingerprint(VALID.slice("SHA256:".length)).fix).toEqual({ label: "Add SHA256:", value: VALID });
    expect(analyzeFingerprint("MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48").message).toMatch(/MD5/u);
    expect(analyzeFingerprint("16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48").message).toMatch(/MD5/u);
    expect(analyzeFingerprint("SHA256:abc").message).toBe("A SHA256 fingerprint has 43 characters after SHA256:, this one has 3. Copy the whole value from ssh-keygen -l.");
    expect(analyzeFingerprint("not a fingerprint!").state).toBe("invalid");
  });

  it("derives the pin badge", () => {
    expect(pinState(VALID, VALID, analyzeFingerprint(VALID))).toBe("pinned");
    expect(pinState(VALID, "", analyzeFingerprint(VALID))).toBe("will-pin");
    expect(pinState("", VALID, analyzeFingerprint(""))).toBe("will-unpin");
    expect(pinState("", "", analyzeFingerprint(""))).toBe("not-pinned");
    expect(pinState("bad", "", analyzeFingerprint("bad"))).toBe("not-pinned");
  });
});

describe("validateServerValues", () => {
  it("requires name, host, port and username", () => {
    const errors = validateServerValues(valuesFromConfig());
    expect(Object.keys(errors).sort()).toEqual(["host", "name", "username"]);
    expect(validateServerValues(filled())).toEqual({});
  });

  it("explains hosts that carry a user, a port or a scheme", () => {
    expect(validateHost("root@203.0.113.10")).toMatch(/Username/u);
    expect(validateHost("vps.example.net:2222")).toMatch(/Port/u);
    expect(validateHost("ssh://vps.example.net")).toMatch(/ssh:\/\//u);
    expect(validateHost("vps example")).toMatch(/spaces/u);
    expect(validateHost("[2001:db8::1]")).toMatch(/brackets/u);
    expect(validateHost("2001:db8::1")).toBeUndefined();
    expect(validateHost("helsinki.example.net")).toBeUndefined();
  });

  it("checks port and keepalive ranges", () => {
    expect(validateServerValues(filled({ port: "0" })).port).toBeDefined();
    expect(validateServerValues(filled({ port: "65536" })).port).toBeDefined();
    expect(validateServerValues(filled({ port: "2222" })).port).toBeUndefined();
    expect(validateServerValues(filled({ keepalive: 59 })).keepalive).toBeDefined();
    expect(validateServerValues(filled({ keepalive: Number.NaN })).keepalive).toBeDefined();
    expect(validateServerValues(filled({ keepalive: 3600 })).keepalive).toBeUndefined();
  });

  it("blocks an invalid fingerprint", () => {
    expect(validateServerValues(filled({ fingerprint: `${VALID}=` })).fingerprint).toMatch(/ends with =/u);
  });
});

describe("toUpsertInput", () => {
  it("trims text and saves only the sign-in that is shown", () => {
    const input = toUpsertInput(filled({ name: " Warsaw-02 ", host: " 203.0.113.48 ", port: " 22 ", password: "secret", privateKeyId: "key-work" }));
    expect(input).toMatchObject({ name: "Warsaw-02", host: "203.0.113.48", port: 22, authType: "password", password: "secret", privateKeyId: undefined });

    const keyInput = toUpsertInput(filled({ authType: "private-key", password: "typed before switching", privateKeyId: "key-work" }), "fra");
    expect(keyInput).toMatchObject({ id: "fra", authType: "private-key", password: undefined, privateKeyId: "key-work" });
  });

  it("keeps the saved password when the field is blank", () => {
    expect(toUpsertInput(valuesFromConfig(frankfurt), "fra").password).toBeUndefined();
  });
});

describe("dirty state and discarded changes", () => {
  it("ignores whitespace and the hidden sign-in method", () => {
    const initial = valuesFromConfig(frankfurt);
    expect(isServerFormDirty(initial, initial)).toBe(false);
    expect(isServerFormDirty(initial, { ...initial, name: "Frankfurt-01 " })).toBe(false);
    expect(isServerFormDirty(initial, { ...initial, privateKeyId: "key-work" })).toBe(false);
    expect(isServerFormDirty(initial, { ...initial, host: "203.0.113.12" })).toBe(true);
    expect(isServerFormDirty(initial, { ...initial, password: "new" })).toBe(true);
  });

  it("lists what would be lost without showing secrets", () => {
    const initial = valuesFromConfig(frankfurt);
    const changes = describeServerChanges(initial, { ...initial, host: "203.0.113.12", keepalive: 300, password: "hunter2", note: "renews on the 14th" }, {
      keys,
      passwordSaved: true
    });
    expect(changes).toEqual([
      { label: "Host", from: "203.0.113.10", to: "203.0.113.12" },
      { label: "Password", from: "saved one", to: "new one typed" },
      { label: "Keepalive", from: "120 s", to: "300 s" },
      { label: "Note", from: "no note", to: "added" }
    ]);
    expect(JSON.stringify(changes)).not.toContain("hunter2");

    const signIn = describeServerChanges(initial, { ...initial, authType: "private-key", privateKeyId: "key-work", fingerprint: "" }, { keys, passwordSaved: true });
    expect(signIn.map((change) => change.label)).toEqual(["Sign in", "Private key", "Host key"]);
    expect(signIn[1]).toEqual({ label: "Private key", from: "none", to: "work-ed25519" });
    expect(signIn[2].to).toBe("not pinned");
  });
});

describe("form copy helpers", () => {
  it("previews the address and the advanced summary", () => {
    expect(connectionPreview({ username: "root", host: "203.0.113.48", port: "22" })).toBe("root@203.0.113.48:22");
    expect(connectionPreview({ username: "", host: "", port: "" })).toBe("user@host:22");
    expect(connectionPreview({ username: "pi", host: "2001:db8::1", port: "22" })).toBe("pi@[2001:db8::1]:22");
    expect(advancedSummary({ keepalive: 120, note: "" })).toBe("Keepalive 120 s · no note");
    expect(advancedSummary({ keepalive: 300, note: "x" })).toBe("Keepalive 300 s · note added");
  });

  it("names the secrets backend", () => {
    expect(secretsPhrase("Windows DPAPI")).toBe("Encrypted by Windows and kept only on this device.");
    expect(secretsPhrase("unavailable")).toBe("Kept only on this device.");
  });

  it("starts a new server with a preset key", () => {
    expect(valuesFromConfig(undefined, { privateKeyId: "key-work" })).toMatchObject({ authType: "private-key", privateKeyId: "key-work", port: "22", keepalive: 120 });
  });
});

describe("observed host key suggestion", () => {
  const saved = { host: "203.0.113.10", port: 22 };
  const seen = "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s";

  it("offers the key the session saw while the form still points at that machine", () => {
    expect(observedKeySuggestion({ observed: seen, values: { host: " 203.0.113.10 ", port: "22" }, saved, activeTarget: "203.0.113.10:22" })).toBe(seen);
    expect(observedKeySuggestion({ observed: seen, values: { host: "SSH.Example.com", port: "22" }, saved: { host: "ssh.example.com", port: 22 } })).toBe(seen);
    expect(observedKeySuggestion({ observed: seen, values: { host: "2001:db8::1", port: "22" }, saved: { host: "2001:db8::1", port: 22 }, activeTarget: "[2001:db8::1]:22" })).toBe(seen);
  });

  it("stops offering it once Host or Port change", () => {
    expect(observedKeySuggestion({ observed: seen, values: { host: "198.51.100.7", port: "22" }, saved })).toBeUndefined();
    expect(observedKeySuggestion({ observed: seen, values: { host: "203.0.113.10", port: "2222" }, saved })).toBeUndefined();
  });

  it("does not offer it when the session runs on an address saved before an earlier edit", () => {
    expect(observedKeySuggestion({ observed: seen, values: { host: "203.0.113.10", port: "22" }, saved, activeTarget: "198.51.100.7:22" })).toBeUndefined();
    expect(observedKeySuggestion({ values: { host: "203.0.113.10", port: "22" }, saved })).toBeUndefined();
  });
});
