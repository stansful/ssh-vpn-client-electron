import { afterEach, describe, expect, it, vi } from "vitest";
import type * as BcryptPbkdf from "../src/core/ssh/bcrypt-pbkdf.js";

const kdf = vi.hoisted(() => ({ calls: 0 }));

vi.mock("../src/core/ssh/bcrypt-pbkdf.js", async (importOriginal) => {
  const actual = await importOriginal<typeof BcryptPbkdf>();
  return {
    ...actual,
    bcryptPbkdf: (...args: Parameters<typeof actual.bcryptPbkdf>) => {
      kdf.calls += 1;
      return actual.bcryptPbkdf(...args);
    }
  };
});

const { forgetOpenedPrivateKeys, loadPrivateKey } = await import("../src/core/ssh/private-key.js");
const { FIXTURE_PASSPHRASE, SSH_KEY_FIXTURES } = await import("./ssh-key-fixtures.js");

describe("passphrase-protected keys across reconnects", () => {
  afterEach(() => {
    forgetOpenedPrivateKeys();
    kdf.calls = 0;
  });

  it("derives the key once per session instead of at every reconnect", () => {
    // The KDF runs on Electron's main thread; a reconnect loop paid for it
    // at every attempt.
    const fixture = SSH_KEY_FIXTURES.ed25519;
    const first = loadPrivateKey(fixture.privateKey, FIXTURE_PASSPHRASE);
    const again = loadPrivateKey(fixture.privateKey, FIXTURE_PASSPHRASE);
    expect(kdf.calls).toBe(1);
    expect(again.privateKey).toBe(first.privateKey);

    // A session that ended takes the opened key with it.
    forgetOpenedPrivateKeys();
    loadPrivateKey(fixture.privateKey, FIXTURE_PASSPHRASE);
    expect(kdf.calls).toBe(2);
  });

  it("never answers for a different passphrase", () => {
    const fixture = SSH_KEY_FIXTURES.ed25519;
    loadPrivateKey(fixture.privateKey, FIXTURE_PASSPHRASE);
    expect(() => loadPrivateKey(fixture.privateKey, "wrong horse")).toThrow(/passphrase is wrong/u);
    expect(() => loadPrivateKey(fixture.privateKey)).toThrow(/none was provided/u);
  });
});
