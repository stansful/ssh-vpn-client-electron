import { describe, expect, it } from "vitest";
import { bcryptPbkdf } from "../src/core/ssh/bcrypt-pbkdf.js";

// Vectors from the OpenBSD reference implementation, as carried by
// golang.org/x/crypto/ssh/internal/bcrypt_pbkdf.
const GOLDEN = [
  {
    rounds: 12,
    passphrase: Buffer.from("password"),
    salt: Buffer.from("salt"),
    key: "1ae42c05d487bc02f64921a4ebe4ea93bcacfe135fda99974c06b7b01fae149a"
  },
  {
    rounds: 3,
    passphrase: Buffer.from("passwordy\0PASSWORD\0"),
    salt: Buffer.from("salty\0SALT\0"),
    key: "7f310bd3e78c3280c59ce4595211a2928e8d4ec744c1ed2efc9f764e3388e0ad"
  },
  {
    rounds: 8,
    passphrase: Buffer.from("секретное слово"),
    salt: Buffer.from("посолить немножко"),
    key:
      "8df43fc6fe131fc47f0c9e39224bd94c70b6fcc8ee8135faddf61156e6cb2733ea765f315a3e1e4afc35bf8687d189254c1e05a6fe80c0617f9183d67260d6a1" +
      "15c6c94e3603e2303fbb43a76a64523ffda686b1d4518543"
  }
];

describe("bcrypt_pbkdf", () => {
  it("matches the OpenBSD reference vectors", () => {
    for (const vector of GOLDEN) {
      const expected = Buffer.from(vector.key, "hex");
      expect(bcryptPbkdf(vector.passphrase, vector.salt, expected.length, vector.rounds).toString("hex")).toBe(vector.key);
    }
  });

  it("returns a prefix of a longer derivation only for whole 32-byte blocks", () => {
    // Bytes are interleaved across blocks, so a shorter key is not simply the
    // start of a longer one - except when both need the same number of blocks.
    const long = bcryptPbkdf(Buffer.from("password"), Buffer.from("salt"), 64, 2);
    expect(bcryptPbkdf(Buffer.from("password"), Buffer.from("salt"), 48, 2)).toEqual(long.subarray(0, 48));
    expect(bcryptPbkdf(Buffer.from("password"), Buffer.from("salt"), 32, 2)).not.toEqual(long.subarray(0, 32));
  });

  it("refuses the inputs OpenBSD refuses", () => {
    expect(() => bcryptPbkdf(Buffer.from("password"), Buffer.from("salt"), 32, 0)).toThrow(/round/u);
    expect(() => bcryptPbkdf(Buffer.alloc(0), Buffer.from("salt"), 32, 1)).toThrow(/passphrase/u);
    expect(() => bcryptPbkdf(Buffer.from("password"), Buffer.alloc(0), 32, 1)).toThrow(/salt/u);
    expect(() => bcryptPbkdf(Buffer.from("password"), Buffer.from("salt"), 0, 1)).toThrow(/key length/u);
    expect(() => bcryptPbkdf(Buffer.from("password"), Buffer.from("salt"), 1025, 1)).toThrow(/key length/u);
  });
});
