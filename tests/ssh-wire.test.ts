import { describe, expect, it } from "vitest";
import { SshBinaryReader, SshBinaryWriter } from "../src/core/ssh/binary.js";
import { createDefaultKexInit, decodeKexInit, encodeKexInit, SSH_MSG_KEXINIT } from "../src/core/ssh/messages.js";
import { decodeSshPacket, encodeSshPacket } from "../src/core/ssh/packet.js";
import { formatClientVersion, parseSshVersionLine } from "../src/core/ssh/version.js";

describe("SSH wire primitives", () => {
  it("round-trips primitive SSH binary values", () => {
    const buffer = new SshBinaryWriter()
      .byte(7)
      .boolean(true)
      .uint32(42)
      .string("shadow")
      .nameList(["aes256-ctr", "aes128-ctr"])
      .mpint(0x80n)
      .toBuffer();

    const reader = new SshBinaryReader(buffer);
    expect(reader.byte()).toBe(7);
    expect(reader.boolean()).toBe(true);
    expect(reader.uint32()).toBe(42);
    expect(reader.utf8String()).toBe("shadow");
    expect(reader.nameList()).toEqual(["aes256-ctr", "aes128-ctr"]);
    expect(reader.mpint()).toBe(0x80n);
    expect(reader.eof()).toBe(true);
  });

  it("frames and decodes SSH packets", () => {
    const payload = Buffer.from([SSH_MSG_KEXINIT, 1, 2, 3]);
    const packet = encodeSshPacket(payload);
    const decoded = decodeSshPacket(packet);

    expect(packet.length % 8).toBe(0);
    expect(decoded.payload).toEqual(payload);
    expect(decoded.padding.length).toBeGreaterThanOrEqual(4);
  });

  it("encodes and decodes KEXINIT", () => {
    const message = createDefaultKexInit();
    const decoded = decodeKexInit(encodeKexInit(message));

    expect(decoded.cookie).toEqual(message.cookie);
    expect(decoded.kexAlgorithms).toContain("curve25519-sha256");
    expect(decoded.encryptionAlgorithmsClientToServer).toContain("aes256-ctr");
  });

  it("formats and parses SSH version lines", () => {
    expect(formatClientVersion("shadow-ssh-test")).toBe("SSH-2.0-shadow-ssh-test\r\n");
    expect(parseSshVersionLine("SSH-2.0-OpenSSH_9.7 comments\r\n")).toEqual({
      protocol: "2.0",
      software: "OpenSSH_9.7",
      comments: "comments",
      raw: "SSH-2.0-OpenSSH_9.7 comments"
    });
  });
});
