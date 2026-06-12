import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { deriveTransportKeys, transportKeyLengthsFor } from "../src/core/ssh/key-derivation.js";
import {
  SshEncryptedPacketStreamReader,
  SshEncryptedPacketStreamWriter,
  SshPlainPacketStreamReader,
  SshPlainPacketStreamWriter
} from "../src/core/ssh/packet-stream.js";
import { readServerIdentificationLine } from "../src/core/ssh/socket-transport.js";

describe("SSH packet stream reader/writer", () => {
  it("handles partial plaintext packet reads", () => {
    const writer = new SshPlainPacketStreamWriter();
    const reader = new SshPlainPacketStreamReader();
    const frame = writer.write(Buffer.from("hello"));

    expect(reader.push(frame.subarray(0, 3))).toEqual([]);
    expect(reader.push(frame.subarray(3))).toEqual([Buffer.from("hello")]);
  });

  it("handles partial encrypted packet reads with MAC verification", () => {
    const keys = deriveTransportKeys(123n, Buffer.alloc(32, 1), Buffer.alloc(32, 2), transportKeyLengthsFor("aes256-ctr", "hmac-sha2-256"));
    const config = {
      cipherName: "aes256-ctr" as const,
      encryptionKey: keys.encryptionKeyClientToServer,
      initialIv: keys.initialIvClientToServer,
      macName: "hmac-sha2-256" as const,
      macKey: keys.integrityKeyClientToServer
    };
    const writer = new SshEncryptedPacketStreamWriter(config);
    const reader = new SshEncryptedPacketStreamReader(config);
    const frame = writer.write(Buffer.from("encrypted"));

    expect(reader.push(frame.subarray(0, 2))).toEqual([]);
    expect(reader.push(frame.subarray(2, 19))).toEqual([]);
    expect(reader.push(frame.subarray(19))).toEqual([Buffer.from("encrypted")]);
  });

  it("continues MAC sequence numbers after plaintext packets", () => {
    const plainWriter = new SshPlainPacketStreamWriter();
    const plainReader = new SshPlainPacketStreamReader();
    plainReader.push(plainWriter.write(Buffer.from("kexinit")));
    plainReader.push(plainWriter.write(Buffer.from("newkeys")));

    const keys = deriveTransportKeys(456n, Buffer.alloc(32, 1), Buffer.alloc(32, 2), transportKeyLengthsFor("aes256-ctr", "hmac-sha2-256"));
    const config = {
      cipherName: "aes256-ctr" as const,
      encryptionKey: keys.encryptionKeyClientToServer,
      initialIv: keys.initialIvClientToServer,
      macName: "hmac-sha2-256" as const,
      macKey: keys.integrityKeyClientToServer
    };
    const encryptedWriter = new SshEncryptedPacketStreamWriter(config, plainWriter.getSequenceNumber());
    const encryptedReader = new SshEncryptedPacketStreamReader(config, plainReader.getSequenceNumber());

    expect(encryptedReader.push(encryptedWriter.write(Buffer.from("service-request")))).toEqual([Buffer.from("service-request")]);
    expect(encryptedWriter.getSequenceNumber()).toBe(3);
    expect(encryptedReader.getSequenceNumber()).toBe(3);
  });

  it("reads SSH identification while ignoring pre-banner lines", async () => {
    const stream = new PassThrough() as unknown as NodeJS.ReadWriteStream;
    const promise = readServerIdentificationLine(stream as never);
    stream.write("notice\r\nSSH-2.0-TestServer_1.0\r\n");

    await expect(promise).resolves.toBe("SSH-2.0-TestServer_1.0");
  });
});
