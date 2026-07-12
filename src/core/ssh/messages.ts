import { randomBytes } from "node:crypto";
import { SshBinaryReader, SshBinaryWriter } from "./binary.js";

export const SSH_MSG_KEXINIT = 20;

export interface SshKexInit {
  cookie: Buffer;
  kexAlgorithms: string[];
  serverHostKeyAlgorithms: string[];
  encryptionAlgorithmsClientToServer: string[];
  encryptionAlgorithmsServerToClient: string[];
  macAlgorithmsClientToServer: string[];
  macAlgorithmsServerToClient: string[];
  compressionAlgorithmsClientToServer: string[];
  compressionAlgorithmsServerToClient: string[];
  languagesClientToServer: string[];
  languagesServerToClient: string[];
  firstKexPacketFollows: boolean;
  reserved: number;
}

export const DEFAULT_KEX_INIT: Omit<SshKexInit, "cookie"> = {
  kexAlgorithms: ["curve25519-sha256", "curve25519-sha256@libssh.org", "diffie-hellman-group14-sha256"],
  serverHostKeyAlgorithms: ["rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519"],
  // Prefer AES-128 for lower client CPU cost and higher bulk throughput while
  // retaining a full 128-bit security level; stronger-key variants remain
  // available for servers whose policy requires them.
  encryptionAlgorithmsClientToServer: ["aes128-ctr", "aes256-ctr", "aes192-ctr"],
  encryptionAlgorithmsServerToClient: ["aes128-ctr", "aes256-ctr", "aes192-ctr"],
  macAlgorithmsClientToServer: ["hmac-sha2-256", "hmac-sha2-512"],
  macAlgorithmsServerToClient: ["hmac-sha2-256", "hmac-sha2-512"],
  compressionAlgorithmsClientToServer: ["none"],
  compressionAlgorithmsServerToClient: ["none"],
  languagesClientToServer: [],
  languagesServerToClient: [],
  firstKexPacketFollows: false,
  reserved: 0
};

export function createDefaultKexInit(): SshKexInit {
  return {
    cookie: randomBytes(16),
    ...DEFAULT_KEX_INIT
  };
}

export function encodeKexInit(message: SshKexInit): Buffer {
  if (message.cookie.length !== 16) {
    throw new Error("SSH KEXINIT cookie must be 16 bytes.");
  }

  return new SshBinaryWriter()
    .byte(SSH_MSG_KEXINIT)
    .raw(message.cookie)
    .nameList(message.kexAlgorithms)
    .nameList(message.serverHostKeyAlgorithms)
    .nameList(message.encryptionAlgorithmsClientToServer)
    .nameList(message.encryptionAlgorithmsServerToClient)
    .nameList(message.macAlgorithmsClientToServer)
    .nameList(message.macAlgorithmsServerToClient)
    .nameList(message.compressionAlgorithmsClientToServer)
    .nameList(message.compressionAlgorithmsServerToClient)
    .nameList(message.languagesClientToServer)
    .nameList(message.languagesServerToClient)
    .boolean(message.firstKexPacketFollows)
    .uint32(message.reserved)
    .toBuffer();
}

export function decodeKexInit(payload: Buffer): SshKexInit {
  const reader = new SshBinaryReader(payload);
  const messageNumber = reader.byte();
  if (messageNumber !== SSH_MSG_KEXINIT) {
    throw new Error(`Unexpected SSH message ${messageNumber}; expected KEXINIT.`);
  }

  const cookie = reader.remaining().subarray(0, 16);
  if (cookie.length !== 16) {
    throw new Error("SSH KEXINIT payload is missing cookie.");
  }
  const cookieAndRest = reader.remaining();
  const rest = new SshBinaryReader(cookieAndRest.subarray(16));
  const message: SshKexInit = {
    cookie,
    kexAlgorithms: rest.nameList(),
    serverHostKeyAlgorithms: rest.nameList(),
    encryptionAlgorithmsClientToServer: rest.nameList(),
    encryptionAlgorithmsServerToClient: rest.nameList(),
    macAlgorithmsClientToServer: rest.nameList(),
    macAlgorithmsServerToClient: rest.nameList(),
    compressionAlgorithmsClientToServer: rest.nameList(),
    compressionAlgorithmsServerToClient: rest.nameList(),
    languagesClientToServer: rest.nameList(),
    languagesServerToClient: rest.nameList(),
    firstKexPacketFollows: rest.boolean(),
    reserved: rest.uint32()
  };

  if (!rest.eof()) {
    throw new Error("SSH KEXINIT payload has trailing bytes.");
  }
  return message;
}
