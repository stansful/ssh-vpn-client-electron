import { SshBinaryReader, SshBinaryWriter } from "./binary.js";

export const SSH_MSG_DISCONNECT = 1;
export const SSH_MSG_IGNORE = 2;
export const SSH_MSG_UNIMPLEMENTED = 3;
export const SSH_MSG_DEBUG = 4;
export const SSH_MSG_GLOBAL_REQUEST = 80;
export const SSH_MSG_REQUEST_SUCCESS = 81;
export const SSH_MSG_REQUEST_FAILURE = 82;

export function encodeDisconnect(reasonCode: number, description: string, language = ""): Buffer {
  return new SshBinaryWriter()
    .byte(SSH_MSG_DISCONNECT)
    .uint32(reasonCode)
    .string(description)
    .string(language)
    .toBuffer();
}

export function encodeKeepaliveRequest(requestName = "keepalive@openssh.com", wantReply = true): Buffer {
  return new SshBinaryWriter().byte(SSH_MSG_GLOBAL_REQUEST).string(requestName).boolean(wantReply).toBuffer();
}

export function decodeGlobalRequest(payload: Buffer): { requestName: string; wantReply: boolean; requestData: Buffer } {
  const reader = new SshBinaryReader(payload);
  if (reader.byte() !== SSH_MSG_GLOBAL_REQUEST) {
    throw new Error("Expected SSH_MSG_GLOBAL_REQUEST.");
  }
  return {
    requestName: reader.utf8String(),
    wantReply: reader.boolean(),
    requestData: reader.remaining()
  };
}

export function encodeRequestFailure(): Buffer {
  return Buffer.from([SSH_MSG_REQUEST_FAILURE]);
}
