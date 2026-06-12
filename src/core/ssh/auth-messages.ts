import { SshBinaryWriter } from "./binary.js";

export const SSH_MSG_SERVICE_REQUEST = 5;
export const SSH_MSG_USERAUTH_REQUEST = 50;

export const SSH_SERVICE_USERAUTH = "ssh-userauth";
export const SSH_SERVICE_CONNECTION = "ssh-connection";

export interface PasswordAuthRequest {
  username: string;
  password: string;
  service?: string;
}

export interface PublicKeyAuthProbe {
  username: string;
  publicKeyAlgorithm: string;
  publicKeyBlob: Buffer;
  service?: string;
}

export interface PublicKeyAuthSignedRequest extends PublicKeyAuthProbe {
  signatureBlob: Buffer;
}

export function encodeServiceRequest(serviceName: string): Buffer {
  return new SshBinaryWriter().byte(SSH_MSG_SERVICE_REQUEST).string(serviceName).toBuffer();
}

export function encodePasswordAuthRequest(request: PasswordAuthRequest): Buffer {
  return new SshBinaryWriter()
    .byte(SSH_MSG_USERAUTH_REQUEST)
    .string(request.username)
    .string(request.service ?? SSH_SERVICE_CONNECTION)
    .string("password")
    .boolean(false)
    .string(request.password)
    .toBuffer();
}

export function encodePublicKeyAuthProbe(request: PublicKeyAuthProbe): Buffer {
  return new SshBinaryWriter()
    .byte(SSH_MSG_USERAUTH_REQUEST)
    .string(request.username)
    .string(request.service ?? SSH_SERVICE_CONNECTION)
    .string("publickey")
    .boolean(false)
    .string(request.publicKeyAlgorithm)
    .string(request.publicKeyBlob)
    .toBuffer();
}

export function encodePublicKeyAuthSignedRequest(request: PublicKeyAuthSignedRequest): Buffer {
  return new SshBinaryWriter()
    .byte(SSH_MSG_USERAUTH_REQUEST)
    .string(request.username)
    .string(request.service ?? SSH_SERVICE_CONNECTION)
    .string("publickey")
    .boolean(true)
    .string(request.publicKeyAlgorithm)
    .string(request.publicKeyBlob)
    .string(request.signatureBlob)
    .toBuffer();
}
