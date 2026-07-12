import { SshBinaryWriter } from "./binary.js";

export const SSH_MSG_CHANNEL_OPEN = 90;
export const SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
export const SSH_MSG_CHANNEL_DATA = 94;
export const SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
export const SSH_MSG_CHANNEL_EOF = 96;
export const SSH_MSG_CHANNEL_CLOSE = 97;
export const SSH_MSG_CHANNEL_REQUEST = 98;
export const SSH_MSG_CHANNEL_FAILURE = 100;

export interface ChannelOpenBase {
  senderChannel: number;
  initialWindowSize?: number;
  maximumPacketSize?: number;
}

export interface DirectTcpIpChannelOpen extends ChannelOpenBase {
  hostToConnect: string;
  portToConnect: number;
  originatorIpAddress: string;
  originatorPort: number;
}

export interface PtyRequest {
  recipientChannel: number;
  terminalType?: string;
  columns: number;
  rows: number;
  pixelWidth?: number;
  pixelHeight?: number;
  terminalModes?: Buffer;
  wantReply?: boolean;
}

export interface ShellRequest {
  recipientChannel: number;
  wantReply?: boolean;
}

export interface WindowChangeRequest {
  recipientChannel: number;
  columns: number;
  rows: number;
  pixelWidth?: number;
  pixelHeight?: number;
  wantReply?: boolean;
}

export interface ChannelData {
  recipientChannel: number;
  data: Buffer;
}

const DEFAULT_WINDOW_SIZE = 1024 * 1024;
const DEFAULT_MAX_PACKET_SIZE = 32 * 1024;

export function encodeSessionChannelOpen(request: ChannelOpenBase): Buffer {
  return new SshBinaryWriter()
    .byte(SSH_MSG_CHANNEL_OPEN)
    .string("session")
    .uint32(request.senderChannel)
    .uint32(request.initialWindowSize ?? DEFAULT_WINDOW_SIZE)
    .uint32(request.maximumPacketSize ?? DEFAULT_MAX_PACKET_SIZE)
    .toBuffer();
}

export function encodeDirectTcpIpChannelOpen(request: DirectTcpIpChannelOpen): Buffer {
  return new SshBinaryWriter()
    .byte(SSH_MSG_CHANNEL_OPEN)
    .string("direct-tcpip")
    .uint32(request.senderChannel)
    .uint32(request.initialWindowSize ?? DEFAULT_WINDOW_SIZE)
    .uint32(request.maximumPacketSize ?? DEFAULT_MAX_PACKET_SIZE)
    .string(request.hostToConnect)
    .uint32(request.portToConnect)
    .string(request.originatorIpAddress)
    .uint32(request.originatorPort)
    .toBuffer();
}

export function encodePtyRequest(request: PtyRequest): Buffer {
  return new SshBinaryWriter()
    .byte(SSH_MSG_CHANNEL_REQUEST)
    .uint32(request.recipientChannel)
    .string("pty-req")
    .boolean(request.wantReply ?? true)
    .string(request.terminalType ?? "xterm-256color")
    .uint32(request.columns)
    .uint32(request.rows)
    .uint32(request.pixelWidth ?? 0)
    .uint32(request.pixelHeight ?? 0)
    .string(request.terminalModes ?? Buffer.from([0]))
    .toBuffer();
}

export function encodeShellRequest(request: ShellRequest): Buffer {
  return new SshBinaryWriter()
    .byte(SSH_MSG_CHANNEL_REQUEST)
    .uint32(request.recipientChannel)
    .string("shell")
    .boolean(request.wantReply ?? true)
    .toBuffer();
}

export function encodeWindowChangeRequest(request: WindowChangeRequest): Buffer {
  return new SshBinaryWriter()
    .byte(SSH_MSG_CHANNEL_REQUEST)
    .uint32(request.recipientChannel)
    .string("window-change")
    .boolean(request.wantReply ?? false)
    .uint32(request.columns)
    .uint32(request.rows)
    .uint32(request.pixelWidth ?? 0)
    .uint32(request.pixelHeight ?? 0)
    .toBuffer();
}

export function encodeChannelData(request: ChannelData): Buffer {
  if (!Number.isInteger(request.recipientChannel) || request.recipientChannel < 0 || request.recipientChannel > 0xffff_ffff) {
    throw new Error("SSH channel recipient is outside uint32 range.");
  }
  // CHANNEL_DATA is the dominant upload hot path. Allocate its exact wire
  // payload once instead of creating byte/uint32/string fragments and joining
  // them through Buffer.concat before packet encryption.
  const payload = Buffer.allocUnsafe(9 + request.data.length);
  payload.writeUInt8(SSH_MSG_CHANNEL_DATA, 0);
  payload.writeUInt32BE(request.recipientChannel, 1);
  payload.writeUInt32BE(request.data.length, 5);
  request.data.copy(payload, 9);
  return payload;
}

export function encodeChannelWindowAdjust(recipientChannel: number, bytesToAdd: number): Buffer {
  return new SshBinaryWriter().byte(SSH_MSG_CHANNEL_WINDOW_ADJUST).uint32(recipientChannel).uint32(bytesToAdd).toBuffer();
}

export function encodeChannelEof(recipientChannel: number): Buffer {
  return new SshBinaryWriter().byte(SSH_MSG_CHANNEL_EOF).uint32(recipientChannel).toBuffer();
}

export function encodeChannelClose(recipientChannel: number): Buffer {
  return new SshBinaryWriter().byte(SSH_MSG_CHANNEL_CLOSE).uint32(recipientChannel).toBuffer();
}

export function encodeChannelOpenFailure(
  recipientChannel: number,
  reasonCode = 1,
  description = "Server-initiated channels are not supported.",
  language = ""
): Buffer {
  return new SshBinaryWriter()
    .byte(SSH_MSG_CHANNEL_OPEN_FAILURE)
    .uint32(recipientChannel)
    .uint32(reasonCode)
    .string(description)
    .string(language)
    .toBuffer();
}

export function encodeChannelFailure(recipientChannel: number): Buffer {
  return new SshBinaryWriter().byte(SSH_MSG_CHANNEL_FAILURE).uint32(recipientChannel).toBuffer();
}
