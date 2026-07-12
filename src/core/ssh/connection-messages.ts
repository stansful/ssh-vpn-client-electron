import { SshBinaryReader } from "./binary.js";

export const SSH_MSG_NEWKEYS = 21;
export const SSH_MSG_SERVICE_ACCEPT = 6;
export const SSH_MSG_USERAUTH_FAILURE = 51;
export const SSH_MSG_USERAUTH_SUCCESS = 52;
export const SSH_MSG_USERAUTH_BANNER = 53;
export const SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
export const SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
export const SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
export const SSH_MSG_CHANNEL_DATA = 94;
export const SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
export const SSH_MSG_CHANNEL_EOF = 96;
export const SSH_MSG_CHANNEL_CLOSE = 97;
export const SSH_MSG_CHANNEL_SUCCESS = 99;
export const SSH_MSG_CHANNEL_FAILURE = 100;

export interface UserAuthFailure {
  methodsThatCanContinue: string[];
  partialSuccess: boolean;
}

export interface ChannelOpenConfirmation {
  recipientChannel: number;
  senderChannel: number;
  initialWindowSize: number;
  maximumPacketSize: number;
}

export interface ChannelOpenFailure {
  recipientChannel: number;
  reasonCode: number;
  description: string;
  languageTag: string;
}

export interface ChannelWindowAdjust {
  recipientChannel: number;
  bytesToAdd: number;
}

export interface ChannelDataPayload {
  recipientChannel: number;
  data: Buffer;
}

export interface ChannelExtendedDataPayload extends ChannelDataPayload {
  dataTypeCode: number;
}

export interface ChannelOpenRequest {
  channelType: string;
  senderChannel: number;
  initialWindowSize: number;
  maximumPacketSize: number;
  requestData: Buffer;
}

export interface ChannelRequest {
  recipientChannel: number;
  requestType: string;
  wantReply: boolean;
  requestData: Buffer;
}

export function messageNumber(payload: Buffer): number {
  if (payload.length === 0) {
    throw new Error("SSH payload is empty.");
  }
  return payload.readUInt8(0);
}

export function decodeServiceAccept(payload: Buffer): string {
  const reader = expectMessage(payload, SSH_MSG_SERVICE_ACCEPT);
  const serviceName = reader.utf8String();
  ensureEof(reader, "SERVICE_ACCEPT");
  return serviceName;
}

export function decodeUserAuthFailure(payload: Buffer): UserAuthFailure {
  const reader = expectMessage(payload, SSH_MSG_USERAUTH_FAILURE);
  const failure = {
    methodsThatCanContinue: reader.nameList(),
    partialSuccess: reader.boolean()
  };
  ensureEof(reader, "USERAUTH_FAILURE");
  return failure;
}

export function decodeChannelOpenConfirmation(payload: Buffer): ChannelOpenConfirmation {
  const reader = expectMessage(payload, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
  const confirmation = {
    recipientChannel: reader.uint32(),
    senderChannel: reader.uint32(),
    initialWindowSize: reader.uint32(),
    maximumPacketSize: reader.uint32()
  };
  ensureEof(reader, "CHANNEL_OPEN_CONFIRMATION");
  return confirmation;
}

export function decodeChannelOpenFailure(payload: Buffer): ChannelOpenFailure {
  const reader = expectMessage(payload, SSH_MSG_CHANNEL_OPEN_FAILURE);
  const failure = {
    recipientChannel: reader.uint32(),
    reasonCode: reader.uint32(),
    description: reader.utf8String(),
    languageTag: reader.utf8String()
  };
  ensureEof(reader, "CHANNEL_OPEN_FAILURE");
  return failure;
}

export function decodeChannelWindowAdjust(payload: Buffer): ChannelWindowAdjust {
  const reader = expectMessage(payload, SSH_MSG_CHANNEL_WINDOW_ADJUST);
  const adjust = {
    recipientChannel: reader.uint32(),
    bytesToAdd: reader.uint32()
  };
  ensureEof(reader, "CHANNEL_WINDOW_ADJUST");
  return adjust;
}

export function decodeChannelData(payload: Buffer): ChannelDataPayload {
  const reader = expectMessage(payload, SSH_MSG_CHANNEL_DATA);
  const data = {
    recipientChannel: reader.uint32(),
    data: reader.string()
  };
  ensureEof(reader, "CHANNEL_DATA");
  return data;
}

export function decodeChannelExtendedData(payload: Buffer): ChannelExtendedDataPayload {
  const reader = expectMessage(payload, SSH_MSG_CHANNEL_EXTENDED_DATA);
  const data = {
    recipientChannel: reader.uint32(),
    dataTypeCode: reader.uint32(),
    data: reader.string()
  };
  ensureEof(reader, "CHANNEL_EXTENDED_DATA");
  return data;
}

export function decodeChannelOpen(payload: Buffer): ChannelOpenRequest {
  const reader = expectMessage(payload, 90);
  return {
    channelType: reader.utf8String(),
    senderChannel: reader.uint32(),
    initialWindowSize: reader.uint32(),
    maximumPacketSize: reader.uint32(),
    requestData: reader.remaining()
  };
}

export function decodeChannelRequest(payload: Buffer): ChannelRequest {
  const reader = expectMessage(payload, 98);
  return {
    recipientChannel: reader.uint32(),
    requestType: reader.utf8String(),
    wantReply: reader.boolean(),
    requestData: reader.remaining()
  };
}

export function decodeChannelEndpoint(payload: Buffer, expectedMessage: number): number {
  const reader = expectMessage(payload, expectedMessage);
  const recipientChannel = reader.uint32();
  ensureEof(reader, `message ${expectedMessage}`);
  return recipientChannel;
}

export function expectMessage(payload: Buffer, expectedMessage: number): SshBinaryReader {
  const reader = new SshBinaryReader(payload);
  const actual = reader.byte();
  if (actual !== expectedMessage) {
    throw new Error(`Unexpected SSH message ${actual}; expected ${expectedMessage}.`);
  }
  return reader;
}

function ensureEof(reader: SshBinaryReader, label: string): void {
  if (!reader.eof()) {
    throw new Error(`SSH ${label} payload has trailing bytes.`);
  }
}
