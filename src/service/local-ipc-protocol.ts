import os from "node:os";
import path from "node:path";
import { StringDecoder } from "node:string_decoder";
import type { Writable } from "node:stream";
import {
  MAX_DIAGNOSTIC_ID_CHARACTERS,
  MAX_DIAGNOSTIC_MESSAGE_BYTES,
  MAX_DIAGNOSTIC_TIMESTAMP_CHARACTERS
} from "../shared/diagnostics-history.js";
import type { ServiceEvent } from "../shared/ipc.js";
import { utf8ByteLength } from "../shared/terminal-history.js";
import type { ConnectRequest, PlatformTarget, RoutingRule, RoutingUpdateRequest, RuntimeStatus, SshConfig, TunnelCheckResult } from "../shared/types.js";

export const SERVICE_PROTOCOL_VERSION = 1;
export const MAX_SERVICE_WIRE_BYTES = 8 * 1024 * 1024;
export const MAX_SERVICE_ENDPOINT_WIRE_BYTES = 4 * 1024 * 1024;
export const MAX_SERVICE_ENDPOINT_CONNECTIONS = 32;
export const MAX_SERVICE_STDERR_LINE_BYTES = 256 * 1024;
export const MAX_SERVICE_PENDING_REQUESTS = 128;
export const MAX_SERVICE_MESSAGE_ID_LENGTH = 128;
export const MAX_SERVICE_AUTH_TOKEN_LENGTH = 1024;
export const SERVICE_CONNECT_TIMEOUT_MS = 5_000;
export const SERVICE_DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
export const SERVICE_LONG_REQUEST_TIMEOUT_MS = 90_000;

export interface NativeServiceCapabilities {
  target: PlatformTarget;
  ipc: string;
  namedPipeAcl: boolean;
  unixSocketMode: boolean;
  serviceControlManager: boolean;
  wfpInterception: boolean;
  tunDevice: boolean;
  routeManipulation: boolean;
  processConnectionAttribution: boolean;
  dnsVisibility: boolean;
  ipv6RouteEnforcement: boolean;
  udpForwarding: boolean;
  sshCoreLinked: boolean;
}

export interface NativeServiceHandshake {
  protocolVersion: number;
  capabilities: NativeServiceCapabilities;
}

type VersionedWireMessage = { protocolVersion?: number };

const SERVICE_COMMAND_TYPES = new Set([
  "get-status",
  "get-capabilities",
  "connect",
  "disconnect",
  "check-tunnel",
  "open-terminal",
  "close-terminal",
  "terminal-input",
  "update-config",
  "update-routing-rules",
  "update-routing",
  "list-process-connections",
  "shutdown"
]);
const SERVICE_EVENT_TYPES = new Set([
  "status-changed",
  "diagnostics-appended",
  "tunnel-check-result",
  "terminal-output",
  "error"
]);
const CONNECTION_STATES = new Set(["Disconnected", "Connecting", "Connected", "Reconnecting", "Disconnecting", "Error"]);
const SERVICE_TRANSPORTS = new Set(["native-ipc", "live-ssh", "xray", "simulator"]);
const DESKTOP_PLATFORMS = new Set(["windows", "macos", "linux", "unknown"]);
const RUNTIME_ARCHITECTURES = new Set(["x64", "arm64", "ia32", "unknown"]);

export type ServiceCommand = VersionedWireMessage & { id: string; authToken?: string } & (
  | { type: "get-status" }
  | { type: "get-capabilities" }
  | { type: "connect"; payload: ConnectRequest }
  | { type: "disconnect" }
  | { type: "check-tunnel"; payload: { endpoint: string } }
  | { type: "open-terminal" }
  | { type: "close-terminal" }
  | { type: "terminal-input"; payload: { input: string } }
  | { type: "update-config"; payload: { config: SshConfig } }
  | { type: "update-routing-rules"; payload: { rules: RoutingRule[] } }
  | { type: "update-routing"; payload: RoutingUpdateRequest }
  | { type: "list-process-connections" }
  | { type: "shutdown" }
);

export type ServiceResponse =
  | (VersionedWireMessage & { kind: "response"; id: string; ok: true; payload?: ServiceResponsePayload })
  | (VersionedWireMessage & { kind: "response"; id: string; ok: false; error: string });

export type ServiceResponsePayload = RuntimeStatus | TunnelCheckResult | NativeServiceHandshake | { accepted: true };
export type ServiceEventEnvelope = VersionedWireMessage & { kind: "event"; event: ServiceEvent };
export type ServiceWireMessage = ServiceCommand | ServiceResponse | ServiceEventEnvelope;

export class ServiceProtocolError extends Error {}

export function defaultServiceEndpoint(appName = "shadow-ssh"): string {
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\${appName}-service`;
  }

  const userId = typeof process.getuid === "function" ? process.getuid() : os.userInfo().username;
  const runtimeDirectory = process.env.SHADOW_SSH_RUNTIME_DIR || process.env.XDG_RUNTIME_DIR || path.join(os.homedir(), ".shadow-ssh", "run");
  return path.join(runtimeDirectory, `${appName}-${userId}.sock`);
}

export function encodeWireMessage(message: ServiceWireMessage): string {
  const encoded = `${JSON.stringify({ ...message, protocolVersion: SERVICE_PROTOCOL_VERSION })}\n`;
  if (Buffer.byteLength(encoded, "utf8") > MAX_SERVICE_WIRE_BYTES) {
    throw new ServiceProtocolError(`Service wire message exceeds ${MAX_SERVICE_WIRE_BYTES} bytes.`);
  }
  return encoded;
}

export function decodeWireMessage(line: string): ServiceWireMessage {
  if (Buffer.byteLength(line, "utf8") > MAX_SERVICE_WIRE_BYTES) {
    throw new ServiceProtocolError(`Service wire message exceeds ${MAX_SERVICE_WIRE_BYTES} bytes.`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch (error) {
    throw new ServiceProtocolError(`Invalid service JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!isRecord(parsed)) {
    throw new ServiceProtocolError("Service wire message must be an object.");
  }
  if (parsed.protocolVersion !== SERVICE_PROTOCOL_VERSION) {
    throw new ServiceProtocolError(
      `Unsupported service protocol version ${String(parsed.protocolVersion ?? "missing")}; expected ${SERVICE_PROTOCOL_VERSION}.`
    );
  }

  if (parsed.kind === "response") {
    if (!isWireMessageId(parsed.id) || typeof parsed.ok !== "boolean") {
      throw new ServiceProtocolError("Malformed service response envelope.");
    }
    if (!parsed.ok && typeof parsed.error !== "string") {
      throw new ServiceProtocolError("Malformed service error response.");
    }
    return parsed as ServiceResponse;
  }
  if (parsed.kind === "event") {
    if (!isServiceEvent(parsed.event)) {
      throw new ServiceProtocolError("Malformed service event envelope.");
    }
    return parsed as ServiceEventEnvelope;
  }
  if (parsed.kind !== undefined) {
    throw new ServiceProtocolError(`Unsupported service wire message kind ${String(parsed.kind)}.`);
  }
  if (
    !isWireMessageId(parsed.id) ||
    typeof parsed.type !== "string" ||
    !SERVICE_COMMAND_TYPES.has(parsed.type) ||
    (parsed.authToken !== undefined && (typeof parsed.authToken !== "string" || parsed.authToken.length > MAX_SERVICE_AUTH_TOKEN_LENGTH))
  ) {
    throw new ServiceProtocolError("Malformed service command envelope.");
  }
  return parsed as ServiceCommand;
}

export class BoundedUtf8LineDecoder {
  private readonly decoder = new StringDecoder("utf8");
  private buffer = "";

  constructor(
    private readonly maxLineBytes: number,
    private readonly label = "line"
  ) {}

  push(chunk: Buffer): string[] {
    this.buffer += this.decoder.write(chunk);
    return this.takeLines(false);
  }

  end(): string[] {
    this.buffer += this.decoder.end();
    return this.takeLines(true);
  }

  private takeLines(flushRemainder: boolean): string[] {
    const lines: string[] = [];
    let newlineIndex = this.buffer.indexOf("\n");
    while (newlineIndex >= 0) {
      const line = this.buffer.slice(0, newlineIndex).replace(/\r$/u, "");
      this.assertWithinLimit(line);
      lines.push(line);
      this.buffer = this.buffer.slice(newlineIndex + 1);
      newlineIndex = this.buffer.indexOf("\n");
    }

    if (flushRemainder && this.buffer.length > 0) {
      this.assertWithinLimit(this.buffer);
      lines.push(this.buffer);
      this.buffer = "";
    } else {
      this.assertWithinLimit(this.buffer);
    }
    return lines;
  }

  private assertWithinLimit(value: string): void {
    if (Buffer.byteLength(value, "utf8") > this.maxLineBytes) {
      throw new ServiceProtocolError(`${this.label} exceeds ${this.maxLineBytes} bytes.`);
    }
  }
}

export class ServiceWireDecoder {
  private readonly lines: BoundedUtf8LineDecoder;

  constructor(maxWireBytes = MAX_SERVICE_WIRE_BYTES) {
    this.lines = new BoundedUtf8LineDecoder(maxWireBytes, "Service wire frame");
  }

  push(chunk: Buffer): ServiceWireMessage[] {
    return this.lines.push(chunk).flatMap((line) => {
      const trimmed = line.trim();
      return trimmed ? [decodeWireMessage(trimmed)] : [];
    });
  }

  end(): ServiceWireMessage[] {
    return this.lines.end().flatMap((line) => {
      const trimmed = line.trim();
      return trimmed ? [decodeWireMessage(trimmed)] : [];
    });
  }
}

export function requestTimeoutMs(commandType: ServiceCommand["type"]): number {
  if (commandType === "connect") {
    return SERVICE_LONG_REQUEST_TIMEOUT_MS;
  }
  return commandType === "get-status" || commandType === "get-capabilities"
    ? SERVICE_CONNECT_TIMEOUT_MS
    : SERVICE_DEFAULT_REQUEST_TIMEOUT_MS;
}

export function isNativeServiceHandshake(value: unknown): value is NativeServiceHandshake {
  if (!isRecord(value) || value.protocolVersion !== SERVICE_PROTOCOL_VERSION || !isRecord(value.capabilities)) {
    return false;
  }
  const capabilities = value.capabilities;
  const target = capabilities.target;
  return (
    isPlatformTargetPayload(target) &&
    typeof capabilities.ipc === "string" &&
    typeof capabilities.namedPipeAcl === "boolean" &&
    typeof capabilities.unixSocketMode === "boolean" &&
    typeof capabilities.serviceControlManager === "boolean" &&
    typeof capabilities.wfpInterception === "boolean" &&
    typeof capabilities.tunDevice === "boolean" &&
    typeof capabilities.routeManipulation === "boolean" &&
    typeof capabilities.processConnectionAttribution === "boolean" &&
    typeof capabilities.dnsVisibility === "boolean" &&
    typeof capabilities.ipv6RouteEnforcement === "boolean" &&
    typeof capabilities.udpForwarding === "boolean" &&
    typeof capabilities.sshCoreLinked === "boolean"
  );
}

export function isRuntimeStatusPayload(value: unknown): value is RuntimeStatus {
  return (
    isRecord(value) &&
    typeof value.state === "string" && CONNECTION_STATES.has(value.state) &&
    typeof value.message === "string" &&
    typeof value.reconnectAttempt === "number" && Number.isInteger(value.reconnectAttempt) && value.reconnectAttempt >= 0 &&
    typeof value.transport === "string" && SERVICE_TRANSPORTS.has(value.transport) &&
    typeof value.realTunnelAvailable === "boolean" &&
    (value.activeConfigId === undefined || typeof value.activeConfigId === "string") &&
    (value.connectedAt === undefined || typeof value.connectedAt === "string") &&
    isPlatformTargetPayload(value.platformTarget)
  );
}

export function isTunnelCheckResultPayload(value: unknown): value is TunnelCheckResult {
  return (
    isRecord(value) &&
    typeof value.endpoint === "string" &&
    typeof value.ok === "boolean" &&
    typeof value.at === "string" &&
    typeof value.message === "string"
  );
}

function isPlatformTargetPayload(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.platform === "string" && DESKTOP_PLATFORMS.has(value.platform) &&
    typeof value.arch === "string" && RUNTIME_ARCHITECTURES.has(value.arch) &&
    typeof value.serviceExecutableName === "string" &&
    typeof value.serviceRelativePath === "string" &&
    typeof value.supportsPrivilegedService === "boolean"
  );
}

function isServiceEvent(value: unknown): value is ServiceEvent {
  if (!isRecord(value) || typeof value.type !== "string" || !SERVICE_EVENT_TYPES.has(value.type)) {
    return false;
  }
  if (value.type === "status-changed") {
    return isRuntimeStatusPayload(value.status);
  }
  if (value.type === "diagnostics-appended") {
    const entry = value.entry;
    return (
      isRecord(entry) &&
      typeof entry.id === "string" &&
      entry.id.length <= MAX_DIAGNOSTIC_ID_CHARACTERS &&
      typeof entry.at === "string" &&
      entry.at.length <= MAX_DIAGNOSTIC_TIMESTAMP_CHARACTERS &&
      typeof entry.level === "string" &&
      (entry.level === "info" || entry.level === "warning" || entry.level === "error") &&
      typeof entry.message === "string" &&
      utf8ByteLength(entry.message) <= MAX_DIAGNOSTIC_MESSAGE_BYTES
    );
  }
  if (value.type === "tunnel-check-result") {
    return isTunnelCheckResultPayload(value.result);
  }
  if (value.type === "terminal-output") {
    const line = value.line;
    return (
      isRecord(line) &&
      typeof line.id === "string" &&
      typeof line.at === "string" &&
      typeof line.stream === "string" &&
      (line.stream === "stdout" || line.stream === "stderr" || line.stream === "system") &&
      typeof line.text === "string"
    );
  }
  return (
    value.type === "error" &&
    typeof value.message === "string" &&
    utf8ByteLength(value.message) <= MAX_DIAGNOSTIC_MESSAGE_BYTES
  );
}

export async function writeWithBackpressure(writer: Writable, data: string): Promise<void> {
  if (writer.destroyed || !writer.writable) {
    throw new Error("Service IPC writer is not writable.");
  }

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    let writeReturned = false;
    let callbackComplete = false;
    let drainComplete = true;

    const cleanup = (): void => {
      writer.off("error", onError);
      writer.off("close", onClose);
      writer.off("drain", onDrain);
    };
    const finish = (error?: Error): void => {
      if (settled) {
        return;
      }
      if (!error && (!writeReturned || !callbackComplete || !drainComplete)) {
        return;
      }
      settled = true;
      cleanup();
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    };
    const onError = (error: Error): void => finish(error);
    const onClose = (): void => finish(new Error("Service IPC writer closed while writing."));
    const onDrain = (): void => {
      drainComplete = true;
      finish();
    };

    writer.once("error", onError);
    writer.once("close", onClose);
    try {
      const accepted = writer.write(data, "utf8", (error?: Error | null) => {
        callbackComplete = true;
        finish(error ?? undefined);
      });
      drainComplete = accepted;
      if (!accepted) {
        writer.once("drain", onDrain);
      }
      writeReturned = true;
      finish();
    } catch (error) {
      finish(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isWireMessageId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_SERVICE_MESSAGE_ID_LENGTH;
}
