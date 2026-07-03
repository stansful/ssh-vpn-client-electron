import os from "node:os";
import path from "node:path";
import type { ServiceEvent } from "../shared/ipc.js";
import type { ConnectRequest, RoutingRule, RoutingUpdateRequest, RuntimeStatus, SshConfig, TunnelCheckResult } from "../shared/types.js";

export type ServiceCommand = { id: string; authToken?: string } & (
  | { type: "get-status" }
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
  | { kind: "response"; id: string; ok: true; payload?: ServiceResponsePayload }
  | { kind: "response"; id: string; ok: false; error: string };

export type ServiceResponsePayload = RuntimeStatus | TunnelCheckResult | { accepted: true };
export type ServiceEventEnvelope = { kind: "event"; event: ServiceEvent };
export type ServiceWireMessage = ServiceCommand | ServiceResponse | ServiceEventEnvelope;

export function defaultServiceEndpoint(appName = "shadow-ssh"): string {
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\${appName}-service`;
  }

  const userId = typeof process.getuid === "function" ? process.getuid() : os.userInfo().username;
  const runtimeDirectory = process.env.SHADOW_SSH_RUNTIME_DIR || process.env.XDG_RUNTIME_DIR || path.join(os.homedir(), ".shadow-ssh", "run");
  return path.join(runtimeDirectory, `${appName}-${userId}.sock`);
}

export function encodeWireMessage(message: ServiceWireMessage): string {
  return `${JSON.stringify(message)}\n`;
}

export function decodeWireMessage(line: string): ServiceWireMessage {
  return JSON.parse(line) as ServiceWireMessage;
}
