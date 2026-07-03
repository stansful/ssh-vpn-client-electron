import net from "node:net";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { createDefaultRuntimeStatus } from "../shared/defaults.js";
import type { ServiceEvent } from "../shared/ipc.js";
import type { RoutingRule, SshConfig } from "../shared/types.js";
import { createPlatformTarget } from "../main/platform/targets.js";
import { decodeWireMessage, defaultServiceEndpoint, encodeWireMessage, type ServiceCommand, type ServiceResponsePayload } from "./local-ipc-protocol.js";
import { InProcessServiceBridge } from "./in-process-service.js";

const endpoint = readArg("--endpoint") ?? process.env.SHADOW_SSH_SERVICE_ENDPOINT ?? defaultServiceEndpoint();
const runtime = {
  ...createDefaultRuntimeStatus(createPlatformTarget()),
  transport: "native-ipc" as const,
  realTunnelAvailable: false,
  message: "Standalone simulator service is running over local IPC."
};
const bridge = new InProcessServiceBridge(runtime);
const clients = new Set<net.Socket>();
const buffers = new Map<net.Socket, string>();
let activeConfig: SshConfig | undefined;
let routingRules: RoutingRule[] = [];

bridge.onEvent((event) => {
  broadcast({ kind: "event", event });
});

const server = net.createServer((socket) => {
  clients.add(socket);
  buffers.set(socket, "");
  socket.on("data", (chunk) => handleData(socket, chunk));
  socket.on("error", () => cleanupSocket(socket));
  socket.on("close", () => cleanupSocket(socket));
});

if (process.platform !== "win32") {
  await mkdir(path.dirname(endpoint), { recursive: true });
}

server.listen(endpoint, () => {
  process.stdout.write(`shadow-ssh service simulator listening on ${endpoint}\n`);
});

function handleData(socket: net.Socket, chunk: Buffer): void {
  const current = buffers.get(socket) ?? "";
  let buffer = current + chunk.toString("utf8");
  let newlineIndex = buffer.indexOf("\n");
  while (newlineIndex >= 0) {
    const rawLine = buffer.slice(0, newlineIndex).trim();
    buffer = buffer.slice(newlineIndex + 1);
    if (rawLine) {
      void handleLine(socket, rawLine);
    }
    newlineIndex = buffer.indexOf("\n");
  }
  buffers.set(socket, buffer);
}

async function handleLine(socket: net.Socket, rawLine: string): Promise<void> {
  try {
    const message = decodeWireMessage(rawLine);
    if (!("type" in message)) {
      return;
    }
    const payload = await executeCommand(message);
    socket.write(encodeWireMessage({ kind: "response", id: message.id, ok: true, payload }));
  } catch (error) {
    const id = readCommandId(rawLine);
    if (id) {
      socket.write(encodeWireMessage({ kind: "response", id, ok: false, error: error instanceof Error ? error.message : String(error) }));
    }
  }
}

async function executeCommand(command: ServiceCommand): Promise<ServiceResponsePayload | undefined> {
  authorize(command);
  switch (command.type) {
    case "get-status":
      return bridge.getStatus();
    case "connect":
      await bridge.connect(command.payload);
      return { accepted: true };
    case "disconnect":
      await bridge.disconnect();
      return { accepted: true };
    case "check-tunnel":
      return bridge.checkTunnel(command.payload.endpoint);
    case "open-terminal":
      await bridge.openTerminal();
      return { accepted: true };
    case "close-terminal":
      await bridge.closeTerminal();
      return { accepted: true };
    case "terminal-input":
      await bridge.terminalInput(command.payload.input);
      return { accepted: true };
    case "update-config":
      activeConfig = command.payload.config;
      await bridge.updateConfig(activeConfig);
      return { accepted: true };
    case "update-routing-rules":
      routingRules = command.payload.rules;
      await bridge.updateRoutingRules(routingRules);
      return { accepted: true };
    case "shutdown":
      await bridge.disconnect();
      server.close();
      return { accepted: true };
  }
}

function authorize(command: ServiceCommand): void {
  const expected = process.env.SHADOW_SSH_SERVICE_TOKEN;
  if (expected && command.authToken !== expected) {
    throw new Error("Unauthorized service command.");
  }
}

function broadcast(event: { kind: "event"; event: ServiceEvent }): void {
  const line = encodeWireMessage(event);
  for (const client of clients) {
    if (client.destroyed || !client.writable) {
      cleanupSocket(client);
      continue;
    }
    client.write(line, (error) => {
      if (error) {
        cleanupSocket(client);
      }
    });
  }
}

function cleanupSocket(socket: net.Socket): void {
  clients.delete(socket);
  buffers.delete(socket);
}

function readArg(name: string): string | undefined {
  const prefix = `${name}=`;
  return process.argv.find((arg) => arg.startsWith(prefix))?.slice(prefix.length);
}

function readCommandId(rawLine: string): string | undefined {
  try {
    const parsed = JSON.parse(rawLine) as { id?: unknown };
    return typeof parsed.id === "string" ? parsed.id : undefined;
  } catch {
    return undefined;
  }
}
