import net from "node:net";
import { chmod, mkdir } from "node:fs/promises";
import path from "node:path";
import { createDefaultRuntimeStatus } from "../shared/defaults.js";
import type { ServiceEvent } from "../shared/ipc.js";
import type { RoutingRule, SshConfig } from "../shared/types.js";
import { createPlatformTarget } from "../main/platform/targets.js";
import {
  defaultServiceEndpoint,
  encodeWireMessage,
  MAX_SERVICE_ENDPOINT_CONNECTIONS,
  MAX_SERVICE_ENDPOINT_WIRE_BYTES,
  SERVICE_PROTOCOL_VERSION,
  ServiceWireDecoder,
  writeWithBackpressure,
  type NativeServiceHandshake,
  type ServiceCommand,
  type ServiceResponsePayload
} from "./local-ipc-protocol.js";
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
const decoders = new Map<net.Socket, ServiceWireDecoder>();
const commandQueues = new Map<net.Socket, Promise<void>>();
const writeQueues = new Map<net.Socket, Promise<void>>();
let activeConfig: SshConfig | undefined;
let routingRules: RoutingRule[] = [];

bridge.onEvent((event) => {
  broadcast({ kind: "event", event });
});

const server = net.createServer((socket) => {
  if (clients.size >= MAX_SERVICE_ENDPOINT_CONNECTIONS) {
    socket.destroy();
    return;
  }
  clients.add(socket);
  decoders.set(socket, new ServiceWireDecoder(MAX_SERVICE_ENDPOINT_WIRE_BYTES));
  commandQueues.set(socket, Promise.resolve());
  writeQueues.set(socket, Promise.resolve());
  socket.on("data", (chunk) => handleData(socket, chunk));
  socket.on("error", () => cleanupSocket(socket));
  socket.on("close", () => cleanupSocket(socket));
});

if (process.platform !== "win32") {
  await mkdir(path.dirname(endpoint), { recursive: true, mode: 0o700 });
}

await new Promise<void>((resolve, reject) => {
  const onError = (error: Error): void => reject(error);
  server.once("error", onError);
  server.listen(endpoint, () => {
    server.off("error", onError);
    resolve();
  });
});
if (process.platform !== "win32") {
  try {
    await chmod(endpoint, 0o600);
  } catch (error) {
    server.close();
    throw error;
  }
}
process.stdout.write(`shadow-ssh service simulator listening on ${endpoint}\n`);

function handleData(socket: net.Socket, chunk: Buffer): void {
  const decoder = decoders.get(socket);
  if (!decoder) {
    socket.destroy();
    return;
  }
  try {
    for (const message of decoder.push(chunk)) {
      if (!("type" in message)) {
        throw new Error("Service simulator accepts commands only.");
      }
      enqueueCommand(socket, message);
    }
  } catch (error) {
    socket.destroy(error instanceof Error ? error : new Error(String(error)));
  }
}

function enqueueCommand(socket: net.Socket, command: ServiceCommand): void {
  const previous = commandQueues.get(socket) ?? Promise.resolve();
  const current = previous.then(() => handleCommand(socket, command));
  commandQueues.set(socket, current.catch(() => undefined));
}

async function handleCommand(socket: net.Socket, command: ServiceCommand): Promise<void> {
  try {
    const payload = await executeCommand(command);
    await enqueueWrite(socket, encodeWireMessage({ kind: "response", id: command.id, ok: true, payload }));
  } catch (error) {
    await enqueueWrite(socket, encodeWireMessage({
      kind: "response",
      id: command.id,
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    })).catch(() => socket.destroy());
  }
}

async function executeCommand(command: ServiceCommand): Promise<ServiceResponsePayload | undefined> {
  authorize(command);
  switch (command.type) {
    case "get-capabilities":
      return simulatorCapabilities();
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
    case "update-routing":
      routingRules = command.payload.routingRules;
      await bridge.updateRouting(command.payload);
      return { accepted: true };
    case "shutdown":
      await bridge.disconnect();
      server.close();
      return { accepted: true };
  }
}

function simulatorCapabilities(): NativeServiceHandshake {
  return {
    protocolVersion: SERVICE_PROTOCOL_VERSION,
    capabilities: {
      target: createPlatformTarget(),
      ipc: process.platform === "win32" ? "node-named-pipe" : "node-unix-socket",
      namedPipeAcl: false,
      unixSocketMode: process.platform !== "win32",
      serviceControlManager: false,
      wfpInterception: false,
      tunDevice: false,
      routeManipulation: false,
      processConnectionAttribution: false,
      dnsVisibility: false,
      ipv6RouteEnforcement: false,
      udpForwarding: false,
      sshCoreLinked: false
    }
  };
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
    void enqueueWrite(client, line).catch(() => client.destroy());
  }
}

function enqueueWrite(socket: net.Socket, line: string): Promise<void> {
  const previous = writeQueues.get(socket) ?? Promise.resolve();
  const current = previous.then(() => writeWithBackpressure(socket, line));
  writeQueues.set(socket, current.catch(() => undefined));
  return current;
}

function cleanupSocket(socket: net.Socket): void {
  clients.delete(socket);
  decoders.delete(socket);
  commandQueues.delete(socket);
  writeQueues.delete(socket);
}

function readArg(name: string): string | undefined {
  const prefix = `${name}=`;
  return process.argv.find((arg) => arg.startsWith(prefix))?.slice(prefix.length);
}
