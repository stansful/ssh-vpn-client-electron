import { app, BrowserWindow, ipcMain } from "electron";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { AppStorage } from "./storage/app-storage.js";
import { listActiveProcesses } from "./processes.js";
import { createPlatformTarget, nativeServiceExists, resolveNativeServicePath } from "./platform/targets.js";
import { createDefaultRuntimeStatus } from "../shared/defaults.js";
import { IPC_CHANNELS, type ServiceEvent } from "../shared/ipc.js";
import { LocalIpcServiceBridge } from "../service/local-ipc-client.js";
import { defaultServiceEndpoint } from "../service/local-ipc-protocol.js";
import { NativeProcessServiceBridge } from "../service/native-process-client.js";
import { LiveSshServiceBridge } from "../service/live-ssh-service.js";
import type {
  AppSettings,
  AppSnapshot,
  DiagnosticsEntry,
  RoutingMode,
  RoutingRule,
  RuntimeStatus,
  TerminalLine,
  TunnelCheckResult,
  UpsertSshConfigInput,
  UpsertSshKeyInput
} from "../shared/types.js";
import { InProcessServiceBridge } from "../service/in-process-service.js";
import type { ServiceBridge } from "../service/service-bridge.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = app.isPackaged ? process.resourcesPath : path.join(__dirname, "..", "..");
const rendererDist = path.join(__dirname, "..", "renderer");
const preloadPath = path.join(__dirname, "..", "preload", "preload.js");
const iconPath = path.join(projectRoot, "icon.svg");

let mainWindow: BrowserWindow | undefined;
let runtime: RuntimeStatus;
let diagnostics: DiagnosticsEntry[] = [];
let terminal: TerminalLine[] = [];
let lastTunnelCheck: TunnelCheckResult | undefined;

app.setName(process.env.SHADOW_SSH_BUILD_CHANNEL === "development" ? "Shadow SSH Dev" : "Shadow SSH");

await app.whenReady();

const platformTarget = createPlatformTarget();
const nativeBinaryAvailable = nativeServiceExists(projectRoot, platformTarget);
runtime = {
  ...createDefaultRuntimeStatus(platformTarget),
  realTunnelAvailable: false,
  transport: "live-ssh"
};
runtime.message = nativeBinaryAvailable
  ? "Live SSH service is active. Native service binary is available for explicit service-mode tests."
  : "Live SSH service is active. Native service binary is missing.";

const storage = new AppStorage();
await storage.init();
const { service, startupDiagnostic } = await createServiceBridge(runtime);
if (startupDiagnostic) {
  diagnostics.push(startupDiagnostic);
}
service.onEvent(handleServiceEvent);

registerIpcHandlers();
await createWindow();

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    void createWindow();
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

let serviceDisposeStarted = false;
app.on("before-quit", (event) => {
  if (!service.dispose || serviceDisposeStarted) {
    return;
  }
  event.preventDefault();
  serviceDisposeStarted = true;
  void service.dispose().finally(() => app.quit());
});

async function createWindow(): Promise<void> {
  mainWindow = new BrowserWindow({
    width: 1240,
    height: 820,
    minWidth: 980,
    minHeight: 680,
    title: app.getName(),
    icon: iconPath,
    backgroundColor: "#f6f7f9",
    webPreferences: {
      preload: preloadPath,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  if (process.env.VITE_DEV_SERVER_URL) {
    await mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL);
    mainWindow.webContents.openDevTools({ mode: "detach" });
  } else {
    await mainWindow.loadFile(path.join(rendererDist, "index.html"));
  }
}

function registerIpcHandlers(): void {
  ipcMain.handle(IPC_CHANNELS.loadSnapshot, () => createSnapshot());
  ipcMain.handle(IPC_CHANNELS.upsertConfig, async (_event, input: UpsertSshConfigInput) => {
    const store = await storage.upsertConfig(input);
    const config = store.sshConfigs.find((candidate) => candidate.id === input.id) ?? store.sshConfigs.at(-1);
    if (config) {
      await service.updateConfig(config);
    }
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.deleteConfig, async (_event, id: string) => {
    await storage.deleteConfig(id);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.selectConfig, async (_event, id: string) => {
    await storage.selectConfig(id);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.upsertKey, async (_event, input: UpsertSshKeyInput) => {
    await storage.upsertKey(input);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.deleteKey, async (_event, id: string) => {
    await storage.deleteKey(id);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.updateSettings, async (_event, settings: AppSettings) => {
    await storage.updateSettings(settings);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.updateRoutingMode, async (_event, mode: RoutingMode) => {
    await storage.updateRoutingMode(mode);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.updateRoutingRules, async (_event, rules: RoutingRule[]) => {
    await storage.updateRoutingRules(rules);
    await service.updateRoutingRules(rules);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.listProcesses, () => listActiveProcesses());
  ipcMain.handle(IPC_CHANNELS.connect, async () => {
    await connect();
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.disconnect, async () => {
    await service.disconnect();
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.checkTunnel, async (_event, endpoint?: string) => {
    const store = storage.getStore();
    lastTunnelCheck = await service.checkTunnel(endpoint ?? store.settings.checkEndpoint);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.openTerminal, async () => {
    await service.openTerminal();
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.terminalInput, async (_event, input: string) => {
    await service.terminalInput(input);
  });
}

async function createServiceBridge(initialRuntime: RuntimeStatus): Promise<{ service: ServiceBridge; startupDiagnostic?: DiagnosticsEntry }> {
  const endpoint = process.env.SHADOW_SSH_SERVICE_ENDPOINT;
  if (endpoint) {
    try {
      const service = await LocalIpcServiceBridge.connect(endpoint, {
        ...initialRuntime,
        transport: "native-ipc",
        message: `Connected to local service endpoint ${endpoint}.`
      });
      return { service };
    } catch (error) {
      return simulatorFallback(
        initialRuntime,
        `Unable to connect to local service endpoint ${endpoint || defaultServiceEndpoint()}: ${error instanceof Error ? error.message : String(error)}.`
      );
    }
  }

  if (process.env.SHADOW_SSH_USE_NATIVE_PROCESS_SERVICE === "1" && nativeServiceExists(projectRoot, platformTarget)) {
    const executablePath = resolveNativeServicePath(projectRoot, platformTarget);
    try {
      const service = await NativeProcessServiceBridge.start(executablePath, {
        ...initialRuntime,
        transport: "native-ipc",
        message: `Started native service process ${executablePath}.`
      });
      return { service };
    } catch (error) {
      return simulatorFallback(
        initialRuntime,
        `Unable to start native service process ${executablePath}: ${error instanceof Error ? error.message : String(error)}.`
      );
    }
  }

  return {
    service: new LiveSshServiceBridge({
      ...initialRuntime,
      transport: "live-ssh",
      message: "Live SSH service is active."
    })
  };
}

function simulatorFallback(initialRuntime: RuntimeStatus, message: string): { service: ServiceBridge; startupDiagnostic: DiagnosticsEntry } {
  return {
    service: new InProcessServiceBridge({
      ...initialRuntime,
      transport: "simulator",
      message: "Native service is unavailable; simulator fallback is active."
    }),
    startupDiagnostic: {
      id: randomUUID(),
      at: new Date().toISOString(),
      level: "warning",
      message
    }
  };
}

async function connect(): Promise<void> {
  const store = storage.getStore();
  const config = store.sshConfigs.find((candidate) => candidate.id === store.selectedConfigId);
  if (!config) {
    appendError("Select or create an SSH configuration before connecting.");
    return;
  }

  const enabledRules = store.routingRules.filter((rule) => rule.enabled);
  if (store.routingMode === "selected-rules" && enabledRules.length === 0) {
    appendError("Selected rules mode requires at least one enabled routing rule.");
    return;
  }

  diagnostics = [];
  terminal = [];
  lastTunnelCheck = undefined;
  await service.connect({
    config,
    routingMode: store.routingMode,
    routingRules: store.routingRules,
    checkEndpoint: store.settings.checkEndpoint,
    secrets: storage.resolveServiceSecrets(config)
  });
}

function createSnapshot(): AppSnapshot {
  runtime = service.getStatus();
  return {
    store: storage.getStore(),
    runtime,
    diagnostics: structuredClone(diagnostics),
    terminal: structuredClone(terminal),
    lastTunnelCheck
  };
}

function handleServiceEvent(event: ServiceEvent): void {
  if (event.type === "status-changed") {
    runtime = event.status;
  }
  if (event.type === "diagnostics-appended") {
    diagnostics.push(event.entry);
  }
  if (event.type === "terminal-output") {
    terminal.push(event.line);
  }
  if (event.type === "tunnel-check-result") {
    lastTunnelCheck = event.result;
  }
  if (event.type === "error") {
    appendError(event.message);
  }
  broadcast(event);
}

function appendError(message: string): void {
  const entry: DiagnosticsEntry = {
    id: randomUUID(),
    at: new Date().toISOString(),
    level: "error",
    message
  };
  diagnostics.push(entry);
  broadcast({ type: "diagnostics-appended", entry });
}

function broadcast(event: ServiceEvent): void {
  for (const window of BrowserWindow.getAllWindows()) {
    window.webContents.send(IPC_CHANNELS.serviceEvent, event);
  }
}
