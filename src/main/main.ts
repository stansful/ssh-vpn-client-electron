import { app, BrowserWindow, clipboard, ipcMain, Menu } from "electron";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import { AppStorage } from "./storage/app-storage.js";
import { listActiveProcesses } from "./processes.js";
import { createPlatformTarget, nativeServiceExists, resolveNativeServicePath } from "./platform/targets.js";
import { createDefaultRuntimeStatus } from "../shared/defaults.js";
import { IPC_CHANNELS, type ServiceEvent } from "../shared/ipc.js";
import { LocalIpcServiceBridge } from "../service/local-ipc-client.js";
import { defaultServiceEndpoint } from "../service/local-ipc-protocol.js";
import { NativeProcessServiceBridge } from "../service/native-process-client.js";
import { LiveSshServiceBridge } from "../service/live-ssh-service.js";
import { TrayController, resolveTrayIconPaths } from "./app/tray.js";
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
const iconPath = app.isPackaged ? path.join(rendererDist, "icon.svg") : path.join(projectRoot, "icon.svg");
const trayIconPaths = resolveTrayIconPaths({ packaged: app.isPackaged, projectRoot, resourcesPath: process.resourcesPath });
const appDisplayName = process.env.SHADOW_SSH_BUILD_CHANNEL === "development" ? "Shadow SSH Dev" : "Shadow SSH";
const explicitUserDataPath = resolveUserDataPath(appDisplayName);
const persistedStorePath = path.join(explicitUserDataPath, "storage", "app-store.v1.json");
const mainLogPath = path.join(explicitUserDataPath, "logs", "main.log");
const routingDataPath = path.join(explicitUserDataPath, "routing");
const DEFAULT_WINDOW_WIDTH = 980;
const DEFAULT_WINDOW_HEIGHT = 680;
const MAX_DIAGNOSTICS_IN_MEMORY = 500;
const MAX_TERMINAL_LINES_IN_MEMORY = 2000;

let mainWindow: BrowserWindow | undefined;
let runtime: RuntimeStatus;
let diagnostics: DiagnosticsEntry[] = [];
let terminal: TerminalLine[] = [];
let lastTunnelCheck: TunnelCheckResult | undefined;
let service: ServiceBridge;
let serviceEventUnsubscribe: (() => void) | undefined;
let diagnosticsLoggingEnabled = true;
let fileLoggingEnabled = true;
let loggingMasterEnabled = true;
let applicationQuitting = false;

app.setName(appDisplayName);
registerProcessErrorHandlers();
await preloadLoggingPreference();
await ensureExplicitUserDataPath();
await writeMainLog(`Main module loaded. pid=${process.pid}, platform=${process.platform}, arch=${process.arch}, userData=${explicitUserDataPath}`);

await app.whenReady();
Menu.setApplicationMenu(null);
await writeMainLog(
  `Application ready. packaged=${app.isPackaged}, resourcesPath=${formatRuntimePath(process.resourcesPath)}, dirname=${formatRuntimePath(__dirname)}, electronUserData=${app.getPath("userData")}`
);

const platformTarget = createPlatformTarget();
const nativeBinaryAvailable = nativeServiceExists(projectRoot, platformTarget);
runtime = {
  ...createDefaultRuntimeStatus(platformTarget),
  realTunnelAvailable: false,
  transport: "simulator",
  message: "Application services are starting."
};
const storage = new AppStorage();
service = new InProcessServiceBridge(runtime);
serviceEventUnsubscribe = service.onEvent(handleServiceEvent);
const trayController = new TrayController({
  appName: appDisplayName,
  iconPaths: trayIconPaths,
  isCloseToTrayEnabled: () => storage.getStore().settings.closeToTrayEnabled,
  isQuitting: () => applicationQuitting,
  onQuit: () => {
    applicationQuitting = true;
    app.quit();
  }
});

registerIpcHandlers();
await createWindow();
void initializeApplicationServices();

app.on("activate", () => {
  const windows = BrowserWindow.getAllWindows();
  if (windows.length > 0) {
    trayController.showWindow();
  } else {
    void createWindow();
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin" && !storage.getStore().settings.closeToTrayEnabled) {
    app.quit();
  }
});

let serviceDisposeStarted = false;
app.on("before-quit", (event) => {
  applicationQuitting = true;
  if (!service.dispose || serviceDisposeStarted) {
    return;
  }
  event.preventDefault();
  serviceDisposeStarted = true;
  void service.dispose().finally(() => {
    trayController.destroy();
    app.quit();
  });
});

async function createWindow(): Promise<void> {
  await writeMainLog(
    `Creating window. renderer=${formatRuntimePath(path.join(rendererDist, "index.html"))}, preload=${formatRuntimePath(preloadPath)}, icon=${formatRuntimePath(iconPath)}`
  );
  mainWindow = new BrowserWindow({
    width: DEFAULT_WINDOW_WIDTH,
    height: DEFAULT_WINDOW_HEIGHT,
    minWidth: DEFAULT_WINDOW_WIDTH,
    minHeight: DEFAULT_WINDOW_HEIGHT,
    title: app.getName(),
    icon: iconPath,
    autoHideMenuBar: true,
    backgroundColor: "#f6f7f9",
    webPreferences: {
      preload: preloadPath,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  mainWindow.on("closed", () => {
    mainWindow = undefined;
  });
  mainWindow.on("close", (event) => {
    const window = mainWindow;
    if (window) {
      trayController.handleWindowClose(event, window);
    }
  });
  mainWindow.webContents.on("did-fail-load", (_event, errorCode, errorDescription, validatedURL) => {
    const message = `Renderer failed to load ${formatRuntimeUrl(validatedURL)}: ${errorCode} ${errorDescription}`;
    appendError(message);
    void writeMainLog(message);
  });
  mainWindow.webContents.on("render-process-gone", (_event, details) => {
    const message = `Renderer process gone: reason=${details.reason}, exitCode=${details.exitCode}`;
    appendError(message);
    void writeMainLog(message);
  });
  mainWindow.webContents.on("preload-error", (_event, failedPreloadPath, error) => {
    const message = `Preload failed ${formatRuntimePath(failedPreloadPath)}: ${formatError(error)}`;
    appendError(message);
    void writeMainLog(message);
  });
  mainWindow.webContents.on("did-finish-load", () => {
    const message = `Renderer finished load: ${formatRuntimeUrl(mainWindow?.webContents.getURL() ?? "unknown")}`;
    void writeMainLog(message);
    scheduleRendererMountCheck();
  });
  mainWindow.webContents.on("console-message", (_event, level, message, line, sourceId) => {
    const levelName = ["debug", "info", "warning", "error"][level] ?? `level-${level}`;
    void writeMainLog(`Renderer console ${levelName}: ${message}${sourceId ? ` (${formatRuntimeUrl(sourceId)}:${line})` : ""}`);
  });

  if (process.env.VITE_DEV_SERVER_URL) {
    await mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL);
    mainWindow.webContents.openDevTools({ mode: "detach" });
  } else {
    try {
      await mainWindow.loadFile(path.join(rendererDist, "index.html"));
    } catch (error) {
      const message = `Unable to load renderer: ${formatError(error)}`;
      appendError(message);
      await writeMainLog(message);
      await mainWindow.loadURL(createErrorDataUrl(message));
    }
  }
}

function registerProcessErrorHandlers(): void {
  process.on("uncaughtException", (error) => {
    const message = `Uncaught exception: ${formatError(error)}`;
    appendError(message);
    void writeMainLog(message);
  });

  process.on("unhandledRejection", (reason) => {
    const message = `Unhandled rejection: ${formatError(reason)}`;
    appendError(message);
    void writeMainLog(message);
  });
}

function scheduleRendererMountCheck(): void {
  const window = mainWindow;
  if (!window) {
    return;
  }
  setTimeout(() => {
    if (window.isDestroyed() || window.webContents.isDestroyed()) {
      return;
    }
    void window.webContents
      .executeJavaScript(
        `(() => {
          const root = document.getElementById("root");
          return {
            url: location.href,
            readyState: document.readyState,
            rootChildCount: root ? root.childElementCount : -1,
            bodyTextLength: document.body ? document.body.innerText.length : -1
          };
        })();`,
        true
      )
      .then((status: { url: string; readyState: string; rootChildCount: number; bodyTextLength: number }) => {
        const message = `Renderer mount status: url=${formatRuntimeUrl(status.url)}, readyState=${status.readyState}, rootChildCount=${status.rootChildCount}, bodyTextLength=${status.bodyTextLength}`;
        void writeMainLog(message);
        if (status.rootChildCount <= 0) {
          appendError(`Renderer did not mount React root. ${message}`);
        }
      })
      .catch((error: unknown) => {
        void writeMainLog(`Renderer mount check failed: ${formatError(error)}`);
      });
  }, 1500);
}

async function initializeApplicationServices(): Promise<void> {
  try {
    await writeMainLog("Initializing storage.");
    await storage.init();
    applyLoggingSettings(storage.getStore().settings);
    trayController.sync();
    const initialRuntime: RuntimeStatus = {
      ...createDefaultRuntimeStatus(platformTarget),
      realTunnelAvailable: false,
      transport: "live-ssh",
      message: nativeBinaryAvailable
        ? "Live SSH service is active. Native service binary is available for explicit service-mode tests."
        : "Live SSH service is active. Native service binary is missing."
    };
    const next = await createServiceBridge(initialRuntime);
    activateService(next.service);
    if (next.startupDiagnostic) {
      if (appendDiagnosticEntry(next.startupDiagnostic)) {
        broadcast({ type: "diagnostics-appended", entry: next.startupDiagnostic });
      }
      await writeMainLog(`${next.startupDiagnostic.level.toUpperCase()} ${next.startupDiagnostic.message}`);
    }
    await writeMainLog("Application services initialized.");
  } catch (error) {
    const message = `Startup failed: ${formatError(error)}`;
    activateService(
      new InProcessServiceBridge({
        ...runtime,
        state: "Error",
        transport: "simulator",
        realTunnelAvailable: false,
        message
      })
    );
    appendError(message);
    await writeMainLog(message);
  }
}

function activateService(nextService: ServiceBridge): void {
  serviceEventUnsubscribe?.();
  service = nextService;
  serviceEventUnsubscribe = service.onEvent(handleServiceEvent);
  runtime = service.getStatus();
  broadcast({ type: "status-changed", status: runtime });
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
  ipcMain.handle(IPC_CHANNELS.copyPrivateKey, (_event, id: string) => {
    clipboard.writeText(storage.readPrivateKeyText(id));
    return true;
  });
  ipcMain.handle(IPC_CHANNELS.deleteKey, async (_event, id: string) => {
    await storage.deleteKey(id);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.updateSettings, async (_event, settings: AppSettings) => {
    applyLoggingSettings(settings);
    await storage.updateSettings(settings);
    trayController.sync();
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
  ipcMain.handle(IPC_CHANNELS.clearDiagnostics, () => {
    diagnostics = [];
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.readLogFile, () => readMainLogContent());
  ipcMain.handle(IPC_CHANNELS.clearLogFile, () => clearMainLogFiles());
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
  ipcMain.handle(IPC_CHANNELS.closeTerminal, async () => {
    await service.closeTerminal();
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
    }, { pacDirectory: routingDataPath })
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
    logFilePaths: uniqueLogPaths(),
    terminal: structuredClone(terminal),
    lastTunnelCheck
  };
}

function handleServiceEvent(event: ServiceEvent): void {
  if (event.type === "status-changed") {
    runtime = event.status;
  }
  if (event.type === "diagnostics-appended") {
    if (shouldPersistDiagnostic(event.entry)) {
      void writeMainLog(`${event.entry.level.toUpperCase()} ${event.entry.message}`);
    }
    if (!appendDiagnosticEntry(event.entry)) {
      return;
    }
  }
  if (event.type === "terminal-output") {
    terminal.push(event.line);
    if (terminal.length > MAX_TERMINAL_LINES_IN_MEMORY) {
      terminal = terminal.slice(-MAX_TERMINAL_LINES_IN_MEMORY);
    }
  }
  if (event.type === "tunnel-check-result") {
    lastTunnelCheck = event.result;
  }
  if (event.type === "error") {
    void writeMainLog(`ERROR ${event.message}`);
    appendError(event.message);
    return;
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
  if (appendDiagnosticEntry(entry)) {
    broadcast({ type: "diagnostics-appended", entry });
  }
}

function appendDiagnosticEntry(entry: DiagnosticsEntry): boolean {
  if (!diagnosticsLoggingEnabled) {
    return false;
  }
  diagnostics.push(entry);
  if (diagnostics.length > MAX_DIAGNOSTICS_IN_MEMORY) {
    diagnostics = diagnostics.slice(-MAX_DIAGNOSTICS_IN_MEMORY);
  }
  return true;
}

function shouldPersistDiagnostic(entry: DiagnosticsEntry): boolean {
  if (isHighVolumeProxyDiagnostic(entry.message)) {
    return false;
  }
  return true;
}

function isHighVolumeProxyDiagnostic(message: string): boolean {
  return (
    /^(HTTP CONNECT|HTTP proxy|SOCKS5 CONNECT) .+ from 127\.0\.0\.1:\d+\.$/u.test(message) ||
    /^(HTTP CONNECT|HTTP proxy|SOCKS5 CONNECT) tunnel opened for .+\.$/u.test(message) ||
    /^(HTTP proxy|SOCKS5|SOCKS\/HTTP proxy) socket closed during handshake\.$/u.test(message) ||
    /^(read ECONNRESET|write after end)$/u.test(message) ||
    /^Further proxy (connection diagnostics|warnings) are suppressed for this session\.$/u.test(message)
  );
}

function broadcast(event: ServiceEvent): void {
  for (const window of BrowserWindow.getAllWindows()) {
    window.webContents.send(IPC_CHANNELS.serviceEvent, event);
  }
}

async function writeMainLog(message: string): Promise<void> {
  if (!loggingMasterEnabled) {
    return;
  }
  if (!fileLoggingEnabled) {
    return;
  }
  for (const logPath of uniqueLogPaths()) {
    try {
      await mkdir(path.dirname(logPath), { recursive: true });
      await appendFile(logPath, `[${new Date().toISOString()}] ${message}\n`, "utf8");
    } catch {
      // Logging must never break app startup.
    }
  }
}

async function readMainLogContent(): Promise<string> {
  const sections: string[] = [];
  const seen = new Set<string>();
  for (const logPath of uniqueLogPaths()) {
    try {
      const content = await readFile(logPath, "utf8");
      if (!content || seen.has(content)) {
        continue;
      }
      seen.add(content);
      sections.push(`### ${logPath}\n${content.trimEnd()}`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        sections.push(`### ${logPath}\nUnable to read log file: ${formatError(error)}`);
      }
    }
  }
  return sections.join("\n\n");
}

async function clearMainLogFiles(): Promise<string> {
  for (const logPath of uniqueLogPaths()) {
    try {
      await mkdir(path.dirname(logPath), { recursive: true });
      await writeFile(logPath, "", "utf8");
    } catch {
      // Clearing one log path should not block clearing another path.
    }
  }
  return readMainLogContent();
}

function applyLoggingSettings(settings: AppSettings): void {
  loggingMasterEnabled = settings.loggingEnabled;
  diagnosticsLoggingEnabled = loggingMasterEnabled && settings.diagnosticsLoggingEnabled;
  fileLoggingEnabled = loggingMasterEnabled && settings.fileLoggingEnabled;
}

async function preloadLoggingPreference(): Promise<void> {
  try {
    const parsed = JSON.parse(await readFile(persistedStorePath, "utf8")) as { settings?: { loggingEnabled?: unknown } };
    if (parsed.settings?.loggingEnabled === false) {
      loggingMasterEnabled = false;
      diagnosticsLoggingEnabled = false;
      fileLoggingEnabled = false;
    }
  } catch {
    // Missing or malformed settings should keep startup diagnostics available.
  }
}

function uniqueLogPaths(): string[] {
  return [mainLogPath];
}

async function ensureExplicitUserDataPath(): Promise<void> {
  try {
    await mkdir(explicitUserDataPath, { recursive: true });
    app.setPath("userData", explicitUserDataPath);
  } catch (error) {
    await writeMainLog(`Unable to set explicit userData path ${explicitUserDataPath}: ${formatError(error)}`);
  }
}

function resolveUserDataPath(name: string): string {
  if (process.env.SHADOW_SSH_USER_DATA_DIR) {
    return process.env.SHADOW_SSH_USER_DATA_DIR;
  }
  if (process.platform === "win32") {
    const appData = process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming");
    return path.join(appData, name);
  }
  if (process.platform === "darwin") {
    return path.join(os.homedir(), "Library", "Application Support", name);
  }
  const configHome = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
  return path.join(configHome, name);
}

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return `${error.message}${error.stack ? `\n${error.stack}` : ""}`;
  }
  return String(error);
}

function createErrorDataUrl(message: string): string {
  const html = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Shadow SSH startup error</title>
    <style>
      body { margin: 0; font: 14px system-ui, sans-serif; color: #20242a; background: #f6f7f9; }
      main { padding: 32px; max-width: 860px; }
      h1 { margin: 0 0 12px; font-size: 24px; }
      pre { white-space: pre-wrap; background: #fff; border: 1px solid #d6dae0; padding: 16px; border-radius: 8px; }
    </style>
  </head>
  <body>
    <main>
      <h1>Shadow SSH could not load the UI</h1>
      <p>Check the main process log under the application data directory.</p>
      <pre>${escapeHtml(message)}</pre>
    </main>
  </body>
</html>`;
  return `data:text/html;charset=utf-8,${encodeURIComponent(html)}`;
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

function formatRuntimePath(value: string): string {
  if (!app.isPackaged || !value) {
    return value;
  }
  const resourcesPath = path.normalize(process.resourcesPath);
  const normalized = path.normalize(value);
  if (normalized === resourcesPath) {
    return "[app-resources]";
  }
  if (normalized.startsWith(`${resourcesPath}${path.sep}`)) {
    return path.join("[app-resources]", path.relative(resourcesPath, normalized));
  }
  return value;
}

function formatRuntimeUrl(value: string): string {
  if (!app.isPackaged || !value) {
    return value;
  }
  try {
    const url = new URL(value);
    if (url.protocol !== "file:") {
      return value;
    }
    return `file://${formatRuntimePath(fileURLToPath(url))}`;
  } catch {
    return formatRuntimePath(value);
  }
}
