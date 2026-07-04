import { app, BrowserWindow, clipboard, ipcMain, Menu, shell } from "electron";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { AppStorage } from "./storage/app-storage.js";
import { listActiveProcesses } from "./processes.js";
import { createPlatformTarget, nativeServiceExists, resolveNativeServicePath } from "./platform/targets.js";
import { createDefaultRuntimeStatus, RUSSIA_INSIDE_PROXY_LIST_URL, RUSSIA_OUTSIDE_DIRECT_LIST_URL } from "../shared/defaults.js";
import { IPC_CHANNELS, type ServiceEvent } from "../shared/ipc.js";
import { parseDomainProxyList } from "../core/routing/domain-proxy-list.js";
import { LocalIpcServiceBridge } from "../service/local-ipc-client.js";
import { defaultServiceEndpoint } from "../service/local-ipc-protocol.js";
import { NativeProcessServiceBridge } from "../service/native-process-client.js";
import { LiveSshServiceBridge } from "../service/live-ssh-service.js";
import { XrayServiceBridge } from "../service/xray-service.js";
import { createMainWindow } from "./app/main-window.js";
import { resolveUserDataPath, resolveXrayExecutablePath } from "./app/paths.js";
import { PortableUpdateController } from "./app/portable-update-controller.js";
import { refreshPublicProxyProfiles } from "./app/public-proxy-refresh.js";
import { formatError, formatRuntimePath as formatRuntimePathValue } from "./app/runtime-format.js";
import { TrayController, resolveTrayIconPaths } from "./app/tray.js";
import { GITHUB_REPOSITORY_URL, ROUTING_DOMAIN_LIST_SOURCE_URL } from "../shared/links.js";
import type {
  AppSettings,
  AppSnapshot,
  AppStore,
  DiagnosticsEntry,
  GlobalTab,
  ImportProxyProfilesInput,
  RoutingMode,
  RoutingRule,
  RuntimeStatus,
  TerminalLine,
  TunnelCheckResult,
  UpsertProxyProfileInput,
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
const runtimeFormatOptions = { packaged: app.isPackaged, resourcesPath: process.resourcesPath };
const trayIconPaths = resolveTrayIconPaths({ packaged: app.isPackaged, projectRoot, resourcesPath: process.resourcesPath });
const appDisplayName = process.env.SHADOW_SSH_BUILD_CHANNEL === "development" ? "Shadow SSH Dev" : "Shadow SSH";
const explicitUserDataPath = resolveUserDataPath(appDisplayName);
const persistedStorePath = path.join(explicitUserDataPath, "storage", "app-store.v1.json");
const mainLogPath = path.join(explicitUserDataPath, "logs", "main.log");
const routingDataPath = path.join(explicitUserDataPath, "routing");
const xrayRuntimeDataPath = path.join(explicitUserDataPath, "xray");
const updateDownloadPath = path.join(explicitUserDataPath, "updates");
const DEFAULT_WINDOW_WIDTH = 980;
const DEFAULT_WINDOW_HEIGHT = 680;
const MAX_DIAGNOSTICS_IN_MEMORY = 500;
const MAX_TERMINAL_LINES_IN_MEMORY = 2000;
const START_MINIMIZED_TO_TRAY_ARG = "--shadow-ssh-start-minimized-to-tray";
const ROUTING_PROXY_LIST_TIMEOUT_MS = 15_000;
const MAX_ROUTING_PROXY_LIST_BYTES = 2 * 1024 * 1024;

const formatRuntimePath = (value: string): string => formatRuntimePathValue(runtimeFormatOptions, value);
const startMinimizedToTray = process.argv.includes(START_MINIMIZED_TO_TRAY_ARG);

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
let activeTransport: "ssh" | "xray" = "ssh";
const portableUpdates = new PortableUpdateController(updateDownloadPath);

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
const xrayService = new XrayServiceBridge(
  {
    ...createDefaultRuntimeStatus(platformTarget),
    transport: "xray",
    message: "Xray transport is ready."
  },
  {
    pacDirectory: path.join(routingDataPath, "xray"),
    runtimeDirectory: xrayRuntimeDataPath,
    executablePath: resolveXrayExecutablePath({
      packaged: app.isPackaged,
      resourcesPath: process.resourcesPath,
      projectRoot
    })
  }
);
const xrayEventUnsubscribe = xrayService.onEvent(handleXrayServiceEvent);
const trayController = new TrayController({
  appName: appDisplayName,
  iconPaths: trayIconPaths,
  isCloseToTrayEnabled: () => storage.getStore().settings.closeToTrayEnabled,
  isTrayRequired: () => startMinimizedToTray || storage.getStore().settings.closeToTrayEnabled,
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
  if (serviceDisposeStarted) {
    return;
  }
  event.preventDefault();
  serviceDisposeStarted = true;
  void Promise.all([service.dispose?.() ?? Promise.resolve(), xrayService.dispose()]).finally(() => {
    trayController.destroy();
    serviceEventUnsubscribe?.();
    xrayEventUnsubscribe?.();
    app.quit();
  });
});

async function createWindow(): Promise<void> {
  await createMainWindow({
    ...runtimeFormatOptions,
    appName: app.getName(),
    rendererDist,
    preloadPath,
    iconPath,
    width: DEFAULT_WINDOW_WIDTH,
    height: DEFAULT_WINDOW_HEIGHT,
    startHidden: startMinimizedToTray,
    devServerUrl: process.env.VITE_DEV_SERVER_URL,
    onClosed: () => undefined,
    onClose: (event, window) => trayController.handleWindowClose(event, window),
    appendError,
    writeLog: writeMainLog
  });
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

async function initializeApplicationServices(): Promise<void> {
  try {
    await writeMainLog("Initializing storage.");
    await storage.init();
    applyLoggingSettings(storage.getStore().settings);
    syncWindowsStartupSetting(storage.getStore().settings);
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
    await autoConnectOnStartup();
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
  ipcMain.handle(IPC_CHANNELS.upsertProxyProfile, async (_event, input: UpsertProxyProfileInput) => {
    await storage.upsertProxyProfile(input);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.importProxyProfiles, async (_event, input: ImportProxyProfilesInput) => {
    const result = await storage.importProxyProfiles(input);
    return { snapshot: createSnapshot(), result: result.result };
  });
  ipcMain.handle(IPC_CHANNELS.refreshProxyProfiles, async () => {
    const result = await refreshPublicProxyProfiles(storage);
    return { snapshot: createSnapshot(), result };
  });
  ipcMain.handle(IPC_CHANNELS.selectProxyProfile, async (_event, id: string) => {
    await storage.selectProxyProfile(id);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.toggleProxyProfilePin, async (_event, id: string) => {
    await storage.toggleProxyProfilePin(id);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.deleteProxyProfile, async (_event, id: string) => {
    if (activeTransport === "xray" && xrayService.getStatus().activeConfigId === id) {
      await xrayService.disconnect();
    }
    await storage.deleteProxyProfile(id);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.deleteUnpinnedProxyProfiles, async () => {
    if (activeTransport === "xray") {
      await xrayService.disconnect();
    }
    await storage.deleteUnpinnedProxyProfiles();
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.updateSettings, async (_event, settings: AppSettings) => {
    applyLoggingSettings(settings);
    await storage.updateSettings(settings);
    syncWindowsStartupSetting(settings);
    trayController.sync();
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.updateRoutingMode, async (_event, mode: RoutingMode) => {
    const previousMode = storage.getStore().routingMode;
    const previousStatus = activeTunnelService().getStatus();
    await storage.updateRoutingMode(mode);
    if (mode !== previousMode && shouldReconnectForRoutingModeChange(previousStatus)) {
      await applyActiveTransportRoutingChange(mode);
    }
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.updateRoutingRules, async (_event, rules: RoutingRule[]) => {
    await storage.updateRoutingRules(rules);
    if (activeTransport === "xray") {
      await xrayService.updateRoutingRules(rules);
    } else {
      await service.updateRoutingRules(rules);
    }
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.updateRoutingProxyListEnabled, async (_event, enabled: boolean) => {
    const current = storage.getStore().routingProxyList;
    if (enabled && current.domains.length === 0) {
      await refreshRoutingProxyList({ enabled: true });
    } else {
      await storage.updateRoutingProxyList({ ...current, enabled });
    }
    await applyRoutingListsChange();
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.refreshRoutingProxyList, async () => {
    await refreshRoutingProxyList();
    await applyRoutingListsChange();
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.updateRoutingDirectListEnabled, async (_event, enabled: boolean) => {
    const current = storage.getStore().routingDirectList;
    if (enabled && current.domains.length === 0) {
      await refreshRoutingDirectList({ enabled: true });
    } else {
      await storage.updateRoutingDirectList({ ...current, enabled });
    }
    await applyRoutingListsChange();
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.refreshRoutingDirectList, async () => {
    await refreshRoutingDirectList();
    await applyRoutingListsChange();
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
  ipcMain.handle(IPC_CHANNELS.connectProxy, async () => {
    await connectProxy();
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.disconnect, async () => {
    await disconnectActiveTransport();
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.checkTunnel, async (_event, endpoint?: string) => {
    const store = storage.getStore();
    lastTunnelCheck = await activeTunnelService().checkTunnel(endpoint ?? store.settings.checkEndpoint);
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.openTerminal, async () => {
    await activeTunnelService().openTerminal();
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.closeTerminal, async () => {
    await activeTunnelService().closeTerminal();
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.terminalInput, async (_event, input: string) => {
    await activeTunnelService().terminalInput(input);
  });
  ipcMain.handle(IPC_CHANNELS.checkForUpdates, async (_event, force?: boolean) => {
    const update = await portableUpdates.check({
      currentVersion: app.getVersion(),
      platformTarget,
      storage,
      force: Boolean(force)
    });
    return { snapshot: createSnapshot(), update };
  });
  ipcMain.handle(IPC_CHANNELS.downloadUpdate, async () => {
    await portableUpdates.downloadSelected();
    return createSnapshot();
  });
  ipcMain.handle(IPC_CHANNELS.revealDownloadedUpdate, async () => {
    if (!portableUpdates.download.filePath) {
      return false;
    }
    shell.showItemInFolder(portableUpdates.download.filePath);
    return true;
  });
  ipcMain.handle(IPC_CHANNELS.copyText, (_event, text: string) => {
    if (typeof text !== "string" || text.length > 10_000) {
      throw new Error("Clipboard payload is invalid.");
    }
    clipboard.writeText(text);
    return true;
  });
  ipcMain.handle(IPC_CHANNELS.openExternal, async (_event, url: string) => {
    await shell.openExternal(assertAllowedExternalUrl(url));
    return true;
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

  if (store.routingMode === "selected-rules" && !hasSelectedRoutingTargets(store)) {
    appendError("Selected rules mode requires at least one enabled routing rule or enabled proxy-list domain.");
    return;
  }

  diagnostics = [];
  terminal = [];
  lastTunnelCheck = undefined;
  if (activeTransport === "xray") {
    await xrayService.disconnect();
  }
  activeTransport = "ssh";
  await service.connect({
    config,
    routingMode: store.routingMode,
    routingRules: store.routingRules,
    routingProxyDomains: activeRoutingProxyDomains(),
    routingDirectDomains: activeRoutingDirectDomains(),
    checkEndpoint: store.settings.checkEndpoint,
    secrets: storage.resolveServiceSecrets(config)
  });
  await rememberLastConnectedTransport("ssh");
}

async function connectProxy(): Promise<void> {
  const store = storage.getStore();
  const profile = store.proxyProfiles.find((candidate) => candidate.id === store.selectedProxyProfileId);
  if (!profile) {
    appendError("Select or import an Xray profile before connecting.");
    return;
  }

  if (store.routingMode === "selected-rules" && !hasSelectedRoutingTargets(store)) {
    appendError("Selected rules mode requires at least one enabled routing rule or enabled proxy-list domain.");
    return;
  }

  diagnostics = [];
  terminal = [];
  lastTunnelCheck = undefined;
  if (activeTransport === "ssh") {
    await service.disconnect();
  }
  activeTransport = "xray";
  await xrayService.connect({
    profile,
    routingMode: store.routingMode,
    routingRules: store.routingRules,
    routingProxyDomains: activeRoutingProxyDomains(),
    routingDirectDomains: activeRoutingDirectDomains(),
    checkEndpoint: store.settings.checkEndpoint,
    secrets: storage.resolveProxySecrets(profile)
  });
  await rememberLastConnectedTransport("xray");
}

async function autoConnectOnStartup(): Promise<void> {
  const store = storage.getStore();
  if (!store.settings.autoConnectOnStartup) {
    await writeMainLog("Auto-connect on startup is disabled.");
    return;
  }

  const transport = store.settings.lastConnectedTransport;
  try {
    if (store.routingMode === "selected-rules" && !hasSelectedRoutingTargets(store)) {
      await writeMainLog("Auto-connect skipped: selected rules mode has no enabled routing rules or enabled proxy-list domains.");
      return;
    }

    if (transport === "xray") {
      const profile = store.proxyProfiles.find((candidate) => candidate.id === store.selectedProxyProfileId);
      if (!profile) {
        await writeMainLog("Auto-connect skipped: no selected Xray profile.");
        return;
      }
      await writeMainLog(`Auto-connect starting Xray profile "${profile.name}".`);
      await connectProxy();
      await writeMainLog(`Auto-connect completed with Xray profile "${profile.name}".`);
      return;
    }

    const config = store.sshConfigs.find((candidate) => candidate.id === store.selectedConfigId);
    if (!config) {
      await writeMainLog("Auto-connect skipped: no selected SSH configuration.");
      return;
    }
    await writeMainLog(`Auto-connect starting SSH configuration "${config.name}".`);
    await connect();
    await writeMainLog(`Auto-connect completed with SSH configuration "${config.name}".`);
  } catch (error) {
    const message = `Auto-connect failed: ${formatError(error)}`;
    appendError(message);
    await writeMainLog(message);
  }
}

async function rememberLastConnectedTransport(transport: GlobalTab): Promise<void> {
  const settings = storage.getStore().settings;
  if (settings.lastConnectedTransport === transport && settings.activeGlobalTab === transport) {
    return;
  }
  await storage.updateSettings({
    ...settings,
    activeGlobalTab: transport,
    lastConnectedTransport: transport
  });
}

async function disconnectActiveTransport(): Promise<void> {
  if (activeTransport === "xray") {
    await xrayService.disconnect();
  } else {
    await service.disconnect();
  }
}

async function applyActiveTransportRoutingChange(mode: RoutingMode): Promise<void> {
  const store = storage.getStore();
  if (mode === "selected-rules" && !hasSelectedRoutingTargets(store)) {
    await disconnectActiveTransport();
    appendError("Selected rules mode requires at least one enabled routing rule or enabled proxy-list domain. Active tunnel was disconnected because routing mode changed.");
    return;
  }

  if (activeTransport === "xray") {
    await xrayService.updateRouting({
      routingMode: mode,
      routingRules: store.routingRules,
      routingProxyDomains: activeRoutingProxyDomains(),
      routingDirectDomains: activeRoutingDirectDomains(),
      checkEndpoint: store.settings.checkEndpoint
    });
  } else {
    await service.updateRouting({
      routingMode: mode,
      routingRules: store.routingRules,
      routingProxyDomains: activeRoutingProxyDomains(),
      routingDirectDomains: activeRoutingDirectDomains(),
      checkEndpoint: store.settings.checkEndpoint
    });
  }
}

async function applyRoutingListsChange(): Promise<void> {
  const store = storage.getStore();
  await activeTunnelService().updateRouting({
    routingMode: store.routingMode,
    routingRules: store.routingRules,
    routingProxyDomains: activeRoutingProxyDomains(),
    routingDirectDomains: activeRoutingDirectDomains(),
    checkEndpoint: store.settings.checkEndpoint
  });
}

async function refreshRoutingProxyList(options: { enabled?: boolean } = {}): Promise<void> {
  const current = storage.getStore().routingProxyList;
  const sourceUrl = current.sourceUrl || RUSSIA_INSIDE_PROXY_LIST_URL;
  const text = await fetchTextWithLimit(sourceUrl, MAX_ROUTING_PROXY_LIST_BYTES, ROUTING_PROXY_LIST_TIMEOUT_MS);
  const domains = parseDomainProxyList(text);
  if (domains.length === 0) {
    throw new Error("Routing proxy list refresh returned no domains.");
  }
  await storage.updateRoutingProxyList({
    enabled: options.enabled ?? current.enabled,
    sourceUrl,
    domains,
    updatedAt: new Date().toISOString()
  });
  appendInfo(`Routing proxy list refreshed: ${domains.length} domains from ${sourceUrl}.`);
}

async function refreshRoutingDirectList(options: { enabled?: boolean } = {}): Promise<void> {
  const current = storage.getStore().routingDirectList;
  const sourceUrl = current.sourceUrl || RUSSIA_OUTSIDE_DIRECT_LIST_URL;
  const text = await fetchTextWithLimit(sourceUrl, MAX_ROUTING_PROXY_LIST_BYTES, ROUTING_PROXY_LIST_TIMEOUT_MS);
  const domains = parseDomainProxyList(text);
  if (domains.length === 0) {
    throw new Error("Routing direct list refresh returned no domains.");
  }
  await storage.updateRoutingDirectList({
    enabled: options.enabled ?? current.enabled,
    sourceUrl,
    domains,
    updatedAt: new Date().toISOString()
  });
  appendInfo(`Routing direct list refreshed: ${domains.length} domains from ${sourceUrl}.`);
}

async function fetchTextWithLimit(url: string, maxBytes: number, timeoutMs: number): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref();
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "shadow-ssh-desktop-routing-list" }
    });
    if (!response.ok) {
      throw new Error(`Routing list download failed: ${response.status} ${response.statusText}`);
    }
    const contentLength = Number(response.headers.get("content-length") ?? "0");
    if (contentLength > maxBytes) {
      throw new Error("Routing list is larger than the allowed limit.");
    }
    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > maxBytes) {
      throw new Error("Routing list is larger than the allowed limit.");
    }
    return text;
  } finally {
    clearTimeout(timer);
  }
}

function activeRoutingProxyDomains(): string[] {
  const proxyList = storage.getStore().routingProxyList;
  return proxyList.enabled ? proxyList.domains : [];
}

function activeRoutingDirectDomains(): string[] {
  const directList = storage.getStore().routingDirectList;
  return directList.enabled ? directList.domains : [];
}

function hasSelectedRoutingTargets(store: AppStore): boolean {
  return store.routingRules.some((rule) => rule.enabled) || (store.routingProxyList.enabled && store.routingProxyList.domains.length > 0);
}

function shouldReconnectForRoutingModeChange(status: RuntimeStatus): boolean {
  return status.state === "Connected" || status.state === "Connecting" || status.state === "Reconnecting";
}

function activeTunnelService(): ServiceBridge | XrayServiceBridge {
  return activeTransport === "xray" ? xrayService : service;
}

function createSnapshot(): AppSnapshot {
  runtime = activeTransport === "xray" ? xrayService.getStatus() : service.getStatus();
  return {
    store: storage.getStore(),
    runtime,
    diagnostics: structuredClone(diagnostics),
    logFilePaths: uniqueLogPaths(),
    terminal: structuredClone(terminal),
    lastTunnelCheck,
    updateInfo: portableUpdates.info,
    updateDownload: portableUpdates.download
  };
}

function handleServiceEvent(event: ServiceEvent): void {
  handleRuntimeEvent("ssh", event);
}

function handleXrayServiceEvent(event: ServiceEvent): void {
  handleRuntimeEvent("xray", event);
}

function handleRuntimeEvent(source: "ssh" | "xray", event: ServiceEvent): void {
  const isActive = activeTransport === source;
  if (event.type === "status-changed") {
    if (!isActive) {
      return;
    }
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
    if (!isActive) {
      return;
    }
    terminal.push(event.line);
    if (terminal.length > MAX_TERMINAL_LINES_IN_MEMORY) {
      terminal = terminal.slice(-MAX_TERMINAL_LINES_IN_MEMORY);
    }
  }
  if (event.type === "tunnel-check-result") {
    if (!isActive) {
      return;
    }
    lastTunnelCheck = event.result;
  }
  if (event.type === "error") {
    void writeMainLog(`ERROR ${event.message}`);
    appendError(event.message);
    return;
  }
  if (isActive || event.type === "diagnostics-appended") {
    broadcast(event);
  }
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

function appendInfo(message: string): void {
  const entry: DiagnosticsEntry = {
    id: randomUUID(),
    at: new Date().toISOString(),
    level: "info",
    message
  };
  if (appendDiagnosticEntry(entry)) {
    broadcast({ type: "diagnostics-appended", entry });
  }
  void writeMainLog(`INFO ${message}`);
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

function assertAllowedExternalUrl(value: string): string {
  const url = new URL(value);
  const allowedUrls = [GITHUB_REPOSITORY_URL, ROUTING_DOMAIN_LIST_SOURCE_URL].map((allowed) => new URL(allowed));
  const requestedPath = url.pathname.replace(/\/$/u, "");
  const allowed = allowedUrls.some((candidate) =>
    url.protocol === "https:" &&
    url.hostname === candidate.hostname &&
    requestedPath === candidate.pathname.replace(/\/$/u, "")
  );
  if (!allowed) {
    throw new Error("External URL is not allowed.");
  }
  return url.toString();
}

async function ensureExplicitUserDataPath(): Promise<void> {
  try {
    await mkdir(explicitUserDataPath, { recursive: true });
    app.setPath("userData", explicitUserDataPath);
  } catch (error) {
    await writeMainLog(`Unable to set explicit userData path ${explicitUserDataPath}: ${formatError(error)}`);
  }
}

function syncWindowsStartupSetting(settings: AppSettings): void {
  if (process.platform !== "win32") {
    return;
  }

  try {
    app.setLoginItemSettings({
      openAtLogin: settings.startWithWindowsInTray,
      path: resolveWindowsStartupExecutablePath(),
      args: settings.startWithWindowsInTray ? [START_MINIMIZED_TO_TRAY_ARG] : []
    });
  } catch (error) {
    const message = `Unable to sync Windows startup setting: ${formatError(error)}`;
    appendError(message);
    void writeMainLog(message);
  }
}

function resolveWindowsStartupExecutablePath(): string {
  const portableExecutable = process.env.PORTABLE_EXECUTABLE_FILE;
  if (portableExecutable && path.isAbsolute(portableExecutable)) {
    return portableExecutable;
  }
  return process.execPath;
}
