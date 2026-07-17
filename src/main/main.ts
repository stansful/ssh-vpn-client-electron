import { app, BrowserWindow, clipboard, ipcMain, Menu, nativeTheme, powerMonitor, session, shell, webContents, webFrameMain } from "electron";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { randomUUID } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { AppStorage } from "./storage/app-storage.js";
import { listActiveProcesses } from "./processes.js";
import { createPlatformTarget, nativeServiceExists, resolveNativeServicePath } from "./platform/targets.js";
import { createDefaultRuntimeStatus, RUSSIA_INSIDE_PROXY_LIST_URL, RUSSIA_OUTSIDE_DIRECT_LIST_URL } from "../shared/defaults.js";
import { IPC_CHANNELS, type RendererEvent, type ServiceEvent } from "../shared/ipc.js";
import { parseDomainProxyList } from "../core/routing/domain-proxy-list.js";
import { recoverWindowsSystemProxy, WindowsSystemProxyManager } from "../core/network/windows-system-proxy.js";
import { LocalIpcServiceBridge } from "../service/local-ipc-client.js";
import { defaultServiceEndpoint } from "../service/local-ipc-protocol.js";
import { NativeProcessServiceBridge } from "../service/native-process-client.js";
import { LiveSshServiceBridge } from "../service/live-ssh-service.js";
import { XrayServiceBridge } from "../service/xray-service.js";
import { createMainWindow } from "./app/main-window.js";
import { resolveUserDataPath, resolveXrayExecutablePath } from "./app/paths.js";
import { PortableUpdateController } from "./app/portable-update-controller.js";
import { RotatingFileLog } from "./app/rotating-file-log.js";
import { fetchRoutingListText } from "./app/routing-list-fetch.js";
import { hasSelectedRoutingTargets, routingMutationAction } from "./app/routing-targets.js";
import { TransportMutationCoordinator } from "./app/transport-mutation-coordinator.js";
import { refreshPublicProxyProfiles } from "./app/public-proxy-refresh.js";
import {
  formatError,
  formatRuntimePath as formatRuntimePathValue,
  formatRuntimeUrl as formatRuntimeUrlValue
} from "./app/runtime-format.js";
import { assessRendererIpcTrust } from "./app/renderer-security.js";
import { TerminalOutputBatcher } from "./app/terminal-output-batcher.js";
import { TrayController, resolveTrayIconPaths } from "./app/tray.js";
import { shouldDeliverRendererEvent, SystemEnergyPolicy, type ThermalState } from "./app/energy-policy.js";
import { GITHUB_REPOSITORY_URL, ROUTING_DOMAIN_LIST_SOURCE_URL } from "../shared/links.js";
import type { FetchImplementation } from "../shared/http-fetch.js";
import {
  appendBoundedDiagnosticEntries,
  MAX_DIAGNOSTICS_HISTORY_BYTES,
  MAX_DIAGNOSTICS_HISTORY_ENTRIES,
  normalizeDiagnosticEntry
} from "../shared/diagnostics-history.js";
import { appendBoundedTerminalLine } from "../shared/terminal-history.js";
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
const preloadPath = path.join(__dirname, "..", "preload", "preload.mjs");
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
const START_MINIMIZED_TO_TRAY_ARG = "--shadow-ssh-start-minimized-to-tray";
const MAX_MAIN_LOG_BYTES = 5 * 1024 * 1024;
const MAX_MAIN_LOG_READ_BYTES = 1024 * 1024;
const MAIN_LOG_BACKUP_COUNT = 2;
const MAX_CLIPBOARD_TEXT_CHARACTERS = 2 * 1024 * 1024;
const MAX_TERMINAL_INPUT_CHARACTERS = 64 * 1024;

const formatRuntimePath = (value: string): string => formatRuntimePathValue(runtimeFormatOptions, value);
const formatRuntimeUrl = (value: string): string => formatRuntimeUrlValue(runtimeFormatOptions, value);
const windowBackgroundColor = (settings: AppSettings): string => {
  if (settings.theme === "dark") {
    return "#0b0d10";
  }
  if (settings.theme === "light") {
    return "#f3f4f7";
  }
  if (settings.theme === "custom") {
    return `#${[settings.customTheme.background.r, settings.customTheme.background.g, settings.customTheme.background.b]
      .map((value) => Math.max(0, Math.min(255, Math.round(value))).toString(16).padStart(2, "0"))
      .join("")}`;
  }
  return nativeTheme.shouldUseDarkColors ? "#0b0d10" : "#f3f4f7";
};
const startMinimizedToTray = process.argv.includes(START_MINIMIZED_TO_TRAY_ARG);
const electronSessionFetch: FetchImplementation = (input, init) => session.defaultSession.fetch(input, init);
const trustedRendererEntryUrl = process.env.VITE_DEV_SERVER_URL ?? pathToFileURL(path.join(rendererDist, "index.html")).href;

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
let storageInitialized = false;
let windowShowRequested = false;
let windowCreationAllowed = false;
let mainWindowCreation: Promise<void> | undefined;
let applicationServicesReadyResolved = false;
let applicationServicesInitialization: Promise<void> | undefined;
let rejectedRendererIpcReported = false;
let rendererSnapshotHandshakeReported = false;
const trustedRendererWebContentsIds = new Set<number>();
let resolveApplicationServicesReady!: () => void;
const applicationServicesReady = new Promise<void>((resolve) => {
  resolveApplicationServicesReady = resolve;
});
const mainLogger = new RotatingFileLog(mainLogPath, {
  maxFileBytes: MAX_MAIN_LOG_BYTES,
  maxReadBytes: MAX_MAIN_LOG_READ_BYTES,
  backupCount: MAIN_LOG_BACKUP_COUNT
});
const sharedSystemProxy = new WindowsSystemProxyManager({ pacDirectory: routingDataPath });
const transportMutations = new TransportMutationCoordinator();
const portableUpdates = new PortableUpdateController(
  updateDownloadPath,
  (download) => broadcast({ type: "update-download-changed", download }),
  electronSessionFetch
);
const terminalOutputBatcher = new TerminalOutputBatcher<"ssh" | "xray">(({ source, lines, droppedBytes }) => {
  if (source !== activeTransport) {
    return;
  }
  const output = [...lines];
  if (droppedBytes > 0) {
    output.push({
      id: randomUUID(),
      at: new Date().toISOString(),
      stream: "system",
      text: `\n[terminal output truncated: ${droppedBytes} UTF-8 bytes exceeded the renderer rate limit]\n`
    });
  }
  for (const line of output) {
    terminal = appendBoundedTerminalLine(terminal, line);
    broadcast({ type: "terminal-output", line });
  }
});

app.setName(appDisplayName);
registerProcessErrorHandlers();
app.on("second-instance", requestWindowShow);
await preloadLoggingPreference();
await ensureExplicitUserDataPath();
await writeMainLog(`Main module loaded. pid=${process.pid}, platform=${process.platform}, arch=${process.arch}, userData=${explicitUserDataPath}`);

await app.whenReady();
Menu.setApplicationMenu(null);
await writeMainLog(
  `Application ready. packaged=${app.isPackaged}, resourcesPath=${formatRuntimePath(process.resourcesPath)}, dirname=${formatRuntimePath(__dirname)}, electronUserData=${app.getPath("userData")}`
);

const platformTarget = createPlatformTarget();
const systemEnergyPolicy = new SystemEnergyPolicy({
  onBatteryPower: powerMonitor.isOnBatteryPower(),
  thermalState: process.platform === "darwin" ? powerMonitor.getCurrentThermalState() : "unknown"
});
let systemSessionActive = true;
powerMonitor.on("on-battery", () => systemEnergyPolicy.setOnBatteryPower(true));
powerMonitor.on("on-ac", () => systemEnergyPolicy.setOnBatteryPower(false));
powerMonitor.on("suspend", () => {
  systemSessionActive = false;
});
powerMonitor.on("resume", () => {
  systemSessionActive = true;
});
if (process.platform === "darwin") {
  powerMonitor.on("thermal-state-change", ({ state }) => systemEnergyPolicy.setThermalState(state as ThermalState));
}
if (process.platform === "darwin" || process.platform === "win32") {
  powerMonitor.on("speed-limit-change", ({ limit }) => systemEnergyPolicy.setCpuSpeedLimitPercent(limit));
  powerMonitor.on("lock-screen", () => {
    systemSessionActive = false;
  });
  powerMonitor.on("unlock-screen", () => {
    systemSessionActive = true;
  });
}
const nativeBinaryAvailable = nativeServiceExists(projectRoot, platformTarget);
runtime = {
  ...createDefaultRuntimeStatus(platformTarget),
  realTunnelAvailable: false,
  transport: "simulator",
  message: "Application services are starting."
};
const storage = new AppStorage();
nativeTheme.on("updated", () => {
  if (!storageInitialized || storage.getSettings().theme !== "system") {
    return;
  }
  const backgroundColor = windowBackgroundColor(storage.getSettings());
  for (const window of BrowserWindow.getAllWindows()) {
    if (!window.isDestroyed()) {
      window.setBackgroundColor(backgroundColor);
    }
  }
});
service = new InProcessServiceBridge(runtime);
serviceEventUnsubscribe = service.onEvent(handleServiceEvent);
const xrayService = new XrayServiceBridge(
  {
    ...createDefaultRuntimeStatus(platformTarget),
    transport: "xray",
    message: "Xray transport is ready."
  },
  {
    systemProxy: sharedSystemProxy,
    processRoutingRefreshIntervalMs: currentProcessRoutingRefreshIntervalMs,
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
  isCloseToTrayEnabled: () => storage.getSettings().closeToTrayEnabled,
  isRendererReleaseEnabled: () => storage.getSettings().releaseRendererInTrayEnabled,
  isTrayRequired: () => startMinimizedToTray || storage.getSettings().closeToTrayEnabled,
  isQuitting: () => applicationQuitting,
  onIconLoaded: ({ width, height, scaleFactors, template }) => {
    void writeMainLog(
      `Tray icon loaded. size=${width}x${height}, scaleFactors=${scaleFactors.join(",") || "none"}, template=${template}`
    );
  },
  onShowRequested: requestWindowShow,
  onQuit: () => {
    applicationQuitting = true;
    trayController.prepareForQuit();
    app.quit();
  }
});
await initializeApplicationStorage();
await restoreStaleWindowsProxyState();
registerIpcHandlers();
windowCreationAllowed = true;
// A minimized startup can omit Chromium entirely. If tray creation failed,
// fall back to a visible window so the application never becomes unreachable.
if (!startMinimizedToTray || !trayController.isCreated) {
  await createWindow();
}
if (windowShowRequested) {
  windowShowRequested = false;
  requestWindowShow();
}
if (storageInitialized) {
  applicationServicesInitialization = initializeApplicationServices();
  void applicationServicesInitialization;
} else {
  markApplicationServicesReady();
}

app.on("activate", () => {
  const windows = BrowserWindow.getAllWindows();
  if (windows.length > 0) {
    trayController.showWindow();
  } else {
    requestWindowShow();
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin" && (!storage.getSettings().closeToTrayEnabled || !trayController.isCreated)) {
    app.quit();
  }
});

let serviceDisposeStarted = false;
let allowFinalQuit = false;
app.on("before-quit", (event) => {
  applicationQuitting = true;
  trayController.prepareForQuit();
  if (allowFinalQuit) {
    return;
  }
  event.preventDefault();
  if (serviceDisposeStarted) {
    return;
  }
  serviceDisposeStarted = true;
  transportMutations.stopAcceptingIntents();
  // Release queued intents immediately. Shutdown still awaits the complete
  // initialization promise below; bridge connect/request operations have
  // their own deadlines, and a late acquired service is disposed before exit.
  markApplicationServicesReady();
  void enqueueTransportMutation(async () => {
    const cleanups: Array<{ label: string; run: () => Promise<void> }> = [
      { label: "active SSH service", run: async () => service.dispose?.() },
      { label: "Xray service", run: async () => xrayService.dispose() },
      { label: "service initialization", run: waitForApplicationServicesInitializationOnShutdown }
    ];
    const results = await Promise.allSettled(cleanups.map(({ run }) => run()));
    for (const [index, result] of results.entries()) {
      if (result.status === "rejected") {
        await writeMainLog(`Shutdown cleanup failed for ${cleanups[index].label}: ${formatError(result.reason)}`);
      }
    }
    // Close only after cleanup diagnostics have been appended. The logger can
    // otherwise reopen its lazy handle for a late failure message.
    await mainLogger.close().catch(() => undefined);
  }).finally(() => {
    try {
      trayController.destroy();
      serviceEventUnsubscribe?.();
      xrayEventUnsubscribe?.();
    } finally {
      allowFinalQuit = true;
      app.quit();
    }
  });
});

async function createWindow(): Promise<void> {
  if (mainWindowCreation) {
    return mainWindowCreation;
  }
  const creation = createMainWindow({
    ...runtimeFormatOptions,
    appName: app.getName(),
    rendererDist,
    preloadPath,
    iconPath,
    width: DEFAULT_WINDOW_WIDTH,
    height: DEFAULT_WINDOW_HEIGHT,
    backgroundColor: windowBackgroundColor(storage.getSettings()),
    startHidden: false,
    devServerUrl: process.env.VITE_DEV_SERVER_URL,
    onCreated: (window) => {
      const webContentsId = window.webContents.id;
      trustedRendererWebContentsIds.add(webContentsId);
      window.once("closed", () => trustedRendererWebContentsIds.delete(webContentsId));
    },
    onClosed: () => undefined,
    onClose: (event, window) => trayController.handleWindowClose(event, window),
    appendError,
    writeLog: writeMainLog
  }).then(() => undefined);
  mainWindowCreation = creation;
  try {
    await creation;
  } finally {
    if (mainWindowCreation === creation) {
      mainWindowCreation = undefined;
    }
  }
}

function requestWindowShow(): void {
  if (!windowCreationAllowed) {
    windowShowRequested = true;
    return;
  }
  void showOrCreateWindow().catch((error: unknown) => {
    const message = `Unable to show application window: ${formatError(error)}`;
    appendError(message);
    void writeMainLog(message);
  });
}

async function showOrCreateWindow(): Promise<void> {
  if (!BrowserWindow.getAllWindows().some((window) => !window.isDestroyed())) {
    await createWindow();
  }
  trayController.showWindow();
}

function currentProcessRoutingRefreshIntervalMs(): number {
  const hasForegroundWindow =
    systemSessionActive &&
    BrowserWindow.getAllWindows().some(
      (window) => !window.isDestroyed() && window.isVisible() && !window.isMinimized()
    );
  return systemEnergyPolicy.processRoutingRefreshIntervalMs(hasForegroundWindow);
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
    const initialRuntime: RuntimeStatus = {
      ...createDefaultRuntimeStatus(platformTarget),
      realTunnelAvailable: false,
      transport: "live-ssh",
      message: nativeBinaryAvailable
        ? "Live SSH service is active. Native service binary is available for explicit service-mode tests."
        : "Live SSH service is active. Native service binary is missing."
    };
    const next = await createServiceBridge(initialRuntime);
    if (applicationQuitting) {
      await next.service.dispose?.();
      markApplicationServicesReady();
      return;
    }
    activateService(next.service);
    markApplicationServicesReady();
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
    if (applicationQuitting) {
      markApplicationServicesReady();
      await writeMainLog(message);
      return;
    }
    activateService(
      new InProcessServiceBridge({
        ...runtime,
        state: "Error",
        transport: "simulator",
        realTunnelAvailable: false,
        message
      })
    );
    markApplicationServicesReady();
    appendError(message);
    await writeMainLog(message);
  }
}

function markApplicationServicesReady(): void {
  if (applicationServicesReadyResolved) {
    return;
  }
  applicationServicesReadyResolved = true;
  resolveApplicationServicesReady();
}

async function waitForApplicationServicesInitializationOnShutdown(): Promise<void> {
  const initialization = applicationServicesInitialization;
  if (!initialization) {
    return;
  }
  await initialization;
}

async function initializeApplicationStorage(): Promise<void> {
  try {
    await writeMainLog("Initializing storage.");
    await storage.init();
    const settings = storage.getSettings();
    applyLoggingSettings(settings);
    try {
      syncWindowsStartupSetting(settings);
    } catch (error) {
      const message = `Windows startup integration failed: ${formatError(error)}`;
      appendError(message);
      await writeMainLog(message);
    }
    try {
      trayController.sync();
    } catch (error) {
      const message = `Tray initialization failed: ${formatError(error)}`;
      appendError(message);
      await writeMainLog(message);
    }
    storageInitialized = true;
    await writeMainLog("Storage initialized before renderer startup.");
  } catch (error) {
    const message = `Storage initialization failed: ${formatError(error)}`;
    runtime = {
      ...runtime,
      state: "Error",
      message
    };
    appendError(message);
    await writeMainLog(message);
  }
}

async function restoreStaleWindowsProxyState(): Promise<void> {
  if (process.platform !== "win32") {
    return;
  }
  try {
    const recovered = await recoverWindowsSystemProxy([routingDataPath, path.join(routingDataPath, "xray")]);
    if (recovered) {
      await writeMainLog("Recovered stale Windows proxy state from the previous application run.");
    }
  } catch (error) {
    const message = `Stale Windows proxy recovery failed: ${formatError(error)}`;
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
  handleTrustedIpc(IPC_CHANNELS.loadSnapshot, () => {
    if (!rendererSnapshotHandshakeReported) {
      rendererSnapshotHandshakeReported = true;
      void writeMainLog("Renderer snapshot IPC handshake completed.");
    }
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.upsertConfig, async (_event, input: UpsertSshConfigInput) => {
    const store = await storage.upsertConfig(input);
    const config = store.sshConfigs.find((candidate) => candidate.id === input.id) ?? store.sshConfigs.at(-1);
    if (config) {
      await service.updateConfig(config);
    }
    return createSnapshot(store);
  });
  handleTrustedIpc(IPC_CHANNELS.deleteConfig, async (_event, id: string) => {
    const store = await storage.deleteConfig(id);
    return createSnapshot(store);
  });
  handleTrustedIpc(IPC_CHANNELS.selectConfig, async (_event, id: string) => {
    const store = await storage.selectConfig(id);
    return createSnapshot(store);
  });
  handleTrustedIpc(IPC_CHANNELS.upsertKey, async (_event, input: UpsertSshKeyInput) => {
    const store = await storage.upsertKey(input);
    return createSnapshot(store);
  });
  handleTrustedIpc(IPC_CHANNELS.copyPrivateKey, (_event, id: string) => {
    clipboard.writeText(storage.readPrivateKeyText(id));
    return true;
  });
  handleTrustedIpc(IPC_CHANNELS.deleteKey, async (_event, id: string) => {
    const store = await storage.deleteKey(id);
    return createSnapshot(store);
  });
  handleTrustedIpc(IPC_CHANNELS.upsertProxyProfile, async (_event, input: UpsertProxyProfileInput) => {
    const store = await storage.upsertProxyProfile(input);
    return createSnapshot(store);
  });
  handleTrustedIpc(IPC_CHANNELS.importProxyProfiles, async (_event, input: ImportProxyProfilesInput) => {
    const result = await storage.importProxyProfiles(input);
    return { snapshot: createSnapshot(result.store), result: result.result };
  });
  handleTrustedIpc(IPC_CHANNELS.refreshProxyProfiles, async () => {
    const result = await refreshPublicProxyProfiles(storage, { fetchImpl: electronSessionFetch });
    return { snapshot: createSnapshot(), result };
  });
  handleTrustedIpc(IPC_CHANNELS.selectProxyProfile, async (_event, id: string) => {
    const store = await storage.selectProxyProfile(id);
    return createSnapshot(store);
  });
  handleTrustedIpc(IPC_CHANNELS.toggleProxyProfilePin, async (_event, id: string) => {
    const store = await storage.toggleProxyProfilePin(id);
    return createSnapshot(store);
  });
  handleTrustedIpc(IPC_CHANNELS.deleteProxyProfile, async (_event, id: string) => {
    if (activeTransport === "xray" && xrayService.getStatus().activeConfigId === id) {
      await disconnectActiveTransport();
    }
    const store = await storage.deleteProxyProfile(id);
    return createSnapshot(store);
  });
  handleTrustedIpc(IPC_CHANNELS.deleteUnpinnedProxyProfiles, async () => {
    if (activeTransport === "xray") {
      await disconnectActiveTransport();
    }
    const store = await storage.deleteUnpinnedProxyProfiles();
    return createSnapshot(store);
  });
  handleTrustedIpc(IPC_CHANNELS.updateSettings, async (_event, patch: Partial<AppSettings>) => {
    const previousSettings = storage.getSettings();
    const nextStore = await storage.updateSettings(patch);
    const nextSettings = nextStore.settings;
    applyLoggingSettings(nextSettings);
    for (const window of BrowserWindow.getAllWindows()) {
      if (!window.isDestroyed()) {
        window.setBackgroundColor(windowBackgroundColor(nextSettings));
      }
    }
    if (previousSettings.startWithWindowsInTray !== nextSettings.startWithWindowsInTray) {
      syncWindowsStartupSetting(nextSettings);
    }
    if (
      previousSettings.closeToTrayEnabled !== nextSettings.closeToTrayEnabled ||
      previousSettings.releaseRendererInTrayEnabled !== nextSettings.releaseRendererInTrayEnabled
    ) {
      trayController.sync();
    }
    return createSnapshot(nextStore);
  });
  handleTrustedIpc(IPC_CHANNELS.updateRoutingMode, async (_event, mode: RoutingMode) => {
    const store = await storage.updateRoutingMode(mode);
    await applyActiveTransportRoutingChange(mode);
    return createSnapshot(store);
  });
  handleTrustedIpc(IPC_CHANNELS.updateRoutingRules, async (_event, rules: RoutingRule[]) => {
    const store = await storage.updateRoutingRules(rules);
    await applyRoutingConfigurationAfterMutation();
    return createSnapshot(store);
  });
  handleTrustedIpc(IPC_CHANNELS.updateRoutingProxyListEnabled, async (_event, enabled: boolean) => {
    const current = storage.getStore().routingProxyList;
    if (enabled && current.domains.length === 0) {
      await refreshRoutingProxyList({ enabled: true });
    } else {
      await storage.updateRoutingProxyList({ ...current, enabled });
    }
    await applyRoutingListsChange();
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.refreshRoutingProxyList, async () => {
    await refreshRoutingProxyList();
    await applyRoutingListsChange();
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.updateRoutingDirectListEnabled, async (_event, enabled: boolean) => {
    const current = storage.getStore().routingDirectList;
    if (enabled && current.domains.length === 0) {
      await refreshRoutingDirectList({ enabled: true });
    } else {
      await storage.updateRoutingDirectList({ ...current, enabled });
    }
    await applyRoutingListsChange();
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.refreshRoutingDirectList, async () => {
    await refreshRoutingDirectList();
    await applyRoutingListsChange();
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.clearDiagnostics, () => {
    diagnostics = [];
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.readLogFile, () => readMainLogContent());
  handleTrustedIpc(IPC_CHANNELS.clearLogFile, () => clearMainLogFiles());
  handleTrustedIpc(IPC_CHANNELS.listProcesses, () => listActiveProcesses());
  handleTrustedIpc(IPC_CHANNELS.connect, async () => {
    await connect();
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.connectProxy, async () => {
    await connectProxy();
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.disconnect, async () => {
    await disconnectActiveTransport();
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.checkTunnel, async (_event, endpoint?: string) => {
    const settings = storage.getSettings();
    lastTunnelCheck = await activeTunnelService().checkTunnel(endpoint ?? settings.checkEndpoint);
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.openTerminal, async () => {
    await activeTunnelService().openTerminal();
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.closeTerminal, async () => {
    await activeTunnelService().closeTerminal();
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.terminalInput, async (_event, input: string) => {
    if (typeof input !== "string" || input.length === 0 || input.length > MAX_TERMINAL_INPUT_CHARACTERS) {
      throw new Error("Terminal input is invalid or too large.");
    }
    await activeTunnelService().terminalInput(input);
  });
  handleTrustedIpc(IPC_CHANNELS.checkForUpdates, async (_event, force?: boolean) => {
    const update = await portableUpdates.check({
      currentVersion: app.getVersion(),
      platformTarget,
      storage,
      force: Boolean(force)
    });
    return { snapshot: createSnapshot(), update };
  });
  handleTrustedIpc(IPC_CHANNELS.downloadUpdate, async () => {
    await portableUpdates.downloadSelected();
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.revealDownloadedUpdate, async () => {
    if (!portableUpdates.download.filePath) {
      return false;
    }
    shell.showItemInFolder(portableUpdates.download.filePath);
    return true;
  });
  handleTrustedIpc(IPC_CHANNELS.copyText, (_event, text: string) => {
    if (typeof text !== "string" || text.length > MAX_CLIPBOARD_TEXT_CHARACTERS) {
      throw new Error("Clipboard payload is invalid.");
    }
    clipboard.writeText(text);
    return true;
  });
  handleTrustedIpc(IPC_CHANNELS.openExternal, async (_event, url: string) => {
    await shell.openExternal(assertAllowedExternalUrl(url));
    return true;
  });
}

function handleTrustedIpc<TArgs extends unknown[], TResult>(
  channel: string,
  listener: (event: Electron.IpcMainInvokeEvent, ...args: TArgs) => TResult | Promise<TResult>
): void {
  ipcMain.handle(channel, (event, ...args) => {
    const frame = event.senderFrame ?? webFrameMain.fromId(event.processId, event.frameId) ?? null;
    const mainFrame = event.sender.mainFrame;
    const senderUrl = event.sender.getURL();
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    const senderIsRegisteredWindow = Boolean(
      ownerWindow &&
        !ownerWindow.isDestroyed() &&
        !event.sender.isDestroyed() &&
        trustedRendererWebContentsIds.has(event.sender.id)
    );
    const applicationWindowWebContentsIds = senderIsRegisteredWindow ? [event.sender.id] : [];
    const frameWebContentsId = frame && !frame.detached ? webContents.fromFrame(frame)?.id : undefined;
    const trust = assessRendererIpcTrust({
      senderWebContentsId: event.sender.id,
      applicationWindowWebContentsIds,
      senderUrl,
      trustedUrl: trustedRendererEntryUrl,
      senderFrame: frame,
      mainFrame,
      frameWebContentsId
    });
    if (!trust.trusted) {
      if (!rejectedRendererIpcReported) {
        rejectedRendererIpcReported = true;
        void writeMainLog(
          `Rejected renderer IPC. channel=${channel}, reason=${trust.reason}, senderId=${event.sender.id}, appWindowIds=${
            applicationWindowWebContentsIds.join(",") || "none"
          }, frameTree=${frame?.frameTreeNodeId ?? "none"}, mainTree=${mainFrame.frameTreeNodeId}, detached=${
            frame?.detached ?? "unknown"
          }, sender=${formatRuntimeUrl(senderUrl)}, frame=${formatRuntimeUrl(frame?.url ?? "")}, trusted=${formatRuntimeUrl(
            trustedRendererEntryUrl
          )}`
        );
      }
      throw new Error("Rejected IPC request from an untrusted renderer frame.");
    }
    return listener(event, ...(args as TArgs));
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
    }, {
      systemProxy: sharedSystemProxy,
      processRoutingRefreshIntervalMs: currentProcessRoutingRefreshIntervalMs
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

async function connect(expectedGeneration?: number): Promise<boolean> {
  const store = storage.getStore();
  const config = store.sshConfigs.find((candidate) => candidate.id === store.selectedConfigId);
  if (!config) {
    appendError("Select or create an SSH configuration before connecting.");
    return false;
  }

  if (store.routingMode === "selected-rules" && !hasSelectedRoutingTargets(store)) {
    appendError("Selected rules mode requires at least one enabled routing rule or enabled proxy-list domain.");
    return false;
  }

  const request = {
    config,
    routingMode: store.routingMode,
    routingRules: store.routingRules,
    routingProxyDomains: activeRoutingProxyDomains(),
    routingDirectDomains: activeRoutingDirectDomains(),
    checkEndpoint: store.settings.checkEndpoint,
    secrets: storage.resolveServiceSecrets(config)
  };
  return requestTransportIntent(async (generation) => {
    diagnostics = [];
    terminalOutputBatcher.clear();
    terminal = [];
    lastTunnelCheck = undefined;
    if (activeTransport === "xray") {
      await xrayService.disconnect();
    }
    if (!transportMutations.isCurrent(generation)) {
      return;
    }
    activeTransport = "ssh";
    await service.connect(request);
    if (!transportMutations.isCurrent(generation)) {
      await service.disconnect();
      return;
    }
    await rememberLastConnectedTransport("ssh");
  }, expectedGeneration);
}

async function connectProxy(expectedGeneration?: number): Promise<boolean> {
  const store = storage.getStore();
  const profile = store.proxyProfiles.find((candidate) => candidate.id === store.selectedProxyProfileId);
  if (!profile) {
    appendError("Select or import an Xray profile before connecting.");
    return false;
  }

  if (store.routingMode === "selected-rules" && !hasSelectedRoutingTargets(store)) {
    appendError("Selected rules mode requires at least one enabled routing rule or enabled proxy-list domain.");
    return false;
  }

  const request = {
    profile,
    routingMode: store.routingMode,
    routingRules: store.routingRules,
    routingProxyDomains: activeRoutingProxyDomains(),
    routingDirectDomains: activeRoutingDirectDomains(),
    checkEndpoint: store.settings.checkEndpoint,
    secrets: storage.resolveProxySecrets(profile)
  };
  return requestTransportIntent(async (generation) => {
    diagnostics = [];
    terminalOutputBatcher.clear();
    terminal = [];
    lastTunnelCheck = undefined;
    if (activeTransport === "ssh") {
      await service.disconnect();
    }
    if (!transportMutations.isCurrent(generation)) {
      return;
    }
    activeTransport = "xray";
    await xrayService.connect(request);
    if (!transportMutations.isCurrent(generation)) {
      await xrayService.disconnect();
      return;
    }
    await rememberLastConnectedTransport("xray");
  }, expectedGeneration);
}

async function autoConnectOnStartup(): Promise<void> {
  const store = storage.getStore();
  if (!store.settings.autoConnectOnStartup) {
    await writeMainLog("Auto-connect on startup is disabled.");
    return;
  }
  if (transportMutations.generation !== 0 || transportMutations.isStopping) {
    await writeMainLog("Auto-connect skipped because a newer user transport action is already pending.");
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
      const connected = await connectProxy(0);
      if (!connected) {
        await writeMainLog("Auto-connect skipped because a newer user transport action superseded it.");
        return;
      }
      await writeMainLog(`Auto-connect completed with Xray profile "${profile.name}".`);
      return;
    }

    const config = store.sshConfigs.find((candidate) => candidate.id === store.selectedConfigId);
    if (!config) {
      await writeMainLog("Auto-connect skipped: no selected SSH configuration.");
      return;
    }
    await writeMainLog(`Auto-connect starting SSH configuration "${config.name}".`);
    const connected = await connect(0);
    if (!connected) {
      await writeMainLog("Auto-connect skipped because a newer user transport action superseded it.");
      return;
    }
    await writeMainLog(`Auto-connect completed with SSH configuration "${config.name}".`);
  } catch (error) {
    const message = `Auto-connect failed: ${formatError(error)}`;
    appendError(message);
    await writeMainLog(message);
  }
}

async function rememberLastConnectedTransport(transport: GlobalTab): Promise<void> {
  const settings = storage.getSettings();
  if (settings.lastConnectedTransport === transport && settings.activeGlobalTab === transport) {
    return;
  }
  await storage.updateSettings({
    activeGlobalTab: transport,
    lastConnectedTransport: transport
  });
}

async function disconnectActiveTransport(): Promise<void> {
  await requestTransportIntent(async (generation) => {
    if (!transportMutations.isCurrent(generation)) {
      return;
    }
    await disconnectActiveTransportInternal();
  });
}

async function disconnectActiveTransportInternal(): Promise<void> {
  if (activeTransport === "xray") {
    await xrayService.disconnect();
  } else {
    await service.disconnect();
  }
}

async function applyActiveTransportRoutingChange(mode: RoutingMode): Promise<void> {
  void mode;
  await applyRoutingConfigurationAfterMutation();
}

async function applyRoutingListsChange(): Promise<void> {
  await applyRoutingConfigurationAfterMutation();
}

async function applyRoutingConfigurationAfterMutation(): Promise<void> {
  await enqueueTransportMutation(async () => {
    await applicationServicesReady;
    if (applicationQuitting) {
      return;
    }
    const store = storage.getStore();
    const activeService = activeTunnelService();
    const action = routingMutationAction(store, activeService.getStatus().state);
    if (action === "disconnect") {
      await disconnectActiveTransportInternal();
      appendError(
        "Selected-rules routing no longer has any enabled rules or enabled proxy-list domains. The active tunnel was disconnected to prevent unintended DIRECT-all routing."
      );
      return;
    }
    if (action === "idle") {
      return;
    }
    await activeService.updateRouting({
      routingMode: store.routingMode,
      routingRules: store.routingRules,
      routingProxyDomains: activeRoutingProxyDomains(),
      routingDirectDomains: activeRoutingDirectDomains(),
      checkEndpoint: store.settings.checkEndpoint
    });
  });
}

function requestTransportIntent(
  operation: (generation: number) => Promise<void>,
  expectedGeneration?: number
): Promise<boolean> {
  return transportMutations.requestIntent(async (generation) => {
    await applicationServicesReady;
    if (!transportMutations.isCurrent(generation) || applicationQuitting) {
      return;
    }
    await operation(generation);
  }, { expectedGeneration });
}

function enqueueTransportMutation<T>(operation: () => Promise<T>): Promise<T> {
  return transportMutations.enqueue(operation);
}

async function refreshRoutingProxyList(options: { enabled?: boolean } = {}): Promise<void> {
  const current = storage.getStore().routingProxyList;
  const sourceUrl = current.sourceUrl || RUSSIA_INSIDE_PROXY_LIST_URL;
  const text = await fetchRoutingListText(sourceUrl);
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
  const text = await fetchRoutingListText(sourceUrl);
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

function activeRoutingProxyDomains(): string[] {
  const proxyList = storage.getStore().routingProxyList;
  return proxyList.enabled ? proxyList.domains : [];
}

function activeRoutingDirectDomains(): string[] {
  const directList = storage.getStore().routingDirectList;
  return directList.enabled ? directList.domains : [];
}

function activeTunnelService(): ServiceBridge | XrayServiceBridge {
  return activeTransport === "xray" ? xrayService : service;
}

function createSnapshot(store: AppStore = storage.getStore()): AppSnapshot {
  runtime = activeTransport === "xray" ? xrayService.getStatus() : service.getStatus();
  return {
    store,
    runtime,
    // Electron serializes the IPC result with structured clone. A shallow
    // array copy protects main-process ownership without needlessly cloning
    // the same large strings twice.
    diagnostics: diagnostics.slice(),
    logFilePaths: uniqueLogPaths(),
    terminal: terminal.slice(),
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
    const entry = normalizeDiagnosticEntry(event.entry);
    if (shouldPersistDiagnostic(entry)) {
      void writeMainLog(`${entry.level.toUpperCase()} ${entry.message}`);
    }
    if (!appendDiagnosticEntry(entry)) {
      return;
    }
    broadcast({ type: "diagnostics-appended", entry });
    return;
  }
  if (event.type === "terminal-output") {
    if (!isActive) {
      return;
    }
    terminalOutputBatcher.enqueue(source, event.line);
    return;
  }
  if (event.type === "tunnel-check-result") {
    if (!isActive) {
      return;
    }
    lastTunnelCheck = event.result;
  }
  if (event.type === "error") {
    const entry = appendError(event.message);
    void writeMainLog(`ERROR ${entry.message}`);
    return;
  }
  if (isActive) {
    broadcast(event);
  }
}

function appendError(message: string): DiagnosticsEntry {
  const entry = normalizeDiagnosticEntry({
    id: randomUUID(),
    at: new Date().toISOString(),
    level: "error",
    message
  });
  if (appendDiagnosticEntry(entry)) {
    broadcast({ type: "diagnostics-appended", entry });
  }
  return entry;
}

function appendInfo(message: string): void {
  const entry = normalizeDiagnosticEntry({
    id: randomUUID(),
    at: new Date().toISOString(),
    level: "info",
    message
  });
  if (appendDiagnosticEntry(entry)) {
    broadcast({ type: "diagnostics-appended", entry });
  }
  void writeMainLog(`INFO ${entry.message}`);
}

function appendDiagnosticEntry(entry: DiagnosticsEntry): DiagnosticsEntry | undefined {
  if (!diagnosticsLoggingEnabled) {
    return undefined;
  }
  const normalized = normalizeDiagnosticEntry(entry);
  diagnostics = appendBoundedDiagnosticEntries(
    diagnostics,
    [normalized],
    MAX_DIAGNOSTICS_HISTORY_ENTRIES,
    MAX_DIAGNOSTICS_HISTORY_BYTES
  );
  return normalized;
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

function broadcast(event: RendererEvent): void {
  for (const window of BrowserWindow.getAllWindows()) {
    const windowDestroyed = window.isDestroyed();
    if (windowDestroyed) {
      continue;
    }
    const contents = window.webContents;
    if (
      !shouldDeliverRendererEvent({
        windowDestroyed,
        webContentsDestroyed: contents.isDestroyed(),
        visible: window.isVisible(),
        minimized: window.isMinimized()
      })
    ) {
      continue;
    }
    contents.send(IPC_CHANNELS.serviceEvent, event);
  }
}

async function writeMainLog(message: string): Promise<void> {
  if (!loggingMasterEnabled) {
    return;
  }
  if (!fileLoggingEnabled) {
    return;
  }
  try {
    await mainLogger.append(`[${new Date().toISOString()}] ${message}`);
  } catch {
    // Logging must never break app startup.
  }
}

async function readMainLogContent(): Promise<string> {
  try {
    const content = await mainLogger.readTail();
    return content ? `### ${mainLogPath}\n${content.trimEnd()}` : "";
  } catch (error) {
    return `### ${mainLogPath}\nUnable to read log file: ${formatError(error)}`;
  }
}

async function clearMainLogFiles(): Promise<string> {
  try {
    await mainLogger.clear();
  } catch {
    // Clearing logs should not destabilize the application.
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
  return [mainLogPath, ...Array.from({ length: MAIN_LOG_BACKUP_COUNT }, (_, index) => `${mainLogPath}.${index + 1}`)];
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
