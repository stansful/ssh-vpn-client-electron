import {
  app,
  BrowserWindow,
  clipboard,
  ipcMain,
  Menu,
  nativeTheme,
  powerMonitor,
  safeStorage,
  screen,
  session,
  shell,
  webContents,
  webFrameMain
} from "electron";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { randomUUID } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { AppStorage, StorageUnreadableError } from "./storage/app-storage.js";
import { listActiveProcesses } from "./processes.js";
import { createPlatformTarget, nativeServiceExists, resolveNativeServicePath } from "./platform/targets.js";
import { detectTunEnvironment } from "./platform/tun-environment.js";
import { createDefaultRuntimeStatus, RUSSIA_INSIDE_PROXY_LIST_URL, RUSSIA_OUTSIDE_DIRECT_LIST_URL } from "../shared/defaults.js";
import { IPC_CHANNELS, type RendererEvent, type ServiceEvent } from "../shared/ipc.js";
import { parseDomainProxyList } from "../core/routing/domain-proxy-list.js";
import { recoverWindowsSystemProxy, WindowsSystemProxyManager } from "../core/network/windows-system-proxy.js";
import { LocalIpcServiceBridge } from "../service/local-ipc-client.js";
import { defaultServiceEndpoint } from "../service/local-ipc-protocol.js";
import { NativeProcessServiceBridge } from "../service/native-process-client.js";
import { LiveSshServiceBridge } from "../service/live-ssh-service.js";
import { XrayServiceBridge } from "../service/xray-service.js";
import { applicationMenuTemplate } from "./app/app-menu.js";
import { createMainWindow, fitWindowSize, type CrashPageTunnel } from "./app/main-window.js";
import { resolveAppDataLayout, resolveUserDataPath, resolveXrayExecutablePath } from "./app/paths.js";
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
import { assertAllowedExternalUrl } from "./app/external-urls.js";
import { TerminalOutputBatcher } from "./app/terminal-output-batcher.js";
import { TrayController, resolveTrayIconPaths } from "./app/tray.js";
import { buildTrayMenuModel } from "./app/tray-model.js";
import { DesktopNotifier } from "./app/notifications.js";
import {
  AttentionStore,
  attentionFromDiagnostic,
  autoConnectFailedAttention,
  autoConnectSkippedAttention,
  splitTunnelNoTargetsAttention,
  storageUnreadableAttention,
  storageWriteFailedAttention,
  systemProxyRecoveredAttention,
  systemProxyRecoveryFailedAttention,
  type AttentionInput
} from "./app/attention-store.js";
import { createAppEnvironment, deriveTunStatus, isLiveSessionState, type TunEnvironmentFacts } from "./app/environment.js";
import { ERROR_SETTLE_DELAY_MS, TunnelTransitionTracker, type TunnelTransition } from "./app/session-transitions.js";
import { TunnelCheckSessionGuard } from "./app/tunnel-check-guard.js";
import { shouldDeliverRendererEvent, SystemEnergyPolicy, type ThermalState } from "./app/energy-policy.js";
import type { FetchImplementation } from "../shared/http-fetch.js";
import {
  appendBoundedDiagnosticEntries,
  MAX_DIAGNOSTICS_HISTORY_BYTES,
  MAX_DIAGNOSTICS_HISTORY_ENTRIES,
  normalizeDiagnosticEntry,
  withDiagnosticSource
} from "../shared/diagnostics-history.js";
import { appendBoundedTerminalLine } from "../shared/terminal-history.js";
import type {
  AppEnvironment,
  AppSettings,
  AutoConnectNotice,
  AppSnapshot,
  AppStore,
  AppUpdateDownload,
  AppUpdateInfo,
  DiagnosticsEntry,
  DiagnosticsSource,
  GlobalTab,
  ImportProxyProfilesInput,
  RoutingMode,
  RoutingMutationResult,
  RoutingRule,
  RuntimeStatus,
  StorageHealth,
  TerminalLine,
  TunnelCheckResult,
  TunStatus,
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
const notificationIconPath = path.join(app.isPackaged ? process.resourcesPath : path.join(projectRoot, "resources"), "icons", "icon.png");
const runtimeFormatOptions = { packaged: app.isPackaged, resourcesPath: process.resourcesPath };
const trayIconPaths = resolveTrayIconPaths({ packaged: app.isPackaged, projectRoot, resourcesPath: process.resourcesPath });
const appDisplayName = process.env.SHADOW_SSH_BUILD_CHANNEL === "development" ? "Shadow SSH Dev" : "Shadow SSH";
const explicitUserDataPath = resolveUserDataPath(appDisplayName);
const dataLayout = resolveAppDataLayout(explicitUserDataPath);
const persistedStorePath = dataLayout.storePath;
const mainLogPath = dataLayout.mainLogPath;
const routingDataPath = dataLayout.routingDirectory;
const xrayRuntimeDataPath = dataLayout.xrayRuntimeDirectory;
const updateDownloadPath = dataLayout.updatesDirectory;
const PREFERRED_WINDOW_SIZE = { width: 1200, height: 800 };
/** The design adapts down to phone width, so the window may get narrow. */
const MINIMUM_WINDOW_SIZE = { width: 460, height: 600 };
const START_MINIMIZED_TO_TRAY_ARG = "--shadow-ssh-start-minimized-to-tray";
/** `build.appId` in package.json; the installer registers its shortcut under it. */
const WINDOWS_APP_USER_MODEL_ID = "app.shadowssh.desktop";
const MAX_MAIN_LOG_BYTES = 5 * 1024 * 1024;
const MAX_MAIN_LOG_READ_BYTES = 1024 * 1024;
const MAIN_LOG_BACKUP_COUNT = 2;
const MAX_CLIPBOARD_TEXT_CHARACTERS = 2 * 1024 * 1024;
const MAX_TERMINAL_INPUT_CHARACTERS = 64 * 1024;
const TRAY_REFRESH_DELAY_MS = 120;
const TUN_ENVIRONMENT_REFRESH_INTERVAL_MS = 10_000;
const DARK_WINDOW_BACKGROUND = "#0A0B0D";
const LIGHT_WINDOW_BACKGROUND = "#F3F3F0";

const formatRuntimePath = (value: string): string => formatRuntimePathValue(runtimeFormatOptions, value);
const formatRuntimeUrl = (value: string): string => formatRuntimeUrlValue(runtimeFormatOptions, value);
const windowBackgroundColor = (settings: AppSettings): string => {
  if (settings.theme === "dark") {
    return DARK_WINDOW_BACKGROUND;
  }
  if (settings.theme === "light") {
    return LIGHT_WINDOW_BACKGROUND;
  }
  if (settings.theme === "custom") {
    return `#${[settings.customTheme.background.r, settings.customTheme.background.g, settings.customTheme.background.b]
      .map((value) => Math.max(0, Math.min(255, Math.round(value))).toString(16).padStart(2, "0"))
      .join("")}`;
  }
  return nativeTheme.shouldUseDarkColors ? DARK_WINDOW_BACKGROUND : LIGHT_WINDOW_BACKGROUND;
};
const startMinimizedToTray = process.argv.includes(START_MINIMIZED_TO_TRAY_ARG);
const electronSessionFetch: FetchImplementation = (input, init) => session.defaultSession.fetch(input, init);
const trustedRendererEntryUrl = process.env.VITE_DEV_SERVER_URL ?? pathToFileURL(path.join(rendererDist, "index.html")).href;

interface ConnectOptions {
  /** Only start when no newer user intent has arrived (auto-connect). */
  expectedGeneration?: number;
  /** Close a live session of the same transport first (switching servers). */
  restart?: boolean;
}

let runtime: RuntimeStatus;
let diagnostics: DiagnosticsEntry[] = [];
let terminal: TerminalLine[] = [];
let lastTunnelCheck: TunnelCheckResult | undefined;
/** The connection whose tunnel has already been verified, so it is verified once. */
let verifiedConnectionKey: string | undefined;
let tunnelVerificationTimer: NodeJS.Timeout | undefined;
let service: ServiceBridge;
let serviceEventUnsubscribe: (() => void) | undefined;
let diagnosticsLoggingEnabled = true;
let fileLoggingEnabled = true;
let loggingMasterEnabled = true;
let applicationQuitting = false;
let activeTransport: GlobalTab = "ssh";
let storageInitialized = false;
let storageHealth: StorageHealth = { state: "ok" };
let storageRecovery: Promise<void> | undefined;
let windowShowRequested = false;
let windowCreationAllowed = false;
let mainWindowCreation: Promise<void> | undefined;
let applicationServicesReadyResolved = false;
let applicationServicesInitialization: Promise<void> | undefined;
let rejectedRendererIpcReported = false;
let rendererSnapshotHandshakeReported = false;
let tunEnvironment: TunEnvironmentFacts | undefined;
let tunEnvironmentCheckedAt = 0;
let tunEnvironmentRefresh: Promise<void> | undefined;
/** `tunDataplaneEnabled` the current session started with. */
let sessionTunSetting: boolean | undefined;
let tunnelChecksInFlight = 0;
/** Why the connection core didn't start (Connect runs the simulator), shown as "Preview only". */
let startupFailure: string | undefined;
let autoConnectNotice: AutoConnectNotice | undefined;
let trayRefreshTimer: NodeJS.Timeout | undefined;
let transitionSettleTimer: NodeJS.Timeout | undefined;
let lastAnnouncedUpdateVersion: string | undefined;
let previousUpdateDownloadState: AppUpdateDownload["state"] = "idle";
const attention = new AttentionStore();
const tunnelTransitions = new TunnelTransitionTracker();
const tunnelCheckSessions = new TunnelCheckSessionGuard();
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
  (download) => {
    broadcast({ type: "update-download-changed", download });
    handleUpdateDownloadChanged(download);
  },
  electronSessionFetch
);
const terminalOutputBatcher = new TerminalOutputBatcher<GlobalTab>(({ source, lines, droppedBytes }) => {
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
if (process.platform === "win32") {
  // Windows attributes toasts to an AppUserModelID; without one (a portable
  // build has no Start-menu shortcut) desktop notifications may never show.
  app.setAppUserModelId(WINDOWS_APP_USER_MODEL_ID);
}
registerProcessErrorHandlers();
app.on("second-instance", requestWindowShow);
await preloadLoggingPreference();
await ensureExplicitUserDataPath();
await writeMainLog(`Main module loaded. pid=${process.pid}, platform=${process.platform}, arch=${process.arch}, userData=${explicitUserDataPath}`);

await app.whenReady();
const applicationMenu = applicationMenuTemplate(process.platform);
Menu.setApplicationMenu(applicationMenu ? Menu.buildFromTemplate(applicationMenu) : null);
await writeMainLog(
  `Application ready. packaged=${app.isPackaged}, resourcesPath=${formatRuntimePath(process.resourcesPath)}, dirname=${formatRuntimePath(__dirname)}, electronUserData=${app.getPath("userData")}`
);

const platformTarget = createPlatformTarget();
const appEnvironment: AppEnvironment = createAppEnvironment({
  version: app.getVersion(),
  platform: process.platform,
  arch: process.arch,
  dataDirectory: explicitUserDataPath,
  logDirectory: dataLayout.logDirectory,
  isPackaged: app.isPackaged,
  buildChannel: process.env.SHADOW_SSH_BUILD_CHANNEL,
  secrets: {
    encryptionAvailable: safeStorage.isEncryptionAvailable(),
    selectedBackend: process.platform === "linux" ? safeStorage.getSelectedStorageBackend?.() : undefined,
    insecureFallbackAllowed: process.env.SHADOW_SSH_ALLOW_INSECURE_SECRET_FALLBACK === "1"
  }
});
void refreshTunEnvironment(true);
const systemEnergyPolicy = new SystemEnergyPolicy({
  onBatteryPower: powerMonitor.isOnBatteryPower(),
  thermalState: process.platform === "darwin" ? powerMonitor.getCurrentThermalState() : "unknown"
});
let systemSessionActive = true;
powerMonitor.on("on-battery", () => systemEnergyPolicy.setOnBatteryPower(true));
powerMonitor.on("on-ac", () => systemEnergyPolicy.setOnBatteryPower(false));
powerMonitor.on("suspend", () => {
  systemSessionActive = false;
  void writeMainLog("System suspend.");
});
powerMonitor.on("resume", () => {
  systemSessionActive = true;
  void writeMainLog("System resume.");
  // The SSH socket almost never survives a sleep: NAT mappings expire and the
  // server may have closed the session unheard. Let the transports check now
  // rather than discover it at the next keepalive.
  wakeTransports("system resume");
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
    // Read-only helper for per-connection process attribution; it never
    // carries tunnel traffic.
    nativeServiceExecutablePath: nativeServiceExists(projectRoot, platformTarget)
      ? resolveNativeServicePath(projectRoot, platformTarget)
      : undefined,
    userDataDirectory: explicitUserDataPath,
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
  onQuit: quitApplication,
  onConnect: () => runBackgroundAction("tray connect", () => connectTransport(storage.getSettings().lastConnectedTransport)),
  onDisconnect: () => runBackgroundAction("tray disconnect", disconnectActiveTransport),
  onRetry: () => runBackgroundAction("tray retry", () => connectTransport(activeTransport)),
  onSelectServer: (kind, id) => runBackgroundAction("tray switch", () => switchTunnelTarget(kind, id)),
  onRunCheck: () => runBackgroundAction("tray check", () => runTunnelCheck()),
  onUpdateError: (error) => {
    void writeMainLog(`Tray update failed: ${formatError(error)}`);
  }
});
const desktopNotifier = new DesktopNotifier({
  appName: appDisplayName,
  iconPath: notificationIconPath,
  getSettings: () => storage.getSettings(),
  isWindowVisible: isAnyWindowVisible,
  onOpenWindow: requestWindowShow,
  onStopReconnecting: () => runBackgroundAction("stop reconnecting", stopReconnectingFromNotification),
  onRevealUpdate: () => {
    revealDownloadedUpdate();
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
  applicationServicesInitialization = initializeApplicationServices({ autoConnect: true });
  void applicationServicesInitialization;
} else {
  // Saved data is unreadable: nothing connects until the recovery screen
  // has been answered (recoverStorage starts the services then).
  markApplicationServicesReady();
}
scheduleTrayRefresh();

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
  clearTimer(trayRefreshTimer);
  cancelTransitionSettle();
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
      desktopNotifier.dispose();
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
  const size = fitWindowSize(PREFERRED_WINDOW_SIZE, MINIMUM_WINDOW_SIZE, screen.getPrimaryDisplay().workAreaSize);
  const creation = createMainWindow({
    ...runtimeFormatOptions,
    appName: app.getName(),
    rendererDist,
    preloadPath,
    iconPath,
    width: size.width,
    height: size.height,
    minWidth: MINIMUM_WINDOW_SIZE.width,
    minHeight: MINIMUM_WINDOW_SIZE.height,
    backgroundColor: windowBackgroundColor(storage.getSettings()),
    startHidden: false,
    devServerUrl: process.env.VITE_DEV_SERVER_URL,
    onCreated: (window) => {
      const webContentsId = window.webContents.id;
      trustedRendererWebContentsIds.add(webContentsId);
      window.once("closed", () => trustedRendererWebContentsIds.delete(webContentsId));
    },
    onClosed: () => undefined,
    onClose: handleWindowClose,
    appendError: (message) => {
      appendError(message);
    },
    writeLog: writeMainLog,
    describeTunnel: describeTunnelForCrashPage,
    onOpenLogFolder: () => {
      void openFolder(dataLayout.logDirectory, "log folder").catch((error: unknown) => {
        void writeMainLog(`Unable to open the log folder: ${formatError(error)}`);
      });
    },
    isQuitting: () => applicationQuitting
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

function isAnyWindowVisible(): boolean {
  return BrowserWindow.getAllWindows().some((window) => !window.isDestroyed() && window.isVisible() && !window.isMinimized());
}

function handleWindowClose(event: Electron.Event, window: BrowserWindow): void {
  trayController.handleWindowClose(event, window);
  if (window.isDestroyed() || window.isVisible()) {
    return;
  }
  // The window went to the tray rather than closing.
  if (!isLiveSessionState(activeTunnelService().getStatus().state)) {
    return;
  }
  appendInfo(`Window hidden to the ${process.platform === "darwin" ? "menu bar" : "tray"}. The tunnel stays connected.`);
  if (storageHealth.state !== "ok" || storage.getSettings().stillRunningNoticeShown) {
    return;
  }
  if (desktopNotifier.notifyStillRunningInTray()) {
    void storage.updateSettings({ stillRunningNoticeShown: true }).catch((error: unknown) => {
      void writeMainLog(`Unable to remember the tray notice: ${formatError(error)}`);
    });
  }
}

function quitApplication(): void {
  applicationQuitting = true;
  trayController.prepareForQuit();
  app.quit();
}

function wakeTransports(reason: string): void {
  try {
    service.wake?.(reason);
  } catch (error) {
    void writeMainLog(`SSH service wake failed: ${formatError(error)}`);
  }
  try {
    xrayService.wake(reason);
  } catch (error) {
    void writeMainLog(`Xray service wake failed: ${formatError(error)}`);
  }
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

async function initializeApplicationServices({ autoConnect }: { autoConnect: boolean }): Promise<void> {
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
    startupFailure = next.startupDiagnostic?.message;
    activateService(next.service);
    markApplicationServicesReady();
    if (next.startupDiagnostic) {
      const appended = appendDiagnosticEntry(next.startupDiagnostic);
      if (appended) {
        broadcast({ type: "diagnostics-appended", entry: appended });
      }
      await writeMainLog(`${next.startupDiagnostic.level.toUpperCase()} ${next.startupDiagnostic.message}`);
    }
    await writeMainLog("Application services initialized.");
    if (autoConnect) {
      await autoConnectOnStartup();
    }
  } catch (error) {
    const message = `Startup failed: ${formatError(error)}`;
    if (applicationQuitting) {
      markApplicationServicesReady();
      await writeMainLog(message);
      return;
    }
    startupFailure = message;
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
    const { writeError } = await storage.init();
    await finishStorageInitialization();
    if (writeError) {
      // Read fine, so nothing is "unreadable": the data is in use and the next save writes it again.
      const message = `Saved data was loaded, but updating its file failed: ${errorMessage(writeError)}`;
      appendDiagnostic("warning", message);
      await writeMainLog(`WARNING ${message}`);
      recordAttention(storageWriteFailedAttention(errorMessage(writeError)));
    }
    await writeMainLog("Storage initialized before renderer startup.");
  } catch (error) {
    const message = `Storage initialization failed: ${formatError(error)}`;
    const reason = errorMessage(error);
    const unreadable = error instanceof StorageUnreadableError ? error : undefined;
    storageHealth = {
      state: "unreadable",
      message: reason,
      storePath: unreadable?.filePath ?? storage.storePath,
      dataDirectory: storage.dataDirectory,
      ...(unreadable && !unreadable.files.includes("store") ? { secretsOnly: true } : {})
    };
    appendError(message);
    await writeMainLog(message);
    recordAttention(storageUnreadableAttention(reason));
    // The store keeps refusing writes until the recovery screen is answered;
    // the tray stays so a hidden or closed window can still be reached.
    try {
      trayController.sync();
    } catch (trayError) {
      await writeMainLog(`Tray initialization failed: ${formatError(trayError)}`);
    }
  }
}

/** Everything that follows a store that could be read: on start, and after "Start fresh". */
async function finishStorageInitialization(): Promise<void> {
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
}

async function recoverStorageStartFresh(): Promise<void> {
  if (storageHealth.state === "ok") {
    return;
  }
  if (!storageRecovery) {
    storageRecovery = (async () => {
      const backups = await storage.startFresh();
      storageHealth = { state: "ok" };
      await finishStorageInitialization();
      if (attention.dismissKind("storage-unreadable")) {
        broadcastAttention();
      }
      for (const window of BrowserWindow.getAllWindows()) {
        if (!window.isDestroyed()) {
          window.setBackgroundColor(windowBackgroundColor(storage.getSettings()));
        }
      }
      await writeMainLog(`Started fresh after unreadable saved data. Backups: ${backups.map(formatRuntimePath).join(", ") || "none"}.`);
      appendInfo(
        backups.length > 0
          ? `Started fresh. The unreadable data was kept as ${backups.map((backup) => path.basename(backup)).join(" and ")}.`
          : "Started fresh with default settings."
      );
      // A fresh store has nothing to connect to, so auto-connect is not run.
      applicationServicesInitialization = initializeApplicationServices({ autoConnect: false });
      await applicationServicesInitialization;
      broadcastSnapshotInvalidated("storage-recovered");
      scheduleTrayRefresh();
    })().finally(() => {
      storageRecovery = undefined;
    });
  }
  await storageRecovery;
}

async function restoreStaleWindowsProxyState(): Promise<void> {
  if (process.platform !== "win32") {
    return;
  }
  try {
    const recovered = await recoverWindowsSystemProxy([routingDataPath, path.join(routingDataPath, "xray")]);
    if (recovered) {
      await writeMainLog("Recovered stale Windows proxy state from the previous application run.");
      appendInfo("Recovered stale Windows proxy settings from the previous run. Direct settings are back.");
      recordAttention(systemProxyRecoveredAttention());
    }
  } catch (error) {
    const message = `Stale Windows proxy recovery failed: ${formatError(error)}`;
    appendError(message);
    await writeMainLog(message);
    recordAttention(systemProxyRecoveryFailedAttention());
  }
}

function activateService(nextService: ServiceBridge): void {
  serviceEventUnsubscribe?.();
  service = nextService;
  serviceEventUnsubscribe = service.onEvent(handleServiceEvent);
  if (activeTransport === "ssh") {
    runtime = service.getStatus();
    broadcast({ type: "status-changed", status: runtime });
  }
  scheduleTrayRefresh();
}

function registerIpcHandlers(): void {
  handleTrustedIpc(IPC_CHANNELS.loadSnapshot, () => {
    if (!rendererSnapshotHandshakeReported) {
      rendererSnapshotHandshakeReported = true;
      void writeMainLog("Renderer snapshot IPC handshake completed.");
    }
    // wintun.dll may have been put in place since the last look.
    void refreshTunEnvironment();
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
  handleTrustedIpc(IPC_CHANNELS.renameProxyProfile, async (_event, id: string, name: string) => {
    const store = await storage.renameProxyProfile(id, name);
    const renamed = store.proxyProfiles.find((profile) => profile.id === id);
    if (renamed) {
      // The running session, the tray and the last check result take the new name without a reconnect.
      xrayService.renameActiveProfile(id, renamed.name);
      if (activeTransport === "xray" && lastTunnelCheck?.transport === "xray" && xrayService.getStatus().activeConfigId === id) {
        lastTunnelCheck = { ...lastTunnelCheck, targetName: renamed.name };
      }
    }
    return createSnapshot(store);
  });
  handleTrustedIpc(IPC_CHANNELS.copyProxyProfileLink, (_event, id: string) => {
    clipboard.writeText(storage.readProxyProfileShareLink(id));
    return true;
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
    if (previousSettings.tunDataplaneEnabled !== nextSettings.tunDataplaneEnabled) {
      void refreshTunEnvironment(true);
    }
    return createSnapshot(nextStore);
  });
  handleTrustedIpc(IPC_CHANNELS.updateRoutingMode, async (_event, mode: RoutingMode) => {
    await saveRoutingChange("The routing mode change wasn’t saved", () => storage.updateRoutingMode(mode));
    return applyRoutingAfterSave();
  });
  handleTrustedIpc(IPC_CHANNELS.updateRoutingRules, async (_event, rules: RoutingRule[]) => {
    await saveRoutingChange("Routing rules weren’t saved", () => storage.updateRoutingRules(rules));
    return applyRoutingAfterSave();
  });
  handleTrustedIpc(IPC_CHANNELS.updateRoutingProxyListEnabled, async (_event, enabled: boolean) => {
    await saveRoutingChange(`Couldn’t turn ${enabled ? "on" : "off"} Blocked in Russia`, async () => {
      const current = storage.getStore().routingProxyList;
      if (enabled && current.domains.length === 0) {
        await refreshRoutingProxyList({ enabled: true });
      } else {
        await storage.updateRoutingProxyList({ ...current, enabled });
      }
    });
    return applyRoutingAfterSave();
  });
  handleTrustedIpc(IPC_CHANNELS.refreshRoutingProxyList, async () => {
    await saveRoutingChange("Blocked in Russia wasn’t refreshed", () => refreshRoutingProxyList());
    return applyRoutingAfterSave();
  });
  handleTrustedIpc(IPC_CHANNELS.updateRoutingDirectListEnabled, async (_event, enabled: boolean) => {
    await saveRoutingChange(`Couldn’t turn ${enabled ? "on" : "off"} Russian services`, async () => {
      const current = storage.getStore().routingDirectList;
      if (enabled && current.domains.length === 0) {
        await refreshRoutingDirectList({ enabled: true });
      } else {
        await storage.updateRoutingDirectList({ ...current, enabled });
      }
    });
    return applyRoutingAfterSave();
  });
  handleTrustedIpc(IPC_CHANNELS.refreshRoutingDirectList, async () => {
    await saveRoutingChange("Russian services wasn’t refreshed", () => refreshRoutingDirectList());
    return applyRoutingAfterSave();
  });
  handleTrustedIpc(IPC_CHANNELS.clearDiagnostics, () => {
    diagnostics = [];
    // Clearing Activity also clears what it was asked to keep.
    if (attention.dismiss()) {
      broadcastAttention();
    }
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.readLogFile, () => readMainLogContent());
  handleTrustedIpc(IPC_CHANNELS.getLogFileInfo, () => mainLogger.describeFiles());
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
  handleTrustedIpc(IPC_CHANNELS.dismissConnectionError, async () => {
    await enqueueTransportMutation(async () => {
      const target = activeTunnelService();
      if (target.getStatus().state === "Error") {
        await target.clearError?.();
      }
    });
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.checkTunnel, async (_event, endpoint?: string) => {
    await runTunnelCheck(typeof endpoint === "string" && endpoint.trim() ? endpoint.trim() : undefined);
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
    let update: AppUpdateInfo;
    try {
      update = await portableUpdates.check({
        currentVersion: app.getVersion(),
        platformTarget,
        storage,
        force: Boolean(force)
      });
    } catch (error) {
      appendDiagnostic("warning", `Update check failed: ${errorMessage(error)}`, "update");
      throw error;
    }
    if (update.available && update.latestVersion && update.latestVersion !== lastAnnouncedUpdateVersion) {
      lastAnnouncedUpdateVersion = update.latestVersion;
      appendInfo(`Update ${update.latestVersion} is available for ${platformDisplayName()} ${appEnvironment.arch}.`, "update");
    }
    return { snapshot: createSnapshot(), update };
  });
  handleTrustedIpc(IPC_CHANNELS.downloadUpdate, async () => {
    await portableUpdates.downloadSelected();
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.revealDownloadedUpdate, () => revealDownloadedUpdate());
  handleTrustedIpc(IPC_CHANNELS.copyText, (_event, text: string) => {
    if (typeof text !== "string") {
      throw new Error("Clipboard payload is invalid.");
    }
    if (text.length > MAX_CLIPBOARD_TEXT_CHARACTERS) {
      throw new Error("The text is over the 2,097,152-character clipboard limit. Copy a shorter part instead.");
    }
    clipboard.writeText(text);
    return true;
  });
  handleTrustedIpc(IPC_CHANNELS.readClipboardText, () => {
    const text = clipboard.readText();
    if (text.length > MAX_CLIPBOARD_TEXT_CHARACTERS) {
      throw new Error("The clipboard holds more than 2,097,152 characters, so nothing was pasted. Copy a shorter part instead.");
    }
    return text;
  });
  handleTrustedIpc(IPC_CHANNELS.openExternal, async (_event, url: string) => {
    await shell.openExternal(assertAllowedExternalUrl(url));
    return true;
  });
  handleTrustedIpc(IPC_CHANNELS.dismissAttention, (_event, id: unknown) => {
    if (id !== undefined && id !== null && typeof id !== "string") {
      throw new Error("Attention id is invalid.");
    }
    if (attention.dismiss(typeof id === "string" ? id : undefined)) {
      broadcastAttention();
    }
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.openLogFolder, async () => {
    await openFolder(dataLayout.logDirectory, "log folder");
    return true;
  });
  handleTrustedIpc(IPC_CHANNELS.openDataFolder, async () => {
    if (storageHealth.state === "unreadable") {
      // Point straight at the file that could not be read.
      shell.showItemInFolder(storageHealth.storePath);
      return true;
    }
    await openFolder(dataLayout.dataDirectory, "data folder");
    return true;
  });
  handleTrustedIpc(IPC_CHANNELS.recoverStorage, async (_event, action: string) => {
    if (action !== "start-fresh") {
      throw new Error("Unknown recovery action.");
    }
    await recoverStorageStartFresh();
    return createSnapshot();
  });
  handleTrustedIpc(IPC_CHANNELS.quitApp, () => {
    quitApplication();
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
    const result = listener(event, ...(args as TArgs));
    // Any request may change what the tray shows (selection, settings, state).
    void Promise.resolve(result).then(scheduleTrayRefresh, scheduleTrayRefresh);
    return result;
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
      processRoutingRefreshIntervalMs: currentProcessRoutingRefreshIntervalMs,
      // The bundled native binary is used purely as a read-only helper for
      // per-connection process attribution; it never carries tunnel traffic.
      nativeServiceExecutablePath: nativeBinaryAvailable
        ? resolveNativeServicePath(projectRoot, platformTarget)
        : undefined,
      userDataDirectory: explicitUserDataPath
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
      message,
      source: "app"
    }
  };
}

function connectTransport(kind: GlobalTab, options: ConnectOptions = {}): Promise<boolean> {
  return kind === "xray" ? connectProxy(options) : connect(options);
}

async function connect(options: ConnectOptions = {}): Promise<boolean> {
  const store = storage.getStore();
  const config = store.sshConfigs.find((candidate) => candidate.id === store.selectedConfigId);
  if (!config) {
    appendError("Select or create an SSH configuration before connecting.", "ssh");
    return false;
  }

  if (store.routingMode === "selected-rules" && !hasSelectedRoutingTargets(store)) {
    appendError("Selected rules mode requires at least one enabled routing rule or enabled proxy-list domain.", "routing");
    return false;
  }

  const request = {
    config,
    routingMode: store.routingMode,
    routingRules: store.routingRules,
    routingProxyDomains: activeRoutingProxyDomains(),
    routingDirectDomains: activeRoutingDirectDomains(),
    checkEndpoint: store.settings.checkEndpoint,
    tunDataplaneEnabled: store.settings.tunDataplaneEnabled,
    secrets: storage.resolveServiceSecrets(config)
  };
  return requestTransportIntent(async (generation) => {
    beginSession(request.tunDataplaneEnabled);
    if (activeTransport === "xray") {
      await xrayService.disconnect();
    } else if (options.restart && service.getStatus().state !== "Disconnected") {
      await service.disconnect();
    }
    if (!transportMutations.isCurrent(generation)) {
      return;
    }
    setActiveTransport("ssh");
    await service.connect(request);
    if (!transportMutations.isCurrent(generation)) {
      await service.disconnect();
      return;
    }
    await rememberLastConnectedTransport("ssh");
  }, options.expectedGeneration);
}

async function connectProxy(options: ConnectOptions = {}): Promise<boolean> {
  const store = storage.getStore();
  const profile = store.proxyProfiles.find((candidate) => candidate.id === store.selectedProxyProfileId);
  if (!profile) {
    appendError("Select or import an Xray profile before connecting.", "xray");
    return false;
  }

  if (store.routingMode === "selected-rules" && !hasSelectedRoutingTargets(store)) {
    appendError("Selected rules mode requires at least one enabled routing rule or enabled proxy-list domain.", "routing");
    return false;
  }

  const request = {
    profile,
    routingMode: store.routingMode,
    routingRules: store.routingRules,
    routingProxyDomains: activeRoutingProxyDomains(),
    routingDirectDomains: activeRoutingDirectDomains(),
    checkEndpoint: store.settings.checkEndpoint,
    tunDataplaneEnabled: store.settings.tunDataplaneEnabled,
    secrets: storage.resolveProxySecrets(profile)
  };
  return requestTransportIntent(async (generation) => {
    beginSession(request.tunDataplaneEnabled);
    if (activeTransport === "ssh") {
      await service.disconnect();
    } else if (options.restart && xrayService.getStatus().state !== "Disconnected") {
      await xrayService.disconnect();
    }
    if (!transportMutations.isCurrent(generation)) {
      return;
    }
    setActiveTransport("xray");
    // A rename saved while this connect waited its turn names the session (and its restarts) too.
    const name = storage.getStore().proxyProfiles.find((candidate) => candidate.id === profile.id)?.name;
    await xrayService.connect(name && name !== profile.name ? { ...request, profile: { ...profile, name } } : request);
    if (!transportMutations.isCurrent(generation)) {
      await xrayService.disconnect();
      return;
    }
    await rememberLastConnectedTransport("xray");
  }, options.expectedGeneration);
}

/** A user or auto Connect starts a new session story: fresh logs, no stale check. */
function beginSession(tunDataplaneEnabled: boolean): void {
  diagnostics = [];
  terminalOutputBatcher.clear();
  terminal = [];
  lastTunnelCheck = undefined;
  tunnelCheckSessions.reset();
  tunnelTransitions.reset();
  cancelTransitionSettle();
  desktopNotifier.withdrawTunnelLost();
  sessionTunSetting = tunDataplaneEnabled;
  void refreshTunEnvironment(true);
}

function setActiveTransport(next: GlobalTab): void {
  if (activeTransport === next) {
    return;
  }
  activeTransport = next;
  runtime = activeTunnelService().getStatus();
  broadcast({ type: "active-transport-changed", transport: next, status: runtime });
  scheduleTrayRefresh();
}

/** Picks a server or profile from the tray and connects it, closing whatever runs now. */
async function switchTunnelTarget(kind: GlobalTab, id: string): Promise<void> {
  const status = activeTunnelService().getStatus();
  if (activeTransport === kind && status.activeConfigId === id && isLiveSessionState(status.state)) {
    return;
  }
  if (kind === "xray") {
    await storage.selectProxyProfile(id);
  } else {
    await storage.selectConfig(id);
  }
  broadcastSnapshotInvalidated("tray-select");
  await connectTransport(kind, { restart: true });
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
  let targetName: string | undefined;
  let secretKind: "password" | "key" | undefined;
  try {
    if (store.routingMode === "selected-rules" && !hasSelectedRoutingTargets(store)) {
      await writeMainLog("Auto-connect skipped: selected rules mode has no enabled routing rules or enabled proxy-list domains.");
      recordAttention(autoConnectSkippedAttention("no-targets"));
      return;
    }

    if (transport === "xray") {
      const profile = store.proxyProfiles.find((candidate) => candidate.id === store.selectedProxyProfileId);
      if (!profile) {
        await writeMainLog("Auto-connect skipped: no selected Xray profile.");
        if (store.proxyProfiles.length > 0) {
          recordAttention(autoConnectSkippedAttention("no-profile"));
        }
        return;
      }
      targetName = profile.name;
      announceAutoConnect("xray", profile.name);
      await writeMainLog(`Auto-connect starting Xray profile "${profile.name}".`);
      const connected = await connectProxy({ expectedGeneration: 0 });
      if (!connected) {
        await writeMainLog("Auto-connect skipped because a newer user transport action superseded it.");
        return;
      }
      reportAutoConnectOutcome("xray", profile.name);
      await writeMainLog(`Auto-connect completed with Xray profile "${profile.name}".`);
      return;
    }

    const config = store.sshConfigs.find((candidate) => candidate.id === store.selectedConfigId);
    if (!config) {
      await writeMainLog("Auto-connect skipped: no selected SSH configuration.");
      if (store.sshConfigs.length > 0) {
        recordAttention(autoConnectSkippedAttention("no-server"));
      }
      return;
    }
    targetName = config.name;
    secretKind = config.authType === "password" ? "password" : "key";
    announceAutoConnect("ssh", config.name);
    await writeMainLog(`Auto-connect starting SSH configuration "${config.name}".`);
    const connected = await connect({ expectedGeneration: 0 });
    if (!connected) {
      await writeMainLog("Auto-connect skipped because a newer user transport action superseded it.");
      return;
    }
    reportAutoConnectOutcome("ssh", config.name);
    await writeMainLog(`Auto-connect completed with SSH configuration "${config.name}".`);
  } catch (error) {
    const message = `Auto-connect failed: ${formatError(error)}`;
    appendError(message);
    await writeMainLog(message);
    if (targetName) {
      recordAttention(
        autoConnectFailedAttention({ transport, targetName, reason: errorMessage(error), secretKind, platform: process.platform })
      );
    }
  } finally {
    // Auto-connect changed the remembered transport and the tab to show.
    broadcastSnapshotInvalidated("auto-connect");
  }
}

/** Open windows show "Connecting automatically" once (the snapshot carries it for windows that load later). */
function announceAutoConnect(transport: GlobalTab, targetName: string): void {
  autoConnectNotice = { at: new Date().toISOString(), transport, targetName };
  broadcastSnapshotInvalidated("auto-connect-started");
}

/** A failed first attempt does not throw; it leaves the transport in Error. */
function reportAutoConnectOutcome(transport: GlobalTab, targetName: string): void {
  const status = serviceFor(transport).getStatus();
  if (activeTransport !== transport || status.state !== "Error") {
    return;
  }
  recordAttention(
    autoConnectFailedAttention({ transport, targetName, reason: status.message, platform: process.platform })
  );
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

/**
 * "Stop reconnecting" on a desktop notification. The notifier only runs it
 * for the drop that is still being retried; this also checks the session
 * itself, so a late click never ends a tunnel that came back on its own.
 */
async function stopReconnectingFromNotification(): Promise<void> {
  const state = activeTunnelService().getStatus().state;
  if (!tunnelTransitions.isRecovering || state === "Connected" || state === "Disconnected" || state === "Disconnecting") {
    await writeMainLog(`Ignored Stop reconnecting from a notification: the tunnel is ${state}.`);
    return;
  }
  await disconnectActiveTransport();
}

async function disconnectActiveTransportInternal(): Promise<void> {
  if (activeTransport === "xray") {
    await xrayService.disconnect();
  } else {
    await service.disconnect();
  }
}

/**
 * Runs the save half of a routing change. A failure still throws to the
 * renderer, and is also written to Activity so "Not saved" can point there.
 */
async function saveRoutingChange(failureLabel: string, save: () => Promise<unknown>): Promise<void> {
  try {
    await save();
  } catch (error) {
    const message = `${failureLabel}: ${errorMessage(error)}`;
    appendError(message, "routing");
    void writeMainLog(`ERROR ${message}`);
    throw error;
  }
}

/**
 * Routing changes are saved before they are applied. A failure to apply them
 * to the running tunnel is reported as `applyError`, not thrown, so the
 * renderer can say "Saved · not applied" and offer a retry.
 */
async function applyRoutingAfterSave(): Promise<RoutingMutationResult> {
  try {
    await applyRoutingConfigurationAfterMutation();
    return { snapshot: createSnapshot() };
  } catch (error) {
    const applyError = errorMessage(error);
    appendDiagnostic("warning", `Routing change saved but not applied: ${applyError}`, "routing");
    return { snapshot: createSnapshot(), applyError };
  }
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
      const targetName = sessionName(activeTransport);
      await disconnectActiveTransportInternal();
      appendError(
        "Selected-rules routing no longer has any enabled rules or enabled proxy-list domains. The active tunnel was disconnected to prevent unintended DIRECT-all routing.",
        "routing"
      );
      recordAttention(splitTunnelNoTargetsAttention(targetName));
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
      checkEndpoint: store.settings.checkEndpoint,
      tunDataplaneEnabled: store.settings.tunDataplaneEnabled
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
  appendInfo(`Routing proxy list refreshed: ${domains.length} domains from ${sourceUrl}.`, "routing");
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
  appendInfo(`Routing direct list refreshed: ${domains.length} domains from ${sourceUrl}.`, "routing");
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
  return serviceFor(activeTransport);
}

function serviceFor(transport: GlobalTab): ServiceBridge | XrayServiceBridge {
  return transport === "xray" ? xrayService : service;
}

/** Display name of the server or profile a transport runs, surviving renames and deletes. */
function sessionName(transport: GlobalTab, status: RuntimeStatus = serviceFor(transport).getStatus()): string | undefined {
  if (status.activeConfigName) {
    return status.activeConfigName;
  }
  const id = status.activeConfigId;
  if (!id) {
    return undefined;
  }
  const store = storage.getStore();
  return transport === "xray"
    ? store.proxyProfiles.find((profile) => profile.id === id)?.name
    : store.sshConfigs.find((config) => config.id === id)?.name;
}

async function runTunnelCheck(endpoint?: string): Promise<void> {
  await performTunnelCheck(activeTransport, endpoint ?? storage.getSettings().checkEndpoint);
}

/**
 * Runs a check on the session that is active now and publishes its result,
 * unless that session ended first: a probe cut off by a disconnect or a
 * server switch would otherwise come back as the next session's "Failed".
 */
async function performTunnelCheck(transport: GlobalTab, endpoint: string): Promise<void> {
  const ticket = tunnelCheckSessions.begin(transport, sessionName(transport));
  await trackTunnelCheck(async () => {
    const result = await serviceFor(transport).checkTunnel(endpoint);
    if (!tunnelCheckSessions.accepts(ticket, activeTransport, serviceFor(transport).getStatus().state)) {
      void writeMainLog(`Dropped a ${transport} tunnel check result for ${result.endpoint}: the session it checked is no longer running.`);
      return;
    }
    // Same session (accepts), so its current name: a rename during the probe shows at once.
    lastTunnelCheck = stampTunnelCheck(transport, result, sessionName(transport) ?? ticket.targetName);
    broadcast({ type: "tunnel-check-result", result: lastTunnelCheck });
    scheduleTrayRefresh();
  });
}

/** Counts a running check so the tray and every window can show "Checking…", whoever started it. */
async function trackTunnelCheck<T>(operation: () => Promise<T>): Promise<T> {
  tunnelChecksInFlight += 1;
  if (tunnelChecksInFlight === 1) {
    broadcast({ type: "tunnel-check-changed", running: true });
  }
  scheduleTrayRefresh();
  try {
    return await operation();
  } finally {
    tunnelChecksInFlight -= 1;
    if (tunnelChecksInFlight === 0) {
      broadcast({ type: "tunnel-check-changed", running: false });
    }
    scheduleTrayRefresh();
  }
}

/** One result serves both transports, so it names the tunnel it checked. */
function stampTunnelCheck(transport: GlobalTab, result: TunnelCheckResult, checkedName?: string): TunnelCheckResult {
  const targetName = result.targetName ?? checkedName;
  return {
    ...result,
    transport: result.transport ?? transport,
    ...(targetName ? { targetName } : {})
  };
}

function createSnapshot(store: AppStore = storage.getStore()): AppSnapshot {
  runtime = activeTunnelService().getStatus();
  return {
    store,
    runtime,
    activeTransport,
    // Electron serializes the IPC result with structured clone. A shallow
    // array copy protects main-process ownership without needlessly cloning
    // the same large strings twice.
    diagnostics: diagnostics.slice(),
    attention: attention.list(),
    logFilePaths: uniqueLogPaths(),
    terminal: terminal.slice(),
    lastTunnelCheck,
    tunnelCheckRunning: tunnelChecksInFlight > 0,
    ...(startupFailure ? { startupFailure } : {}),
    ...(autoConnectNotice ? { autoConnect: autoConnectNotice } : {}),
    updateInfo: portableUpdates.info,
    updateDownload: portableUpdates.download,
    storageHealth: { ...storageHealth },
    tunStatus: currentTunStatus(runtime, store.settings),
    environment: appEnvironment
  };
}

function currentTunStatus(status: RuntimeStatus, settings: AppSettings): TunStatus {
  return deriveTunStatus({
    environment: tunEnvironment,
    platform: process.platform,
    enabled: settings.tunDataplaneEnabled,
    sessionState: status.state,
    tunActive: status.tunActive === true,
    sessionTunSetting
  });
}

/** Re-reads the TUN prerequisites; a change makes open windows reload their snapshot. */
function refreshTunEnvironment(force = false): Promise<void> {
  if (tunEnvironmentRefresh) {
    return tunEnvironmentRefresh;
  }
  if (!force && tunEnvironment && Date.now() - tunEnvironmentCheckedAt < TUN_ENVIRONMENT_REFRESH_INTERVAL_MS) {
    return Promise.resolve();
  }
  const refresh = detectTunEnvironment({
    platform: process.platform,
    appDirectory: path.dirname(process.execPath),
    dataDirectory: explicitUserDataPath,
    resourcesPath: projectRoot
  })
    .then((next) => {
      const changed = JSON.stringify(next) !== JSON.stringify(tunEnvironment);
      tunEnvironment = next;
      tunEnvironmentCheckedAt = Date.now();
      if (changed) {
        broadcastSnapshotInvalidated("tun-environment");
      }
    })
    .catch((error: unknown) => {
      void writeMainLog(`TUN environment check failed: ${formatError(error)}`);
    })
    .finally(() => {
      tunEnvironmentRefresh = undefined;
    });
  tunEnvironmentRefresh = refresh;
  return refresh;
}

function handleServiceEvent(event: ServiceEvent): void {
  handleRuntimeEvent("ssh", event);
}

function handleXrayServiceEvent(event: ServiceEvent): void {
  handleRuntimeEvent("xray", event);
}

function handleRuntimeEvent(source: GlobalTab, event: ServiceEvent): void {
  const isActive = activeTransport === source;
  if (event.type === "status-changed") {
    if (!isActive) {
      return;
    }
    runtime = event.status;
    scheduleTunnelVerification(source, event.status);
    const checkCleared = handleActiveStatusChanged(source, event.status);
    broadcast(event);
    if (checkCleared) {
      broadcastSnapshotInvalidated("tunnel-check-cleared");
    }
    return;
  }
  if (event.type === "diagnostics-appended") {
    const entry = withDiagnosticSource(normalizeDiagnosticEntry(event.entry), source);
    if (shouldPersistDiagnostic(entry)) {
      void writeMainLog(`${entry.level.toUpperCase()} ${entry.message}`);
    }
    recordDiagnosticAttention(source, entry);
    const appended = appendDiagnosticEntry(entry);
    if (appended) {
      broadcast({ type: "diagnostics-appended", entry: appended });
    }
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
    // Every check runs through performTunnelCheck, which publishes the result
    // only if its session is still the one running.
    return;
  }
  if (event.type === "error") {
    const entry = appendError(event.message, source);
    void writeMainLog(`ERROR ${entry.message}`);
  }
}

/** Returns true when the tunnel check result was dropped, so windows must reload it. */
function handleActiveStatusChanged(source: GlobalTab, status: RuntimeStatus): boolean {
  tunnelCheckSessions.observe(source, status);
  let checkCleared = false;
  // A result describes a running tunnel; it must not outlive it.
  if (lastTunnelCheck && status.state !== "Connected" && status.state !== "Reconnecting") {
    lastTunnelCheck = undefined;
    checkCleared = true;
  }
  for (const transition of tunnelTransitions.observe(status.state, status.message)) {
    announceTunnelTransition(source, transition, status);
  }
  if (!tunnelTransitions.isRecovering) {
    // The drop is over (back, given up, disconnected): its "Stop reconnecting" must go too.
    desktopNotifier.withdrawTunnelLost();
  }
  if (tunnelTransitions.hasPendingStop) {
    scheduleTransitionSettle(source);
  } else {
    cancelTransitionSettle();
  }
  scheduleTrayRefresh();
  return checkCleared;
}

function announceTunnelTransition(source: GlobalTab, transition: TunnelTransition, status: RuntimeStatus): void {
  const notifier = desktopNotifier;
  const name = sessionName(source, status) ?? (source === "xray" ? "Xray" : "SSH");
  try {
    if (transition.kind === "lost") {
      notifier.notifyTunnelLost(name);
    } else if (transition.kind === "restored") {
      notifier.notifyTunnelRestored(name);
    } else {
      notifier.notifyReconnectStopped(name, transition.reason);
    }
  } catch (error) {
    void writeMainLog(`Desktop notification failed: ${formatError(error)}`);
  }
}

function scheduleTransitionSettle(source: GlobalTab): void {
  if (transitionSettleTimer) {
    return;
  }
  transitionSettleTimer = setTimeout(() => {
    transitionSettleTimer = undefined;
    if (activeTransport !== source) {
      return;
    }
    const status = serviceFor(source).getStatus();
    for (const transition of tunnelTransitions.settle()) {
      announceTunnelTransition(source, transition, status);
    }
    if (!tunnelTransitions.isRecovering) {
      desktopNotifier.withdrawTunnelLost();
    }
  }, ERROR_SETTLE_DELAY_MS);
  transitionSettleTimer.unref();
}

function cancelTransitionSettle(): void {
  clearTimer(transitionSettleTimer);
  transitionSettleTimer = undefined;
}

function recordDiagnosticAttention(source: GlobalTab, entry: DiagnosticsEntry): void {
  const input = attentionFromDiagnostic(entry, source, () => ({
    targetName: sessionName(source),
    statusMessage: serviceFor(source).getStatus().message,
    tun: tunEnvironment,
    launchedAtSignIn: startMinimizedToTray
  }));
  if (input) {
    recordAttention(input);
  }
}

function recordAttention(input: AttentionInput): void {
  const event = attention.add(input);
  void writeMainLog(`ATTENTION ${event.kind}: ${event.title}`);
  broadcastAttention();
}

function broadcastAttention(): void {
  broadcast({ type: "attention-changed", attention: attention.list() });
}

function broadcastSnapshotInvalidated(reason: string): void {
  broadcast({ type: "snapshot-invalidated", reason });
}

/** Runs work the renderer did not ask for (tray, notifications) and tells windows to reload. */
function runBackgroundAction(label: string, operation: () => Promise<unknown>): void {
  void operation()
    .catch((error: unknown) => {
      const message = `${capitalize(label)} failed: ${errorMessage(error)}`;
      appendError(message);
      void writeMainLog(message);
    })
    .finally(() => {
      broadcastSnapshotInvalidated(label.replaceAll(" ", "-"));
      scheduleTrayRefresh();
    });
}

function scheduleTrayRefresh(): void {
  if (trayRefreshTimer || applicationQuitting) {
    return;
  }
  trayRefreshTimer = setTimeout(() => {
    trayRefreshTimer = undefined;
    refreshTray();
  }, TRAY_REFRESH_DELAY_MS);
  trayRefreshTimer.unref();
}

function refreshTray(): void {
  if (applicationQuitting) {
    return;
  }
  try {
    trayController.update(
      buildTrayMenuModel({
        appName: appDisplayName,
        platform: process.platform,
        activeTransport,
        runtime: activeTunnelService().getStatus(),
        store: storage.getStore(),
        lastTunnelCheck,
        checkInProgress: tunnelChecksInFlight > 0,
        storageReadable: storageHealth.state === "ok"
      })
    );
  } catch (error) {
    void writeMainLog(`Tray update failed: ${formatError(error)}`);
  }
}

function describeTunnelForCrashPage(): CrashPageTunnel {
  const status = activeTunnelService().getStatus();
  const name = sessionName(activeTransport, status);
  const route = `${activeTransport === "xray" ? "Xray" : "SSH"}${name ? ` · ${name}` : ""}`;
  if (status.state === "Connected") {
    return { tone: "on", text: `Tunnel still on · ${route}` };
  }
  if (status.state === "Reconnecting") {
    return { tone: "busy", text: `Tunnel reconnecting · ${route}` };
  }
  if (status.state === "Connecting") {
    return { tone: "busy", text: `Tunnel connecting · ${route}` };
  }
  return { tone: "off", text: "Tunnel is off" };
}

function handleUpdateDownloadChanged(download: AppUpdateDownload): void {
  const previous = previousUpdateDownloadState;
  previousUpdateDownloadState = download.state;
  if (download.state === "downloaded" && previous !== "downloaded") {
    const version = portableUpdates.info?.asset?.version ?? portableUpdates.info?.latestVersion ?? "";
    const fileName = download.filePath ? path.basename(download.filePath) : undefined;
    appendInfo(`Update ${version} downloaded${fileName ? `: ${fileName}` : ""}.`, "update");
    try {
      desktopNotifier.notifyUpdateDownloaded(version, { fileName, sizeBytes: download.totalBytes });
    } catch (error) {
      void writeMainLog(`Desktop notification failed: ${formatError(error)}`);
    }
  } else if (download.state === "error" && previous !== "error") {
    appendDiagnostic("error", `Update download failed: ${download.message ?? "unknown error"}`, "update");
  }
}

function revealDownloadedUpdate(): boolean {
  const filePath = portableUpdates.download.filePath;
  if (!filePath) {
    return false;
  }
  shell.showItemInFolder(filePath);
  return true;
}

async function openFolder(directory: string, label: string): Promise<void> {
  await mkdir(directory, { recursive: true });
  const failure = await shell.openPath(directory);
  if (failure) {
    throw new Error(`Couldn’t open the ${label}: ${failure}`);
  }
}

/**
 * How long a freshly connected transport is given before it is probed. An
 * outbound with a handshake still to finish would otherwise be called dead for
 * being slow.
 */
const TUNNEL_VERIFICATION_DELAY_MS = 1_500;

/**
 * Confirms once per connection that the tunnel actually carries data.
 *
 * A transport whose outbound is dead still accepts every connection the
 * routing rules hand it, so what the user sees - selected traffic hangs,
 * unselected traffic works - is indistinguishable from routing that stopped
 * matching. The log could not tell them apart either: in selected-rules mode
 * the transport's SOCKS inbound only relays bytes, so it never reads a
 * response and has nothing to report, and the failure passed in silence. This
 * probe is what puts the difference in writing, at the moment it matters.
 */
function scheduleTunnelVerification(source: GlobalTab, status: RuntimeStatus): void {
  if (status.state !== "Connected" || !status.connectedAt) {
    cancelTunnelVerification();
    return;
  }
  // Keyed on the moment of connection: a reconnect earns a fresh check, while
  // the several status updates one connection emits do not.
  const key = `${source}:${status.activeConfigId ?? ""}:${status.connectedAt}`;
  if (verifiedConnectionKey === key) {
    return;
  }
  cancelTunnelVerification();
  verifiedConnectionKey = key;
  tunnelVerificationTimer = setTimeout(() => {
    tunnelVerificationTimer = undefined;
    if (applicationQuitting || activeTransport !== source || verifiedConnectionKey !== key) {
      return;
    }
    // Published exactly like a manual check, and dropped the same way if the session ends first.
    void performTunnelCheck(source, storage.getSettings().checkEndpoint).catch(() => undefined);
  }, TUNNEL_VERIFICATION_DELAY_MS);
  tunnelVerificationTimer.unref();
}

function cancelTunnelVerification(): void {
  clearTimer(tunnelVerificationTimer);
  tunnelVerificationTimer = undefined;
  verifiedConnectionKey = undefined;
}

function appendDiagnostic(level: DiagnosticsEntry["level"], message: string, source: DiagnosticsSource = "app"): DiagnosticsEntry {
  const entry = normalizeDiagnosticEntry({
    id: randomUUID(),
    at: new Date().toISOString(),
    level,
    message,
    source
  });
  const appended = appendDiagnosticEntry(entry);
  if (appended) {
    broadcast({ type: "diagnostics-appended", entry: appended });
  }
  return entry;
}

function appendError(message: string, source: DiagnosticsSource = "app"): DiagnosticsEntry {
  return appendDiagnostic("error", message, source);
}

function appendInfo(message: string, source: DiagnosticsSource = "app"): void {
  const entry = appendDiagnostic("info", message, source);
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

function platformDisplayName(): string {
  return appEnvironment.platform === "windows"
    ? "Windows"
    : appEnvironment.platform === "macos"
      ? "macOS"
      : appEnvironment.platform === "linux"
        ? "Linux"
        : process.platform;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function clearTimer(timer: NodeJS.Timeout | undefined): void {
  if (timer) {
    clearTimeout(timer);
  }
}
