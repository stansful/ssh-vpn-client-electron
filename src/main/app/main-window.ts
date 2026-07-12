import { BrowserWindow } from "electron";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createErrorDataUrl, formatError, formatRuntimePath, formatRuntimeUrl, type RuntimeFormatOptions } from "./runtime-format.js";
import { RendererNavigationPolicy } from "./renderer-security.js";
import { FixedWindowRateLimiter } from "./fixed-window-rate-limiter.js";
import { createEnergyAwareWindowOptions, shouldLogRendererConsoleMessage } from "./energy-policy.js";

const MAX_RENDERER_CONSOLE_MESSAGES_PER_WINDOW = 50;
const RENDERER_CONSOLE_RATE_WINDOW_MS = 10_000;

export interface CreateMainWindowOptions extends RuntimeFormatOptions {
  appName: string;
  rendererDist: string;
  preloadPath: string;
  iconPath: string;
  width: number;
  height: number;
  startHidden: boolean;
  devServerUrl?: string;
  onCreated: (window: BrowserWindow) => void;
  onClosed: () => void;
  onClose: (event: Electron.Event, window: BrowserWindow) => void;
  appendError: (message: string) => void;
  writeLog: (message: string) => Promise<void>;
}

export async function createMainWindow(options: CreateMainWindowOptions): Promise<BrowserWindow> {
  await options.writeLog(
    `Creating window. renderer=${formatRuntimePath(options, path.join(options.rendererDist, "index.html"))}, preload=${formatRuntimePath(options, options.preloadPath)}, icon=${formatRuntimePath(options, options.iconPath)}`
  );
  const energyOptions = createEnergyAwareWindowOptions(options.startHidden);
  const window = new BrowserWindow({
    width: options.width,
    height: options.height,
    minWidth: options.width,
    minHeight: options.height,
    title: options.appName,
    icon: options.iconPath,
    autoHideMenuBar: true,
    backgroundColor: "#f6f7f9",
    show: energyOptions.show,
    paintWhenInitiallyHidden: energyOptions.paintWhenInitiallyHidden,
    webPreferences: {
      ...energyOptions.webPreferences,
      preload: options.preloadPath,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });
  // Register the WebContents before loadFile/loadURL can execute preload code
  // and issue the initial snapshot IPC request.
  options.onCreated(window);

  const rendererUrl = options.devServerUrl ?? pathToFileURL(path.join(options.rendererDist, "index.html")).href;
  const navigationPolicy = new RendererNavigationPolicy([rendererUrl]);
  const consoleMessageRateLimiter = new FixedWindowRateLimiter(
    MAX_RENDERER_CONSOLE_MESSAGES_PER_WINDOW,
    RENDERER_CONSOLE_RATE_WINDOW_MS
  );
  let blockedNavigationReported = false;
  const blockUntrustedNavigation = (event: Electron.Event, targetUrl: string): void => {
    if (navigationPolicy.permits(targetUrl)) {
      return;
    }
    event.preventDefault();
    if (!blockedNavigationReported) {
      blockedNavigationReported = true;
      void options.writeLog(`Blocked untrusted renderer navigation: ${formatRuntimeUrl(options, targetUrl)}`);
    }
  };

  let cancelRendererMountCheck: (() => void) | undefined;
  window.on("closed", () => {
    cancelRendererMountCheck?.();
    options.onClosed();
  });
  window.on("close", (event) => options.onClose(event, window));
  window.webContents.on("will-navigate", blockUntrustedNavigation);
  window.webContents.on("will-redirect", blockUntrustedNavigation);
  window.webContents.setWindowOpenHandler(({ url }) => {
    if (!blockedNavigationReported) {
      blockedNavigationReported = true;
      void options.writeLog(`Blocked renderer window-open request: ${formatRuntimeUrl(options, url)}`);
    }
    return { action: "deny" };
  });
  window.webContents.on("did-fail-load", (_event, errorCode, errorDescription, validatedURL) => {
    const message = `Renderer failed to load ${formatRuntimeUrl(options, validatedURL)}: ${errorCode} ${errorDescription}`;
    options.appendError(message);
    void options.writeLog(message);
  });
  window.webContents.on("render-process-gone", (_event, details) => {
    const message = `Renderer process gone: reason=${details.reason}, exitCode=${details.exitCode}`;
    options.appendError(message);
    void options.writeLog(message);
  });
  window.webContents.on("preload-error", (_event, failedPreloadPath, error) => {
    const message = `Preload failed ${formatRuntimePath(options, failedPreloadPath)}: ${formatError(error)}`;
    options.appendError(message);
    void options.writeLog(message);
  });
  window.webContents.on("did-finish-load", () => {
    const message = `Renderer finished load: ${formatRuntimeUrl(options, window.webContents.getURL())}`;
    void options.writeLog(message);
    cancelRendererMountCheck?.();
    cancelRendererMountCheck = scheduleRendererMountCheck(window, options);
  });
  window.webContents.on("console-message", (_event, level, message, line, sourceId) => {
    if (!shouldLogRendererConsoleMessage(options.packaged, level)) {
      return;
    }
    const decision = consoleMessageRateLimiter.take();
    if (!decision.allowed) {
      return;
    }
    if (decision.suppressedSinceLastWindow > 0) {
      void options.writeLog(`Suppressed ${decision.suppressedSinceLastWindow} renderer console messages due to rate limiting.`);
    }
    const levelName = ["debug", "info", "warning", "error"][level] ?? `level-${level}`;
    void options.writeLog(`Renderer console ${levelName}: ${message}${sourceId ? ` (${formatRuntimeUrl(options, sourceId)}:${line})` : ""}`);
  });

  if (options.devServerUrl) {
    await window.loadURL(options.devServerUrl);
    if (!options.startHidden) {
      window.webContents.openDevTools({ mode: "detach" });
    }
  } else {
    try {
      await window.loadFile(path.join(options.rendererDist, "index.html"));
    } catch (error) {
      const message = `Unable to load renderer: ${formatError(error)}`;
      options.appendError(message);
      await options.writeLog(message);
      const errorUrl = createErrorDataUrl(message);
      navigationPolicy.allow(errorUrl);
      await window.loadURL(errorUrl);
    }
  }

  if (!options.startHidden && !window.isVisible()) {
    window.show();
  }

  return window;
}

function scheduleRendererMountCheck(window: BrowserWindow, options: CreateMainWindowOptions): () => void {
  let timer: NodeJS.Timeout | undefined;
  const run = (): void => {
    timer = setTimeout(() => {
      timer = undefined;
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
              bodyTextLength: document.body ? (document.body.textContent || "").length : -1,
              preloadApiAvailable: typeof globalThis.shadowSsh?.loadSnapshot === "function",
              startupState: document.querySelector("[data-startup-state]")?.getAttribute("data-startup-state") || "missing"
            };
          })();`,
          true
        )
        .then((status: {
          url: string;
          readyState: string;
          rootChildCount: number;
          bodyTextLength: number;
          preloadApiAvailable: boolean;
          startupState: string;
        }) => {
          const message = `Renderer mount status: url=${formatRuntimeUrl(options, status.url)}, readyState=${status.readyState}, rootChildCount=${status.rootChildCount}, bodyTextLength=${status.bodyTextLength}, preloadApi=${status.preloadApiAvailable ? "available" : "missing"}, startupState=${status.startupState}`;
          void options.writeLog(message);
          if (status.rootChildCount <= 0) {
            options.appendError(`Renderer did not mount React root. ${message}`);
          } else if (!status.preloadApiAvailable) {
            options.appendError(`Renderer preload API is unavailable. ${message}`);
          }
        })
        .catch((error: unknown) => {
          void options.writeLog(`Renderer mount check failed: ${formatError(error)}`);
        });
    }, 1500);
    timer.unref();
  };

  if (window.isVisible()) {
    run();
  } else {
    window.once("show", run);
  }

  return () => {
    window.removeListener("show", run);
    if (timer) {
      clearTimeout(timer);
      timer = undefined;
    }
  };
}
