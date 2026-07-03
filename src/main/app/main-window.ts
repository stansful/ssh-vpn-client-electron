import { BrowserWindow } from "electron";
import path from "node:path";
import { createErrorDataUrl, formatError, formatRuntimePath, formatRuntimeUrl, type RuntimeFormatOptions } from "./runtime-format.js";

export interface CreateMainWindowOptions extends RuntimeFormatOptions {
  appName: string;
  rendererDist: string;
  preloadPath: string;
  iconPath: string;
  width: number;
  height: number;
  devServerUrl?: string;
  onClosed: () => void;
  onClose: (event: Electron.Event, window: BrowserWindow) => void;
  appendError: (message: string) => void;
  writeLog: (message: string) => Promise<void>;
}

export async function createMainWindow(options: CreateMainWindowOptions): Promise<BrowserWindow> {
  await options.writeLog(
    `Creating window. renderer=${formatRuntimePath(options, path.join(options.rendererDist, "index.html"))}, preload=${formatRuntimePath(options, options.preloadPath)}, icon=${formatRuntimePath(options, options.iconPath)}`
  );
  const window = new BrowserWindow({
    width: options.width,
    height: options.height,
    minWidth: options.width,
    minHeight: options.height,
    title: options.appName,
    icon: options.iconPath,
    autoHideMenuBar: true,
    backgroundColor: "#f6f7f9",
    webPreferences: {
      preload: options.preloadPath,
      contextIsolation: true,
      nodeIntegration: false,
      backgroundThrottling: true,
      sandbox: false
    }
  });

  window.on("closed", options.onClosed);
  window.on("close", (event) => options.onClose(event, window));
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
    scheduleRendererMountCheck(window, options);
  });
  window.webContents.on("console-message", (_event, level, message, line, sourceId) => {
    const levelName = ["debug", "info", "warning", "error"][level] ?? `level-${level}`;
    void options.writeLog(`Renderer console ${levelName}: ${message}${sourceId ? ` (${formatRuntimeUrl(options, sourceId)}:${line})` : ""}`);
  });

  if (options.devServerUrl) {
    await window.loadURL(options.devServerUrl);
    window.webContents.openDevTools({ mode: "detach" });
  } else {
    try {
      await window.loadFile(path.join(options.rendererDist, "index.html"));
    } catch (error) {
      const message = `Unable to load renderer: ${formatError(error)}`;
      options.appendError(message);
      await options.writeLog(message);
      await window.loadURL(createErrorDataUrl(message));
    }
  }

  return window;
}

function scheduleRendererMountCheck(window: BrowserWindow, options: CreateMainWindowOptions): void {
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
        const message = `Renderer mount status: url=${formatRuntimeUrl(options, status.url)}, readyState=${status.readyState}, rootChildCount=${status.rootChildCount}, bodyTextLength=${status.bodyTextLength}`;
        void options.writeLog(message);
        if (status.rootChildCount <= 0) {
          options.appendError(`Renderer did not mount React root. ${message}`);
        }
      })
      .catch((error: unknown) => {
        void options.writeLog(`Renderer mount check failed: ${formatError(error)}`);
      });
  }, 1500);
}
