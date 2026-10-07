import { BrowserWindow, nativeTheme } from "electron";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createErrorDataUrl, formatError, formatRuntimePath, formatRuntimeUrl, type RuntimeFormatOptions } from "./runtime-format.js";
import { RendererNavigationPolicy } from "./renderer-security.js";
import { FixedWindowRateLimiter } from "./fixed-window-rate-limiter.js";
import { createEnergyAwareWindowOptions, shouldLogRendererConsoleMessage } from "./energy-policy.js";

const MAX_RENDERER_CONSOLE_MESSAGES_PER_WINDOW = 50;
const RENDERER_CONSOLE_RATE_WINDOW_MS = 10_000;
/** A second renderer crash this soon after an automatic reload shows the crash page instead. */
export const RENDERER_CRASH_RELOAD_WINDOW_MS = 60_000;
export const CRASH_PAGE_RELOAD_URL = "shadow-ssh://reload";
export const CRASH_PAGE_OPEN_LOGS_URL = "shadow-ssh://open-logs";

export interface WindowSize {
  width: number;
  height: number;
}

/** What the crash page says about the tunnel, which keeps running in the main process. */
export interface CrashPageTunnel {
  tone: "on" | "busy" | "off";
  /** For example "Tunnel still on · SSH · Frankfurt-01". */
  text: string;
}

export interface CreateMainWindowOptions extends RuntimeFormatOptions {
  appName: string;
  rendererDist: string;
  preloadPath: string;
  iconPath: string;
  width: number;
  height: number;
  minWidth: number;
  minHeight: number;
  backgroundColor?: string;
  startHidden: boolean;
  devServerUrl?: string;
  onCreated: (window: BrowserWindow) => void;
  onClosed: () => void;
  onClose: (event: Electron.Event, window: BrowserWindow) => void;
  appendError: (message: string) => void;
  writeLog: (message: string) => Promise<void>;
  /** Tunnel line for the crash page. */
  describeTunnel?: () => CrashPageTunnel;
  /** "Open log folder" on the crash page. */
  onOpenLogFolder?: () => void;
  isQuitting?: () => boolean;
}

export async function createMainWindow(options: CreateMainWindowOptions): Promise<BrowserWindow> {
  await options.writeLog(
    `Creating window. renderer=${formatRuntimePath(options, path.join(options.rendererDist, "index.html"))}, preload=${formatRuntimePath(options, options.preloadPath)}, icon=${formatRuntimePath(options, options.iconPath)}`
  );
  const energyOptions = createEnergyAwareWindowOptions(options.startHidden);
  const window = new BrowserWindow({
    width: options.width,
    height: options.height,
    minWidth: options.minWidth,
    minHeight: options.minHeight,
    title: options.appName,
    icon: options.iconPath,
    autoHideMenuBar: true,
    backgroundColor: options.backgroundColor ?? (nativeTheme.shouldUseDarkColors ? "#0A0B0D" : "#F3F3F0"),
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
  const crashPolicy = new RendererCrashPolicy();
  let crashPageShown = false;
  /** The renderer went down and nothing was loaded after it; reopening the window tries again. */
  let leftDownAfterCrash = false;
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

  const loadRenderer = async (): Promise<void> => {
    crashPageShown = false;
    leftDownAfterCrash = false;
    if (options.devServerUrl) {
      await window.loadURL(options.devServerUrl);
      return;
    }
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
  };

  const reloadRenderer = (): void => {
    if (window.isDestroyed()) {
      return;
    }
    void loadRenderer().catch((error: unknown) => {
      void options.writeLog(`Interface reload failed: ${formatError(error)}`);
    });
  };

  // The crash page is a data: URL with no script and no trusted origin, so
  // the IPC trust check rejects it; its two links are handled here instead.
  const showCrashPage = (detail: string): void => {
    if (window.isDestroyed()) {
      return;
    }
    crashPageShown = true;
    const tunnel = options.describeTunnel?.() ?? { tone: "off", text: "Tunnel is off" };
    void window.loadURL(createCrashPageDataUrl({ tunnel, detail })).catch((error: unknown) => {
      void options.writeLog(`Unable to show the crash page: ${formatError(error)}`);
    });
  };

  let cancelRendererMountCheck: (() => void) | undefined;
  window.on("closed", () => {
    cancelRendererMountCheck?.();
    options.onClosed();
  });
  window.on("close", (event) => options.onClose(event, window));
  // Opening the window again is the user asking for it, so it may retry once.
  window.on("show", () => {
    if (leftDownAfterCrash && !window.isDestroyed() && !window.webContents.isDestroyed()) {
      void options.writeLog("Reloading the interface as the window opens again after a crash.");
      reloadRenderer();
    }
  });
  window.webContents.on("will-navigate", (event, targetUrl) => {
    const action = crashPageShown ? crashPageAction(targetUrl) : undefined;
    if (action) {
      event.preventDefault();
      if (action === "reload") {
        void options.writeLog("Reloading the interface from the crash page.");
        reloadRenderer();
      } else {
        options.onOpenLogFolder?.();
      }
      return;
    }
    blockUntrustedNavigation(event, targetUrl);
  });
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
    if (details.reason === "clean-exit" || options.isQuitting?.() || window.isDestroyed() || window.webContents.isDestroyed()) {
      return;
    }
    const decision = crashPolicy.next(Date.now(), { reason: details.reason, crashPageShown });
    if (decision === "stay") {
      leftDownAfterCrash = true;
      void options.writeLog(
        crashPageShown
          ? "The crash page itself stopped; leaving the window as it is."
          : `The interface can't start (${details.reason}); leaving the window as it is instead of retrying.`
      );
      return;
    }
    // Let Electron finish tearing the dead renderer down before navigating.
    setImmediate(() => {
      if (decision === "reload") {
        void options.writeLog("Reloading the interface after a renderer crash.");
        reloadRenderer();
      } else {
        void options.writeLog("The interface crashed again within a minute; showing the crash page.");
        showCrashPage(message);
      }
    });
  });
  window.webContents.on("preload-error", (_event, failedPreloadPath, error) => {
    const message = `Preload failed ${formatRuntimePath(options, failedPreloadPath)}: ${formatError(error)}`;
    options.appendError(message);
    void options.writeLog(message);
  });
  window.webContents.on("did-finish-load", () => {
    cancelRendererMountCheck?.();
    cancelRendererMountCheck = undefined;
    if (crashPageShown) {
      void options.writeLog("Renderer finished load: crash page");
      return;
    }
    const message = `Renderer finished load: ${formatRuntimeUrl(options, window.webContents.getURL())}`;
    void options.writeLog(message);
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

  await loadRenderer();
  if (options.devServerUrl && !options.startHidden) {
    window.webContents.openDevTools({ mode: "detach" });
  }

  if (!options.startHidden && !window.isVisible()) {
    window.show();
  }

  return window;
}

/** The preferred size, shrunk to the screen's work area but never below the minimum. */
export function fitWindowSize(preferred: WindowSize, minimum: WindowSize, workArea?: WindowSize): WindowSize {
  if (!workArea || workArea.width <= 0 || workArea.height <= 0) {
    return { ...preferred };
  }
  return {
    width: Math.max(minimum.width, Math.min(preferred.width, workArea.width)),
    height: Math.max(minimum.height, Math.min(preferred.height, workArea.height))
  };
}

/** Renderer exits after which loading anything again needs a renderer that cannot start either. */
const RENDERER_START_FAILURES = new Set(["launch-failed", "integrity-failure"]);

/**
 * Reload the interface once on its own; a second crash within a minute shows
 * the crash page. Every navigation needs a new renderer, so nothing is
 * navigated automatically when the renderer cannot start at all, or when the
 * crash page itself went down - that would relaunch renderers back to back.
 */
export class RendererCrashPolicy {
  private lastAutomaticReloadAt: number | undefined;

  constructor(private readonly windowMs = RENDERER_CRASH_RELOAD_WINDOW_MS) {}

  next(now: number, crash: { reason?: string; crashPageShown?: boolean } = {}): "reload" | "crash-page" | "stay" {
    if (crash.crashPageShown || (crash.reason !== undefined && RENDERER_START_FAILURES.has(crash.reason))) {
      return "stay";
    }
    if (this.lastAutomaticReloadAt !== undefined && now - this.lastAutomaticReloadAt < this.windowMs) {
      return "crash-page";
    }
    this.lastAutomaticReloadAt = now;
    return "reload";
  }
}

/** Which crash-page link a navigation targets, if any. */
export function crashPageAction(targetUrl: string): "reload" | "open-logs" | undefined {
  let url: URL;
  try {
    url = new URL(targetUrl);
  } catch {
    return undefined;
  }
  if (url.protocol !== "shadow-ssh:" || (url.pathname !== "" && url.pathname !== "/") || url.search || url.username) {
    return undefined;
  }
  if (url.hostname === "reload") {
    return "reload";
  }
  if (url.hostname === "open-logs") {
    return "open-logs";
  }
  return undefined;
}

export function createCrashPageDataUrl(input: { tunnel: CrashPageTunnel; detail: string }): string {
  return `data:text/html;charset=utf-8,${encodeURIComponent(createCrashPageHtml(input))}`;
}

/** Night Signal crash page (System.dc.html, "Interface crash"). No script runs on it. */
export function createCrashPageHtml({ tunnel, detail }: { tunnel: CrashPageTunnel; detail: string }): string {
  const tunnelUp = tunnel.tone !== "off";
  const lead = tunnelUp
    ? "The window crashed, but your tunnel didn’t. Reload to get the controls back. Open forms and unsaved drafts will be lost."
    : "The window crashed. Reload to get the controls back. Open forms and unsaved drafts will be lost.";
  return `<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Shadow SSH</title>
<style>
:root {
  color-scheme: dark;
  --bg: #0A0B0D; --surface-2: #1A1D22; --surface-3: #22262C; --line-2: #323741;
  --text: #F3F1EC; --text-2: #A9ACB2; --text-3: #7E838B;
  --accent: #F6A019; --ink-on-accent: #1A1203;
  --ok: #34D08A; --ok-text: #5BE0A3; --ok-soft: rgba(52, 208, 138, .12); --ok-line: rgba(52, 208, 138, .36);
  --warn-text: #F7D27A; --warn-soft: rgba(243, 194, 75, .11);
  --info: #74A9FF; --info-text: #9DC2FF; --info-soft: rgba(116, 169, 255, .12); --info-line: rgba(116, 169, 255, .34);
  --focus: color-mix(in oklab, var(--accent) 70%, white);
  --ease-out: cubic-bezier(.22, 1, .36, 1);
}
* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  padding: 40px 28px 24px;
  background: radial-gradient(circle at 1px 1px, rgba(255, 255, 255, .035) 1px, transparent 0) 0 0 / 22px 22px, var(--bg);
  color: var(--text);
  font: 14px/1.5 "Onest", system-ui, -apple-system, "Segoe UI", sans-serif;
  -webkit-font-smoothing: antialiased;
  text-align: center;
}
main { display: flex; flex-direction: column; align-items: center; gap: 16px; max-width: 520px; flex: 1 1 auto; justify-content: center; }
.tile { width: 56px; height: 56px; border-radius: 17px; display: grid; place-items: center; background: var(--warn-soft); color: var(--warn-text); }
.ic { width: 18px; height: 18px; flex: 0 0 auto; fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.ic-lg { width: 22px; height: 22px; }
.ic-sm { width: 15px; height: 15px; }
.copy { display: flex; flex-direction: column; gap: 8px; align-items: center; }
h1 { margin: 0; font-family: "Unbounded", "Onest", system-ui, sans-serif; font-weight: 500; font-size: 19px; letter-spacing: -.015em; line-height: 1.25; text-wrap: balance; }
p { margin: 0; color: var(--text-2); font-size: 13.5px; max-width: 46ch; text-wrap: pretty; }
.alive { display: inline-flex; align-items: center; gap: 8px; height: 30px; padding: 0 12px; border-radius: 999px; font-size: 12.5px; font-weight: 600; background: var(--surface-2); border: 1px solid var(--line-2); color: var(--text-2); }
.alive[data-tone="on"] { background: var(--ok-soft); border-color: var(--ok-line); color: var(--ok-text); }
.alive[data-tone="busy"] { background: var(--info-soft); border-color: var(--info-line); color: var(--info-text); }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--text-3); flex: 0 0 auto; }
.alive[data-tone="on"] .dot { background: var(--ok); box-shadow: 0 0 0 3px var(--ok-soft); }
.alive[data-tone="busy"] .dot { background: var(--info); box-shadow: 0 0 0 3px var(--info-soft); }
.actions { display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; }
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 8px;
  height: 38px; padding: 0 14px; border-radius: 12px;
  border: 1px solid var(--line-2); background: var(--surface-2); color: var(--text);
  font-weight: 500; font-size: 13.5px; white-space: nowrap; text-decoration: none; cursor: pointer;
  transition: background 140ms var(--ease-out), border-color 140ms var(--ease-out), transform 140ms var(--ease-out);
}
.btn:hover { background: var(--surface-3); border-color: var(--text-3); }
.btn:active { transform: translateY(1px) scale(.99); }
.btn-primary { background: var(--accent); border-color: transparent; color: var(--ink-on-accent); font-weight: 600; box-shadow: 0 8px 22px -12px color-mix(in oklab, var(--accent) 80%, transparent); }
.btn-primary:hover { background: color-mix(in oklab, var(--accent) 88%, white); border-color: transparent; }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; border-radius: 8px; }
.btn:focus-visible { border-radius: 12px; }
footer { margin-top: 24px; font-size: 11.5px; color: var(--text-3); line-height: 1.6; overflow-wrap: anywhere; }
.mono { font-family: "JetBrains Mono", ui-monospace, "SFMono-Regular", Consolas, monospace; font-size: 11px; letter-spacing: -.01em; }
@media (prefers-reduced-motion: no-preference) {
  main { animation: rise 420ms var(--ease-out) both; }
}
@keyframes rise { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
@media (max-width: 480px) { body { padding-left: 16px; padding-right: 16px; } }
</style>
</head>
<body>
<main>
  <span class="tile" aria-hidden="true"><svg class="ic ic-lg" viewBox="0 0 24 24"><rect width="20" height="14" x="2" y="3" rx="2"></rect><path d="M8 21h8"></path><path d="M12 17v4"></path></svg></span>
  <div class="copy" role="alert">
    <h1>The interface stopped responding</h1>
    <p>${escapeHtml(lead)}</p>
  </div>
  <span class="alive" data-tone="${tunnel.tone}"><span class="dot" aria-hidden="true"></span>${escapeHtml(tunnel.text)}</span>
  <div class="actions">
    <a class="btn btn-primary" href="${CRASH_PAGE_RELOAD_URL}" autofocus><svg class="ic ic-sm" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"></path><path d="M21 3v5h-5"></path><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"></path><path d="M8 16H3v5"></path></svg>Reload interface</a>
    <a class="btn" href="${CRASH_PAGE_OPEN_LOGS_URL}"><svg class="ic ic-sm" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"></path></svg>Open log folder</a>
  </div>
</main>
<footer><span class="mono">${escapeHtml(detail)}</span></footer>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
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
