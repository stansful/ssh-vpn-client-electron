import { app, BrowserWindow } from "electron";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const appDisplayName = process.env.SHADOW_SSH_BUILD_CHANNEL === "development" ? "Shadow SSH Dev" : "Shadow SSH";
const explicitUserDataPath = resolveUserDataPath(appDisplayName);
const persistedStorePath = path.join(explicitUserDataPath, "storage", "app-store.v1.json");
const primaryLogPath = path.join(explicitUserDataPath, "logs", "main.log");
const bootstrapLoggingEnabled = readPersistedLoggingEnabled();

registerCrashLogging();

try {
  app.setName(appDisplayName);
  ensureUserDataPath();
  writeBootstrapLog(`Bootstrap loaded. pid=${process.pid}, platform=${process.platform}, arch=${process.arch}, userData=${explicitUserDataPath}`);
} catch (error) {
  writeBootstrapLog(`Bootstrap setup failed: ${formatError(error)}`);
}

void import("./main.js").catch(async (error) => {
  const message = `Fatal main module import failure: ${formatError(error)}`;
  writeBootstrapLog(message);
  await showFatalWindow(message);
});

function registerCrashLogging(): void {
  process.on("uncaughtException", (error) => {
    writeBootstrapLog(`Uncaught exception before main recovery: ${formatError(error)}`);
  });

  process.on("unhandledRejection", (reason) => {
    writeBootstrapLog(`Unhandled rejection before main recovery: ${formatError(reason)}`);
  });
}

function ensureUserDataPath(): void {
  mkdirSync(explicitUserDataPath, { recursive: true });
  app.setPath("userData", explicitUserDataPath);
}

function writeBootstrapLog(message: string): void {
  if (!bootstrapLoggingEnabled) {
    return;
  }
  for (const logPath of uniqueLogPaths()) {
    try {
      mkdirSync(path.dirname(logPath), { recursive: true });
      appendFileSync(logPath, `[${new Date().toISOString()}] ${message}\n`, "utf8");
    } catch {
      // Bootstrap logging must never prevent Electron from continuing startup.
    }
  }
}

function uniqueLogPaths(): string[] {
  return [primaryLogPath];
}

function readPersistedLoggingEnabled(): boolean {
  try {
    const parsed = JSON.parse(readFileSync(persistedStorePath, "utf8")) as { settings?: { loggingEnabled?: unknown } };
    return parsed.settings?.loggingEnabled !== false;
  } catch {
    return true;
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

async function showFatalWindow(message: string): Promise<void> {
  try {
    await app.whenReady();
    const window = new BrowserWindow({
      width: 920,
      height: 560,
      minWidth: 720,
      minHeight: 420,
      title: `${appDisplayName} startup error`,
      backgroundColor: "#f6f7f9",
      webPreferences: {
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true
      }
    });
    await window.loadURL(createErrorDataUrl(message));
  } catch (error) {
    writeBootstrapLog(`Unable to show fatal startup window: ${formatError(error)}`);
    app.exit(1);
  }
}

function createErrorDataUrl(message: string): string {
  const html = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>${escapeHtml(appDisplayName)} startup error</title>
    <style>
      body { margin: 0; font: 14px system-ui, sans-serif; color: #20242a; background: #f6f7f9; }
      main { padding: 32px; max-width: 900px; }
      h1 { margin: 0 0 12px; font-size: 24px; }
      p { line-height: 1.45; }
      pre { white-space: pre-wrap; background: #fff; border: 1px solid #d6dae0; padding: 16px; border-radius: 8px; }
    </style>
  </head>
  <body>
    <main>
      <h1>${escapeHtml(appDisplayName)} could not start</h1>
      <p>Main-process startup failed before the application UI could load.</p>
      <pre>${escapeHtml(message)}</pre>
      <p>Logs are written to:</p>
      <pre>${escapeHtml(uniqueLogPaths().join("\n"))}</pre>
    </main>
  </body>
</html>`;
  return `data:text/html;charset=utf-8,${encodeURIComponent(html)}`;
}

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return `${error.message}${error.stack ? `\n${error.stack}` : ""}`;
  }
  return String(error);
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}
