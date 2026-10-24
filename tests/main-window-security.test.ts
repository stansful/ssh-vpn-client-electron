import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const created: FakeWindow[] = [];

class FakeWebContents {
  readonly id = 41;
  readonly openDevTools = vi.fn();
  on(): this {
    return this;
  }
  setWindowOpenHandler(): void {}
  isDestroyed(): boolean {
    return false;
  }
  getURL(): string {
    return "";
  }
}

class FakeWindow {
  readonly webContents = new FakeWebContents();
  readonly loadFile = vi.fn(async () => undefined);
  readonly loadURL = vi.fn(async () => undefined);
  readonly show = vi.fn();
  constructor(readonly options: Electron.BrowserWindowConstructorOptions) {
    created.push(this);
  }
  on(): this {
    return this;
  }
  once(): this {
    return this;
  }
  removeListener(): this {
    return this;
  }
  isVisible(): boolean {
    return false;
  }
  isDestroyed(): boolean {
    return false;
  }
}

vi.mock("electron", () => ({
  BrowserWindow: FakeWindow,
  nativeTheme: { shouldUseDarkColors: true }
}));

const { createMainWindow } = await import("../src/main/app/main-window.js");

const rendererDist = path.join(path.sep, "app", "dist", "renderer");

function windowOptions(overrides: { packaged: boolean; devServerUrl?: string; startHidden?: boolean }) {
  return {
    packaged: overrides.packaged,
    resourcesPath: path.join(path.sep, "app", "resources"),
    appName: "Shadow",
    rendererDist,
    preloadPath: path.join(path.sep, "app", "dist", "preload", "preload.cjs"),
    iconPath: path.join(path.sep, "app", "icon.svg"),
    width: 1200,
    height: 800,
    minWidth: 460,
    minHeight: 600,
    startHidden: overrides.startHidden ?? false,
    devServerUrl: overrides.devServerUrl,
    onCreated: vi.fn(),
    onClosed: vi.fn(),
    onClose: vi.fn(),
    appendError: vi.fn(),
    writeLog: vi.fn(async () => undefined)
  };
}

afterEach(() => {
  created.splice(0);
});

describe("main window hardening", () => {
  it("keeps the renderer in the Chromium sandbox with an isolated, Node-free context", async () => {
    await createMainWindow(windowOptions({ packaged: true }));
    const [window] = created;
    expect(window?.options.webPreferences).toMatchObject({
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(path.sep, "app", "dist", "preload", "preload.cjs")
    });
  });

  it("loads only the bundled renderer and never opens DevTools in a packaged build", async () => {
    await createMainWindow(windowOptions({ packaged: true, devServerUrl: "http://evil.example/" }));
    const [window] = created;
    expect(window?.loadURL).not.toHaveBeenCalled();
    expect(window?.loadFile).toHaveBeenCalledWith(path.join(rendererDist, "index.html"));
    expect(window?.webContents.openDevTools).not.toHaveBeenCalled();
  });

  it("still serves npm run dev from the dev server with DevTools", async () => {
    await createMainWindow(windowOptions({ packaged: false, devServerUrl: "http://127.0.0.1:5173" }));
    const [window] = created;
    expect(window?.loadURL).toHaveBeenCalledWith("http://127.0.0.1:5173");
    expect(window?.loadFile).not.toHaveBeenCalled();
    expect(window?.webContents.openDevTools).toHaveBeenCalled();
  });

  it("opens no DevTools for a window started hidden", async () => {
    await createMainWindow(windowOptions({ packaged: false, devServerUrl: "http://127.0.0.1:5173", startHidden: true }));
    expect(created[0]?.webContents.openDevTools).not.toHaveBeenCalled();
  });
});
