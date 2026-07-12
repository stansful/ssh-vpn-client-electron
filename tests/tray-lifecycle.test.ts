import { EventEmitter } from "node:events";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const electron = vi.hoisted(() => ({
  getAllWindows: vi.fn<() => unknown[]>(() => []),
  createFromPath: vi.fn<(iconPath: string) => Electron.NativeImage>(() => ({
    isEmpty: () => true
  }) as Electron.NativeImage),
  createEmpty: vi.fn<() => Electron.NativeImage>(() => ({} as Electron.NativeImage))
}));

vi.mock("electron", () => ({
  BrowserWindow: { getAllWindows: electron.getAllWindows },
  Menu: { buildFromTemplate: vi.fn(() => ({})) },
  nativeImage: { createFromPath: electron.createFromPath, createEmpty: electron.createEmpty },
  Tray: class {
    setToolTip(): void {}
    setContextMenu(): void {}
    on(): void {}
    destroy(): void {}
  }
}));

const { loadTrayIcon, resolveTrayIconPaths, TrayController } = await import("../src/main/app/tray.js");

afterEach(() => {
  vi.useRealTimers();
  electron.getAllWindows.mockReset();
  electron.getAllWindows.mockReturnValue([]);
  electron.createFromPath.mockReset();
  electron.createFromPath.mockReturnValue({ isEmpty: () => true } as Electron.NativeImage);
  electron.createEmpty.mockClear();
});

describe("tray window lifecycle", () => {
  it("uses a dedicated macOS template icon and preserves platform fallbacks", () => {
    const options = { packaged: true, projectRoot: "/project", resourcesPath: "/resources" };

    expect(resolveTrayIconPaths({ ...options, platform: "darwin" })).toEqual([
      path.join("/resources", "icons", "trayTemplate.png"),
      path.join("/resources", "icons", "icon.png")
    ]);
    expect(resolveTrayIconPaths({ ...options, platform: "linux" })).toEqual([
      path.join("/resources", "icons", "icon.png")
    ]);
    expect(resolveTrayIconPaths({ ...options, platform: "win32" })).toEqual([
      path.join("/resources", "icons", "icon.ico"),
      path.join("/resources", "icons", "icon.png")
    ]);
  });

  it("marks the small macOS glyph as a system-tinted template image", () => {
    const setTemplateImage = vi.fn();
    const resize = vi.fn();
    const image = {
      isEmpty: () => false,
      getSize: () => ({ width: 16, height: 16 }),
      resize,
      setTemplateImage
    } as unknown as Electron.NativeImage;
    electron.createFromPath.mockReturnValue(image);

    expect(loadTrayIcon(["/resources/icons/trayTemplate.png"], "darwin")).toBe(image);
    expect(resize).not.toHaveBeenCalled();
    expect(setTemplateImage).toHaveBeenCalledOnce();
    expect(setTemplateImage).toHaveBeenCalledWith(true);
  });

  it("defensively shrinks an ordinary macOS fallback without turning its opaque background into a template", () => {
    const resized = { setTemplateImage: vi.fn() } as unknown as Electron.NativeImage;
    const resize = vi.fn(() => resized);
    electron.createFromPath.mockReturnValue({
      isEmpty: () => false,
      getSize: () => ({ width: 256, height: 256 }),
      resize
    } as unknown as Electron.NativeImage);

    expect(loadTrayIcon(["/resources/icons/icon.png"], "darwin")).toBe(resized);
    expect(resize).toHaveBeenCalledWith({ width: 16, height: 16, quality: "best" });
    expect(resized.setTemplateImage).not.toHaveBeenCalled();
  });

  it("requests lazy window creation when a tray-only app is first opened", () => {
    const onShowRequested = vi.fn();
    const controller = createController({ onShowRequested });

    controller.showWindow();

    expect(onShowRequested).toHaveBeenCalledOnce();
    expect(controller.isCreated).toBe(false);
  });

  it("cancels renderer release when the window is reopened during the grace period", () => {
    vi.useFakeTimers();
    const window = new FakeWindow();
    electron.getAllWindows.mockReturnValue([window]);
    const controller = createController({ rendererReleaseDelayMs: 1_000 });
    controller.sync();
    const closeEvent = fakeCloseEvent();

    controller.handleWindowClose(closeEvent, window.asBrowserWindow());
    vi.advanceTimersByTime(500);
    controller.showWindow();
    vi.advanceTimersByTime(1_000);

    expect(closeEvent.preventDefault).toHaveBeenCalledOnce();
    expect(window.hide).toHaveBeenCalledOnce();
    expect(window.show).toHaveBeenCalledOnce();
    expect(window.destroy).not.toHaveBeenCalled();
  });

  it("destroys only the renderer after the tray grace period and leaves the tunnel/main state alone", () => {
    vi.useFakeTimers();
    const window = new FakeWindow();
    electron.getAllWindows.mockReturnValue([window]);
    const onQuit = vi.fn();
    const tunnel = { connected: true };
    const controller = createController({ onQuit, rendererReleaseDelayMs: 1_000 });
    controller.sync();

    controller.handleWindowClose(fakeCloseEvent(), window.asBrowserWindow());
    vi.advanceTimersByTime(1_000);

    expect(window.destroy).toHaveBeenCalledOnce();
    expect(onQuit).not.toHaveBeenCalled();
    expect(tunnel.connected).toBe(true);
  });

  it("requests a fresh renderer after the released window is opened from the tray", () => {
    vi.useFakeTimers();
    const window = new FakeWindow();
    electron.getAllWindows.mockImplementation(() => window.isDestroyed() ? [] : [window]);
    const onShowRequested = vi.fn();
    const controller = createController({ onShowRequested, rendererReleaseDelayMs: 1_000 });
    controller.sync();

    controller.handleWindowClose(fakeCloseEvent(), window.asBrowserWindow());
    vi.advanceTimersByTime(1_000);
    controller.showWindow();

    expect(window.destroy).toHaveBeenCalledOnce();
    expect(onShowRequested).toHaveBeenCalledOnce();
  });

  it("does not release a renderer while the application is quitting", () => {
    vi.useFakeTimers();
    const window = new FakeWindow();
    let quitting = false;
    const controller = createController({ isQuitting: () => quitting, rendererReleaseDelayMs: 1_000 });
    controller.sync();

    controller.handleWindowClose(fakeCloseEvent(), window.asBrowserWindow());
    quitting = true;
    controller.prepareForQuit();
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(1_000);

    expect(window.destroy).not.toHaveBeenCalled();
  });

  it("resets the grace period after a repeated close without accumulating timers", () => {
    vi.useFakeTimers();
    const window = new FakeWindow();
    const controller = createController({ rendererReleaseDelayMs: 1_000 });
    controller.sync();

    controller.handleWindowClose(fakeCloseEvent(), window.asBrowserWindow());
    vi.advanceTimersByTime(750);
    controller.handleWindowClose(fakeCloseEvent(), window.asBrowserWindow());
    vi.advanceTimersByTime(750);
    expect(window.destroy).not.toHaveBeenCalled();

    vi.advanceTimersByTime(250);
    expect(window.destroy).toHaveBeenCalledOnce();
  });

  it("cancels pending release on focus, controller destruction, or a disabled setting", () => {
    vi.useFakeTimers();
    const focusedWindow = new FakeWindow();
    const focusedController = createController({ rendererReleaseDelayMs: 1_000 });
    focusedController.sync();
    focusedController.handleWindowClose(fakeCloseEvent(), focusedWindow.asBrowserWindow());
    focusedWindow.emit("focus");
    vi.advanceTimersByTime(1_000);
    expect(focusedWindow.destroy).not.toHaveBeenCalled();

    const shutdownWindow = new FakeWindow();
    const shutdownController = createController({ rendererReleaseDelayMs: 1_000 });
    shutdownController.sync();
    shutdownController.handleWindowClose(fakeCloseEvent(), shutdownWindow.asBrowserWindow());
    shutdownController.destroy();
    vi.advanceTimersByTime(1_000);
    expect(shutdownWindow.destroy).not.toHaveBeenCalled();

    const disabledWindow = new FakeWindow();
    const disabledController = createController({ rendererReleaseEnabled: false, rendererReleaseDelayMs: 1_000 });
    disabledController.sync();
    disabledController.handleWindowClose(fakeCloseEvent(), disabledWindow.asBrowserWindow());
    vi.advanceTimersByTime(1_000);
    expect(disabledWindow.hide).toHaveBeenCalledOnce();
    expect(disabledWindow.destroy).not.toHaveBeenCalled();
  });

  it("does not hide a window when close-to-tray is disabled or tray creation failed", () => {
    const disabledWindow = new FakeWindow();
    const disabledController = createController({ closeToTrayEnabled: false });
    disabledController.sync();
    const disabledEvent = fakeCloseEvent();
    disabledController.handleWindowClose(disabledEvent, disabledWindow.asBrowserWindow());
    expect(disabledEvent.preventDefault).not.toHaveBeenCalled();
    expect(disabledWindow.hide).not.toHaveBeenCalled();

    const noTrayWindow = new FakeWindow();
    const noTrayController = createController();
    const noTrayEvent = fakeCloseEvent();
    noTrayController.handleWindowClose(noTrayEvent, noTrayWindow.asBrowserWindow());
    expect(noTrayEvent.preventDefault).not.toHaveBeenCalled();
    expect(noTrayWindow.hide).not.toHaveBeenCalled();
  });

  it("restores a hidden window before disabling the tray so a settings race cannot strand the app", () => {
    vi.useFakeTimers();
    let closeToTrayEnabled = true;
    const window = new FakeWindow();
    electron.getAllWindows.mockReturnValue([window]);
    const controller = new TrayController({
      appName: "Shadow SSH",
      iconPaths: [],
      isCloseToTrayEnabled: () => closeToTrayEnabled,
      isRendererReleaseEnabled: () => true,
      isTrayRequired: () => closeToTrayEnabled,
      isQuitting: () => false,
      onQuit: vi.fn(),
      rendererReleaseDelayMs: 1_000
    });
    controller.sync();
    controller.handleWindowClose(fakeCloseEvent(), window.asBrowserWindow());

    closeToTrayEnabled = false;
    controller.sync();
    vi.advanceTimersByTime(1_000);

    expect(controller.isCreated).toBe(false);
    expect(window.show).toHaveBeenCalledOnce();
    expect(window.focus).toHaveBeenCalledOnce();
    expect(window.destroy).not.toHaveBeenCalled();
  });
});

class FakeWindow extends EventEmitter {
  private visible = true;
  private destroyed = false;
  private minimized = false;

  readonly hide = vi.fn(() => {
    this.visible = false;
  });
  readonly show = vi.fn(() => {
    this.visible = true;
    this.emit("show");
  });
  readonly focus = vi.fn(() => {
    this.emit("focus");
  });
  readonly restore = vi.fn(() => {
    this.minimized = false;
  });
  readonly destroy = vi.fn(() => {
    this.destroyed = true;
    this.visible = false;
    this.emit("closed");
  });

  isVisible(): boolean {
    return this.visible;
  }

  isDestroyed(): boolean {
    return this.destroyed;
  }

  isMinimized(): boolean {
    return this.minimized;
  }

  asBrowserWindow(): Electron.BrowserWindow {
    return this as unknown as Electron.BrowserWindow;
  }
}

function fakeCloseEvent(): Electron.Event & { preventDefault: ReturnType<typeof vi.fn> } {
  return { preventDefault: vi.fn() } as unknown as Electron.Event & { preventDefault: ReturnType<typeof vi.fn> };
}

function createController({
  closeToTrayEnabled = true,
  rendererReleaseEnabled = true,
  isQuitting = () => false,
  onShowRequested = vi.fn(),
  onQuit = vi.fn(),
  rendererReleaseDelayMs = 30_000
}: {
  closeToTrayEnabled?: boolean;
  rendererReleaseEnabled?: boolean;
  isQuitting?: () => boolean;
  onShowRequested?: () => void;
  onQuit?: () => void;
  rendererReleaseDelayMs?: number;
} = {}): InstanceType<typeof TrayController> {
  return new TrayController({
    appName: "Shadow SSH",
    iconPaths: [],
    isCloseToTrayEnabled: () => closeToTrayEnabled,
    isRendererReleaseEnabled: () => rendererReleaseEnabled,
    isTrayRequired: () => closeToTrayEnabled,
    isQuitting,
    onShowRequested,
    onQuit,
    rendererReleaseDelayMs
  });
}
