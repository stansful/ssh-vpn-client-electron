import { EventEmitter } from "node:events";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { TrayControllerOptions, TrayMenuActions, TrayMenuModel } from "../src/main/app/tray.js";

const electron = vi.hoisted(() => {
  class FakeTray {
    static instances: FakeTray[] = [];
    readonly handlers = new Map<string, () => void>();
    readonly setToolTip = vi.fn<(toolTip: string) => void>();
    readonly setContextMenu = vi.fn<(menu: { template: Electron.MenuItemConstructorOptions[] }) => void>();
    readonly setImage = vi.fn<(image: unknown) => void>();
    readonly destroy = vi.fn();

    constructor(readonly image: unknown) {
      FakeTray.instances.push(this);
    }

    on(event: string, handler: () => void): void {
      this.handlers.set(event, handler);
    }
  }
  return {
    FakeTray,
    getAllWindows: vi.fn<() => unknown[]>(() => []),
    createFromPath: vi.fn<(iconPath: string) => Electron.NativeImage>(() => ({
      isEmpty: () => true
    }) as Electron.NativeImage),
    createEmpty: vi.fn<() => Electron.NativeImage>(() => ({} as Electron.NativeImage)),
    createFromBitmap: vi.fn<(buffer: Buffer, options: { width: number; height: number }) => Electron.NativeImage>(),
    getPrimaryDisplay: vi.fn(() => ({ scaleFactor: 1 })),
    buildFromTemplate: vi.fn((template: Electron.MenuItemConstructorOptions[]) => ({ template }))
  };
});

vi.mock("electron", () => ({
  BrowserWindow: { getAllWindows: electron.getAllWindows },
  Menu: { buildFromTemplate: electron.buildFromTemplate },
  nativeImage: { createFromPath: electron.createFromPath, createEmpty: electron.createEmpty, createFromBitmap: electron.createFromBitmap },
  screen: { getPrimaryDisplay: electron.getPrimaryDisplay },
  Tray: electron.FakeTray
}));

const {
  buildTrayMenuTemplate,
  loadTrayIcon,
  resolveTrayIconPaths,
  supportsNativeMenuSublabels,
  TrayController
} = await import("../src/main/app/tray.js");

afterEach(() => {
  vi.useRealTimers();
  electron.getAllWindows.mockReset();
  electron.getAllWindows.mockReturnValue([]);
  electron.createFromPath.mockReset();
  electron.createFromPath.mockReturnValue({ isEmpty: () => true } as Electron.NativeImage);
  electron.createEmpty.mockReset();
  electron.createEmpty.mockImplementation(() => ({} as Electron.NativeImage));
  electron.createFromBitmap.mockReset();
  electron.buildFromTemplate.mockClear();
  electron.FakeTray.instances = [];
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
      appName: "Shadow",
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

  it("keeps single and double click opening the window", () => {
    const window = new FakeWindow();
    window.hide();
    electron.getAllWindows.mockReturnValue([window]);
    const controller = createController();
    controller.sync();

    lastTray().handlers.get("click")?.();
    lastTray().handlers.get("double-click")?.();

    expect(window.show).toHaveBeenCalledTimes(2);
    expect(window.focus).toHaveBeenCalledTimes(2);
  });
});

describe("tray state updates", () => {
  it("shows Open and Quit with the app name as tooltip until the first model arrives", () => {
    const onQuit = vi.fn();
    const controller = createController({ onQuit });
    controller.sync();

    expect(lastTray().setToolTip).toHaveBeenCalledWith("Shadow");
    const menu = lastMenu();
    expect(menu.map((item) => item.type === "separator" ? "---" : item.label)).toEqual(["Open Shadow", "---", "Quit"]);
    click(menuItem(menu, "Quit"));
    expect(onQuit).toHaveBeenCalledOnce();
  });

  it("applies a model that arrives before the tray exists when the tray is created", () => {
    const controller = createController({ platform: "win32" });
    controller.update(protectedModel());
    expect(electron.FakeTray.instances).toHaveLength(0);

    controller.sync();

    expect(lastTray().setToolTip).toHaveBeenCalledWith("Shadow — Protected · SSH · Frankfurt-01");
    expect(lastMenu()[0]).toMatchObject({ label: "Protected · SSH · Frankfurt-01", enabled: false });
    // The tray was created with the tone image already, so there is nothing to swap.
    expect(lastTray().setImage).not.toHaveBeenCalled();
  });

  it("rebuilds the icon only on tone changes and ignores identical models", () => {
    const controller = createController({ platform: "win32" });
    controller.sync();
    const tray = lastTray();

    controller.update(protectedModel());
    controller.update(protectedModel());
    expect(tray.setImage).toHaveBeenCalledOnce();
    expect(electron.buildFromTemplate).toHaveBeenCalledTimes(2);

    controller.update(protectedModel({ statusTitle: "Protected · SSH · Amsterdam-edge" }));
    expect(tray.setImage).toHaveBeenCalledOnce();
    expect(lastMenu()[0]?.label).toBe("Protected · SSH · Amsterdam-edge");

    controller.update(protectedModel({ tone: "busy", statusTitle: "Connecting…" }));
    expect(tray.setImage).toHaveBeenCalledTimes(2);
  });

  it("paints Windows tones on a bitmap already at the notification area's size", () => {
    const pixels = 24;
    const resize = vi.fn(() => ({ toBitmap: () => Buffer.alloc(pixels * pixels * 4, 255) }));
    electron.createFromPath.mockReturnValue({
      isEmpty: () => false,
      getSize: () => ({ width: 32, height: 32 }),
      getScaleFactors: () => [1],
      isTemplateImage: () => false,
      resize
    } as unknown as Electron.NativeImage);
    electron.createFromBitmap.mockImplementation((buffer, { width, height }) => ({
      isEmpty: () => false,
      isTemplateImage: () => false,
      getScaleFactors: () => [1],
      getSize: () => ({ width, height }),
      toBitmap: () => Buffer.from(buffer)
    }) as unknown as Electron.NativeImage);
    const representations: Array<{ width: number; height: number; scaleFactor: number }> = [];
    electron.createEmpty.mockImplementation(() => ({
      isEmpty: () => representations.length === 0,
      addRepresentation: (representation: { width: number; height: number; scaleFactor: number }) => {
        representations.push(representation);
      }
    }) as unknown as Electron.NativeImage);
    const controller = createController({ platform: "win32", iconPaths: ["/icons/icon.ico"], displayScaleFactor: () => 1.5 });
    controller.update(protectedModel());

    controller.sync();

    expect(resize).toHaveBeenCalledWith({ width: pixels, height: pixels, quality: "best" });
    expect(representations).toEqual([expect.objectContaining({ scaleFactor: 1, width: pixels, height: pixels })]);
  });

  it("reapplies the last model after the tray is destroyed and recreated", () => {
    let required = true;
    const controller = new TrayController({
      appName: "Shadow",
      iconPaths: [],
      platform: "win32",
      isCloseToTrayEnabled: () => required,
      isRendererReleaseEnabled: () => true,
      isTrayRequired: () => required,
      isQuitting: () => false,
      onQuit: vi.fn()
    });
    controller.sync();
    controller.update(protectedModel());
    required = false;
    controller.sync();
    required = true;
    controller.sync();

    expect(electron.FakeTray.instances).toHaveLength(2);
    expect(lastTray().setToolTip).toHaveBeenCalledWith("Shadow — Protected · SSH · Frankfurt-01");
  });

  it("wires menu actions to the controller callbacks", () => {
    const window = new FakeWindow();
    electron.getAllWindows.mockReturnValue([window]);
    const onDisconnect = vi.fn();
    const onRunCheck = vi.fn();
    const onSelectServer = vi.fn();
    const onQuit = vi.fn();
    const controller = createController({ platform: "win32", onDisconnect, onRunCheck, onSelectServer, onQuit });
    controller.sync();
    controller.update(protectedModel());
    const menu = lastMenu();

    click(menuItem(menu, "Disconnect"));
    click(menuItem(menu, "Run check"));
    click(menuItem(menu, "Open Shadow"));
    click(menuItem(menu, "Quit"));

    expect(onDisconnect).toHaveBeenCalledOnce();
    expect(onRunCheck).toHaveBeenCalledOnce();
    expect(window.show).toHaveBeenCalledOnce();
    expect(onQuit).toHaveBeenCalledOnce();
  });

  it("selects another server and restores the model's radio state until the caller updates", () => {
    const onSelectServer = vi.fn();
    const controller = createController({ platform: "win32", onSelectServer });
    controller.sync();
    controller.update(protectedModel());
    const builds = electron.buildFromTemplate.mock.calls.length;
    const submenu = submenuOf(menuItem(lastMenu(), "Switch server or profile"));

    click(menuItem(submenu, "de-fra-reality"));
    expect(onSelectServer).toHaveBeenCalledWith("xray", "xr");
    expect(electron.buildFromTemplate).toHaveBeenCalledTimes(builds + 1);

    click(menuItem(submenu, "Frankfurt-01"));
    expect(onSelectServer).toHaveBeenCalledOnce();
  });

  it("disables actions that have no handler instead of offering dead items", () => {
    const controller = createController({ platform: "win32" });
    controller.sync();
    controller.update(protectedModel());
    const menu = lastMenu();

    expect(menuItem(menu, "Disconnect").enabled).toBe(false);
    expect(menuItem(menu, "Run check").enabled).toBe(false);
  });

  it("reports a failed refresh instead of throwing into the status pipeline", () => {
    const onUpdateError = vi.fn();
    const controller = createController({ platform: "win32", onUpdateError });
    controller.sync();
    electron.buildFromTemplate.mockImplementationOnce(() => {
      throw new Error("menu failed");
    });

    expect(() => controller.update(protectedModel())).not.toThrow();
    expect(onUpdateError).toHaveBeenCalledWith(expect.objectContaining({ message: "menu failed" }));
  });
});

describe("tray menu template", () => {
  const windows = { appName: "Shadow", platform: "win32" as const, nativeSublabels: false };
  const mac = { appName: "Shadow", platform: "darwin" as const, nativeSublabels: true };

  it("follows the board order: header, primary, switch, check, Open, Quit", () => {
    const menu = buildTrayMenuTemplate(protectedModel(), testActions(), windows);

    expect(menu.map((item) => item.type === "separator" ? "---" : item.label)).toEqual([
      "Protected · SSH · Frankfurt-01",
      "---",
      "Disconnect",
      "Switch server or profile",
      "Run check — Passed · 184 ms",
      "---",
      "Open Shadow",
      "Quit — Disconnects the tunnel first"
    ]);
    expect(menu[0]?.enabled).toBe(false);
  });

  it("uses native sublabels where macOS draws them", () => {
    const menu = buildTrayMenuTemplate(protectedModel(), testActions(), mac);

    expect(menuItem(menu, "Run check")).toMatchObject({ label: "Run check", sublabel: "Passed · 184 ms" });
    expect(menuItem(menu, "Quit")).toMatchObject({ label: "Quit", sublabel: "Disconnects the tunnel first" });
  });

  it("lists SSH servers, then pinned Xray profiles, with the current one checked", () => {
    const submenu = submenuOf(menuItem(buildTrayMenuTemplate(protectedModel(), testActions(), windows), "Switch"));

    expect(submenu.map((item) => item.type === "separator" ? "---" : item.label)).toEqual([
      "SSH servers",
      "Frankfurt-01",
      "Lab Raspberry — No password saved",
      "---",
      "Pinned Xray profiles",
      "de-fra-reality — VLESS",
      "---",
      "Picking another one closes the current tunnel first, then connects."
    ]);
    expect(menuItem(submenu, "SSH servers").enabled).toBe(false);
    expect(menuItem(submenu, "Frankfurt-01")).toMatchObject({ type: "radio", checked: true, enabled: true });
    expect(menuItem(submenu, "Lab Raspberry")).toMatchObject({ type: "radio", checked: false, enabled: false });
  });

  it("maps each primary action and disables the busy state", () => {
    const actions = testActions();
    const primary = (model: TrayMenuModel): Electron.MenuItemConstructorOptions => {
      const item = buildTrayMenuTemplate(model, actions, windows)[2];
      if (!item) {
        throw new Error("Primary item missing.");
      }
      return item;
    };

    click(primary(protectedModel({ tone: "off", primary: { label: "Connect", action: "connect", enabled: true } })));
    click(primary(protectedModel({ tone: "attention", primary: { label: "Try again", action: "retry", enabled: true } })));
    const busy = primary(protectedModel({
      tone: "busy",
      primary: { label: "Connecting…", action: "none", enabled: false, sublabel: "Can’t be cancelled" }
    }));

    expect(actions.connect).toHaveBeenCalledOnce();
    expect(actions.retry).toHaveBeenCalledOnce();
    expect(busy).toMatchObject({ label: "Connecting… — Can’t be cancelled", enabled: false });
    expect(busy.click).toBeUndefined();
  });

  it("disables switching while connecting and when there is nothing to switch to", () => {
    const connecting = buildTrayMenuTemplate(protectedModel({ switchEnabled: false }), testActions(), windows);
    const empty = buildTrayMenuTemplate(protectedModel({ servers: [] }), testActions(), windows);

    expect(menuItem(connecting, "Switch server or profile").enabled).toBe(false);
    expect(menuItem(empty, "Switch server or profile").enabled).toBe(false);
    expect(submenuOf(menuItem(empty, "Switch server or profile"))).toEqual([
      { label: "No servers or profiles yet", enabled: false }
    ]);
  });

  it("escapes ampersands in user-named servers outside macOS", () => {
    const model = protectedModel({
      statusTitle: "Protected · SSH · R&D",
      servers: [{ kind: "ssh", id: "rd", label: "R&D", checked: true, enabled: true }]
    });

    expect(buildTrayMenuTemplate(model, testActions(), windows)[0]?.label).toBe("Protected · SSH · R&&D");
    expect(buildTrayMenuTemplate(model, testActions(), mac)[0]?.label).toBe("Protected · SSH · R&D");
  });

  it("detects native menu sublabels from macOS 14.4 on", () => {
    expect(supportsNativeMenuSublabels("darwin", "23.4.0")).toBe(true);
    expect(supportsNativeMenuSublabels("darwin", "25.0.0")).toBe(true);
    expect(supportsNativeMenuSublabels("darwin", "23.3.0")).toBe(false);
    expect(supportsNativeMenuSublabels("darwin", "22.6.0")).toBe(false);
    expect(supportsNativeMenuSublabels("win32", "10.0.26100")).toBe(false);
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
  rendererReleaseDelayMs = 30_000,
  ...extra
}: {
  closeToTrayEnabled?: boolean;
  rendererReleaseEnabled?: boolean;
  isQuitting?: () => boolean;
  onShowRequested?: () => void;
  onQuit?: () => void;
  rendererReleaseDelayMs?: number;
} & Partial<Omit<TrayControllerOptions, "isCloseToTrayEnabled" | "isRendererReleaseEnabled" | "isTrayRequired">> = {}): InstanceType<typeof TrayController> {
  return new TrayController({
    appName: "Shadow",
    iconPaths: [],
    isCloseToTrayEnabled: () => closeToTrayEnabled,
    isRendererReleaseEnabled: () => rendererReleaseEnabled,
    isTrayRequired: () => closeToTrayEnabled,
    isQuitting,
    onShowRequested,
    onQuit,
    rendererReleaseDelayMs,
    ...extra
  });
}

function protectedModel(overrides: Partial<TrayMenuModel> = {}): TrayMenuModel {
  return {
    tone: "ok",
    statusTitle: "Protected · SSH · Frankfurt-01",
    tooltip: "Shadow — Protected · SSH · Frankfurt-01",
    primary: { label: "Disconnect", action: "disconnect", enabled: true },
    servers: [
      { kind: "ssh", id: "fra", label: "Frankfurt-01", checked: true, enabled: true },
      { kind: "ssh", id: "lab", label: "Lab Raspberry", checked: false, enabled: false, sublabel: "No password saved" },
      { kind: "xray", id: "xr", label: "de-fra-reality", checked: false, enabled: true, sublabel: "VLESS" }
    ],
    switchEnabled: true,
    switchNote: "Picking another one closes the current tunnel first, then connects.",
    check: { label: "Run check", enabled: true, sublabel: "Passed · 184 ms" },
    quitSublabel: "Disconnects the tunnel first",
    ...overrides
  };
}

function lastTray(): InstanceType<typeof electron.FakeTray> {
  const tray = electron.FakeTray.instances.at(-1);
  if (!tray) {
    throw new Error("No tray was created.");
  }
  return tray;
}

function lastMenu(): Electron.MenuItemConstructorOptions[] {
  const call = electron.buildFromTemplate.mock.lastCall;
  if (!call) {
    throw new Error("No tray menu was built.");
  }
  return call[0];
}

function menuItem(items: Electron.MenuItemConstructorOptions[], label: string): Electron.MenuItemConstructorOptions {
  const item = items.find((candidate) => candidate.label?.startsWith(label));
  if (!item) {
    throw new Error(`Menu item "${label}" not found in ${items.map((candidate) => candidate.label ?? "-").join(", ")}`);
  }
  return item;
}

function submenuOf(item: Electron.MenuItemConstructorOptions): Electron.MenuItemConstructorOptions[] {
  if (!Array.isArray(item.submenu)) {
    throw new Error(`Menu item "${item.label}" has no submenu template.`);
  }
  return item.submenu;
}

function click(item: Electron.MenuItemConstructorOptions): void {
  item.click?.({} as Electron.MenuItem, undefined, {} as Electron.KeyboardEvent);
}

function testActions(overrides: Partial<TrayMenuActions> = {}): TrayMenuActions {
  return {
    open: vi.fn(),
    quit: vi.fn(),
    connect: vi.fn(),
    disconnect: vi.fn(),
    retry: vi.fn(),
    selectServer: vi.fn(),
    runCheck: vi.fn(),
    resync: vi.fn(),
    ...overrides
  };
}
