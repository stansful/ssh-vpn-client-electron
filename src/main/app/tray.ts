import { BrowserWindow, Menu, nativeImage, screen, Tray } from "electron";
import os from "node:os";
import path from "node:path";
import { composeTrayIcon, windowsTrayIconPixelSize, windowsTrayIconSource, type TrayTone } from "./tray-icons.js";

export type { TrayTone } from "./tray-icons.js";

export type TrayServerKind = "ssh" | "xray";

export interface TrayMenuModel {
  tone: TrayTone;
  /** Header line, e.g. "Protected · SSH · Frankfurt-01" or "Not connected". */
  statusTitle: string;
  /** Tooltip, e.g. "Shadow SSH — Protected · SSH · Frankfurt-01". */
  tooltip: string;
  primary: { label: string; action: "connect" | "disconnect" | "retry" | "none"; enabled: boolean; sublabel?: string };
  servers: Array<{ kind: TrayServerKind; id: string; label: string; checked: boolean; enabled: boolean; sublabel?: string }>;
  switchEnabled: boolean;
  /** e.g. "Picking another one closes the current tunnel first, then connects." */
  switchNote?: string;
  /** e.g. "Run check"; `sublabel` carries the board's hint ("Passed · 184 ms", "Needs a tunnel"). */
  check: { label: string; enabled: boolean; sublabel?: string };
  /** e.g. "Disconnects the tunnel first" or "Closes Shadow SSH". */
  quitSublabel?: string;
}

export interface TrayControllerOptions {
  appName: string;
  iconPaths: string[];
  platform?: NodeJS.Platform;
  /** Overrides the macOS 14.4+ detection of native menu sublabels (tests). */
  nativeMenuSublabels?: boolean;
  isCloseToTrayEnabled: () => boolean;
  isRendererReleaseEnabled: () => boolean;
  isTrayRequired: () => boolean;
  isQuitting: () => boolean;
  onIconLoaded?: (details: { width: number; height: number; scaleFactors: number[]; template: boolean }) => void;
  onShowRequested?: () => void;
  onQuit: () => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onRetry?: () => void;
  onSelectServer?: (kind: TrayServerKind, id: string) => void;
  onRunCheck?: () => void;
  /** A failed icon/menu refresh never reaches the status pipeline that called `update()`. */
  onUpdateError?: (error: unknown) => void;
  rendererReleaseDelayMs?: number;
  /** Primary display scale, which sets the Windows tray icon's pixel size. Defaults to Electron's `screen`. */
  displayScaleFactor?: () => number;
}

export const DEFAULT_RENDERER_RELEASE_DELAY_MS = 30_000;
export const MACOS_TRAY_ICON_SIZE = 16;
export const TRAY_MENU_ICON_SIZE = 16;
export const SWITCH_MENU_LABEL = "Switch server or profile";
const MAX_MENU_LABEL_LENGTH = 48;

interface ScheduledRendererRelease {
  window: BrowserWindow;
  timer: NodeJS.Timeout;
  cancelOnShow: () => void;
  cancelOnFocus: () => void;
  cancelOnClosed: () => void;
}

export interface TrayMenuActions {
  open: () => void;
  quit: () => void;
  connect?: () => void;
  disconnect?: () => void;
  retry?: () => void;
  selectServer?: (kind: TrayServerKind, id: string) => void;
  runCheck?: () => void;
  /** Re-applies the current model after a radio click. */
  resync?: () => void;
}

export interface TrayMenuTemplateOptions {
  appName: string;
  platform: NodeJS.Platform;
  /** Native sublabels exist only in macOS 14.4+; elsewhere the hint joins the label. */
  nativeSublabels: boolean;
  headerIcon?: Electron.NativeImage;
}

export class TrayController {
  private tray: Tray | undefined;
  private scheduledRendererRelease: ScheduledRendererRelease | undefined;
  private model: TrayMenuModel | undefined;
  private baseIcon: Electron.NativeImage | undefined;
  private toneSource: Electron.NativeImage | undefined;
  private readonly toneIcons = new Map<TrayTone, Electron.NativeImage>();
  private readonly menuIcons = new Map<TrayTone, Electron.NativeImage | undefined>();
  private renderedIconTone: TrayTone | undefined;
  private renderedKey: string | undefined;
  private nativeMenuSublabels: boolean | undefined;

  constructor(private readonly options: TrayControllerOptions) {}

  get isCreated(): boolean {
    return this.tray !== undefined;
  }

  sync(): void {
    if (!this.options.isCloseToTrayEnabled() || !this.options.isRendererReleaseEnabled()) {
      this.cancelRendererRelease();
    }
    if (!this.options.isTrayRequired()) {
      // A close-to-tray toggle can race with the native close event. If that
      // event hid the window first, make it reachable again before removing
      // the tray icon.
      for (const window of BrowserWindow.getAllWindows()) {
        if (!window.isDestroyed() && !window.isVisible()) {
          window.show();
          window.focus();
        }
      }
      this.destroy();
      return;
    }
    this.ensure();
  }

  /**
   * Applies the tunnel state to the icon, tooltip and context menu. Safe to
   * call on every status change: identical models are ignored, and a model
   * that arrives before the tray exists is applied when it is created.
   */
  update(model: TrayMenuModel): void {
    this.model = model;
    if (!this.tray) {
      return;
    }
    try {
      this.render();
    } catch (error) {
      this.options.onUpdateError?.(error);
    }
  }

  handleWindowClose(event: Electron.Event, window: BrowserWindow): void {
    // Never make the application unreachable if tray initialization failed.
    if (!this.tray || !this.options.isCloseToTrayEnabled() || this.options.isQuitting()) {
      return;
    }
    event.preventDefault();
    window.hide();
    this.scheduleRendererRelease(window);
  }

  showWindow(): void {
    this.cancelRendererRelease();
    const window = BrowserWindow.getAllWindows().find((candidate) => !candidate.isDestroyed());
    if (!window) {
      this.options.onShowRequested?.();
      return;
    }
    if (window.isMinimized()) {
      window.restore();
    }
    window.show();
    window.focus();
  }

  prepareForQuit(): void {
    this.cancelRendererRelease();
  }

  destroy(): void {
    this.cancelRendererRelease();
    const tray = this.tray;
    this.tray = undefined;
    this.renderedIconTone = undefined;
    this.renderedKey = undefined;
    tray?.destroy();
  }

  private ensure(): void {
    if (this.tray) {
      return;
    }
    const tone = this.model?.tone;
    const tray = new Tray(this.iconFor(tone));
    try {
      this.tray = tray;
      this.renderedIconTone = tone;
      this.render();
      tray.on("click", () => this.showWindow());
      tray.on("double-click", () => this.showWindow());
    } catch (error) {
      this.tray = undefined;
      this.renderedIconTone = undefined;
      this.renderedKey = undefined;
      tray.destroy();
      throw error;
    }
  }

  private loadBaseIcon(): Electron.NativeImage {
    if (this.baseIcon) {
      return this.baseIcon;
    }
    const icon = loadTrayIcon(this.options.iconPaths, this.options.platform);
    if (this.options.onIconLoaded) {
      const size = icon.getSize();
      this.options.onIconLoaded({
        width: size.width,
        height: size.height,
        scaleFactors: icon.getScaleFactors(),
        template: icon.isTemplateImage()
      });
    }
    this.baseIcon = icon;
    return icon;
  }

  private iconFor(tone: TrayTone | undefined): Electron.NativeImage {
    const base = this.loadBaseIcon();
    if (!tone) {
      return base;
    }
    let icon = this.toneIcons.get(tone);
    if (!icon) {
      icon = composeTrayIcon(this.toneSourceIcon(base), tone);
      this.toneIcons.set(tone, icon);
    }
    return icon;
  }

  /** The image tones are painted on: on Windows, the base shrunk to the notification area's size. */
  private toneSourceIcon(base: Electron.NativeImage): Electron.NativeImage {
    if ((this.options.platform ?? process.platform) !== "win32") {
      return base;
    }
    this.toneSource ??= windowsTrayIconSource(base, windowsTrayIconPixelSize(this.displayScaleFactor()));
    return this.toneSource;
  }

  private displayScaleFactor(): number {
    try {
      return this.options.displayScaleFactor?.() ?? screen.getPrimaryDisplay().scaleFactor;
    } catch {
      return 1;
    }
  }

  private menuIconFor(tone: TrayTone): Electron.NativeImage | undefined {
    if (this.menuIcons.has(tone)) {
      return this.menuIcons.get(tone);
    }
    const icon = createMenuIcon(this.iconFor(tone));
    this.menuIcons.set(tone, icon);
    return icon;
  }

  private render(): void {
    const tray = this.tray;
    if (!tray) {
      return;
    }
    const model = this.model;
    const key = model ? JSON.stringify(model) : "";
    if (key === this.renderedKey) {
      return;
    }
    if (model && model.tone !== this.renderedIconTone) {
      tray.setImage(this.iconFor(model.tone));
      this.renderedIconTone = model.tone;
    }
    tray.setToolTip(model?.tooltip ?? this.options.appName);
    const platform = this.options.platform ?? process.platform;
    this.nativeMenuSublabels ??= this.options.nativeMenuSublabels ?? supportsNativeMenuSublabels(platform, os.release());
    const template = buildTrayMenuTemplate(model, this.menuActions(), {
      appName: this.options.appName,
      platform,
      nativeSublabels: this.nativeMenuSublabels,
      headerIcon: model ? this.menuIconFor(model.tone) : undefined
    });
    tray.setContextMenu(Menu.buildFromTemplate(template));
    this.renderedKey = key;
  }

  private menuActions(): TrayMenuActions {
    return {
      open: () => this.showWindow(),
      quit: () => this.options.onQuit(),
      connect: this.options.onConnect,
      disconnect: this.options.onDisconnect,
      retry: this.options.onRetry,
      selectServer: this.options.onSelectServer,
      runCheck: this.options.onRunCheck,
      resync: () => {
        // Electron flips radio checks locally on click; show the model's
        // choice again until the caller publishes the outcome.
        this.renderedKey = undefined;
        try {
          this.render();
        } catch (error) {
          this.options.onUpdateError?.(error);
        }
      }
    };
  }

  private scheduleRendererRelease(window: BrowserWindow): void {
    this.cancelRendererRelease();
    if (!this.options.isRendererReleaseEnabled()) {
      return;
    }

    const cancelOnShow = (): void => this.cancelRendererRelease(window);
    const cancelOnFocus = (): void => this.cancelRendererRelease(window);
    const cancelOnClosed = (): void => this.cancelRendererRelease(window);
    const timer = setTimeout(() => {
      this.cancelRendererRelease(window);
      if (
        this.options.isQuitting() ||
        !this.options.isCloseToTrayEnabled() ||
        !this.options.isRendererReleaseEnabled() ||
        window.isDestroyed() ||
        window.isVisible()
      ) {
        return;
      }
      // Only Chromium/React is destroyed. The tunnel and proxy services live
      // in the Electron main process and are restored into a fresh renderer
      // from the authoritative snapshot when the tray window is reopened.
      window.destroy();
    }, this.options.rendererReleaseDelayMs ?? DEFAULT_RENDERER_RELEASE_DELAY_MS);
    timer.unref();
    window.once("show", cancelOnShow);
    window.once("focus", cancelOnFocus);
    window.once("closed", cancelOnClosed);
    this.scheduledRendererRelease = { window, timer, cancelOnShow, cancelOnFocus, cancelOnClosed };
  }

  private cancelRendererRelease(expectedWindow?: BrowserWindow): void {
    const scheduled = this.scheduledRendererRelease;
    if (!scheduled || (expectedWindow && scheduled.window !== expectedWindow)) {
      return;
    }
    this.scheduledRendererRelease = undefined;
    clearTimeout(scheduled.timer);
    scheduled.window.removeListener("show", scheduled.cancelOnShow);
    scheduled.window.removeListener("focus", scheduled.cancelOnFocus);
    scheduled.window.removeListener("closed", scheduled.cancelOnClosed);
  }
}

/**
 * Builds the System board's tray menu: status header, primary action, the
 * server/profile switcher, tunnel check, then Open and Quit.
 */
export function buildTrayMenuTemplate(
  model: TrayMenuModel | undefined,
  actions: TrayMenuActions,
  options: TrayMenuTemplateOptions
): Electron.MenuItemConstructorOptions[] {
  const openItem: Electron.MenuItemConstructorOptions = {
    label: menuText(`Open ${options.appName}`, options.platform),
    click: () => actions.open()
  };
  if (!model) {
    return [openItem, { type: "separator" }, { label: "Quit", click: () => actions.quit() }];
  }

  const primaryAction = primaryClick(model.primary.action, actions);
  return [
    {
      label: menuText(truncate(model.statusTitle), options.platform),
      enabled: false,
      ...(options.headerIcon ? { icon: options.headerIcon } : {})
    },
    { type: "separator" },
    {
      ...labelWithHint(model.primary.label, model.primary.sublabel, options),
      enabled: model.primary.enabled && primaryAction !== undefined,
      ...(primaryAction ? { click: primaryAction } : {})
    },
    {
      label: SWITCH_MENU_LABEL,
      enabled: model.switchEnabled && model.servers.length > 0,
      submenu: buildSwitchSubmenu(model, actions, options)
    },
    {
      ...labelWithHint(model.check.label, model.check.sublabel, options),
      enabled: model.check.enabled && actions.runCheck !== undefined,
      click: () => actions.runCheck?.()
    },
    { type: "separator" },
    openItem,
    {
      ...labelWithHint("Quit", model.quitSublabel, options),
      click: () => actions.quit()
    }
  ];
}

export function supportsNativeMenuSublabels(platform: NodeJS.Platform, osRelease: string): boolean {
  if (platform !== "darwin") {
    return false;
  }
  // Darwin 23.4 is macOS 14.4, the first release that draws menu sublabels.
  const [major = 0, minor = 0] = osRelease.split(".").map((part) => Number.parseInt(part, 10) || 0);
  return major > 23 || (major === 23 && minor >= 4);
}

function buildSwitchSubmenu(
  model: TrayMenuModel,
  actions: TrayMenuActions,
  options: TrayMenuTemplateOptions
): Electron.MenuItemConstructorOptions[] {
  const groups: Array<{ kind: TrayServerKind; title: string }> = [
    { kind: "ssh", title: "SSH servers" },
    { kind: "xray", title: "Pinned Xray profiles" }
  ];
  const items: Electron.MenuItemConstructorOptions[] = [];
  for (const group of groups) {
    const servers = model.servers.filter((server) => server.kind === group.kind);
    if (servers.length === 0) {
      continue;
    }
    if (items.length > 0) {
      items.push({ type: "separator" });
    }
    items.push({ label: group.title, enabled: false });
    for (const server of servers) {
      items.push({
        ...labelWithHint(truncate(server.label), server.sublabel, options),
        type: "radio",
        checked: server.checked,
        enabled: server.enabled,
        click: () => {
          // Picking the current one only closes the menu, as on the board.
          if (!server.checked) {
            actions.selectServer?.(server.kind, server.id);
          }
          actions.resync?.();
        }
      });
    }
  }
  if (items.length === 0) {
    return [{ label: "No servers or profiles yet", enabled: false }];
  }
  if (model.switchNote) {
    items.push({ type: "separator" }, { label: menuText(model.switchNote, options.platform), enabled: false });
  }
  return items;
}

function primaryClick(action: TrayMenuModel["primary"]["action"], actions: TrayMenuActions): (() => void) | undefined {
  const handler = action === "connect"
    ? actions.connect
    : action === "disconnect"
      ? actions.disconnect
      : action === "retry"
        ? actions.retry
        : undefined;
  return handler ? () => handler() : undefined;
}

function labelWithHint(
  label: string,
  hint: string | undefined,
  options: TrayMenuTemplateOptions
): Pick<Electron.MenuItemConstructorOptions, "label" | "sublabel"> {
  if (!hint) {
    return { label: menuText(label, options.platform) };
  }
  if (options.nativeSublabels) {
    return { label: menuText(label, options.platform), sublabel: hint };
  }
  return { label: menuText(`${label} — ${hint}`, options.platform) };
}

/** Windows and Linux menus read "&" as a mnemonic marker; server names are user text. */
function menuText(text: string, platform: NodeJS.Platform): string {
  return platform === "darwin" ? text : text.replaceAll("&", "&&");
}

function truncate(text: string): string {
  return text.length > MAX_MENU_LABEL_LENGTH ? `${text.slice(0, MAX_MENU_LABEL_LENGTH - 1)}…` : text;
}

function createMenuIcon(icon: Electron.NativeImage): Electron.NativeImage | undefined {
  try {
    if (icon.isEmpty()) {
      return undefined;
    }
    const size = icon.getSize();
    if (size.width <= TRAY_MENU_ICON_SIZE && size.height <= TRAY_MENU_ICON_SIZE) {
      return icon;
    }
    const resized = icon.resize({ width: TRAY_MENU_ICON_SIZE, height: TRAY_MENU_ICON_SIZE, quality: "best" });
    if (icon.isTemplateImage()) {
      resized.setTemplateImage(true);
    }
    return resized;
  } catch {
    return undefined;
  }
}

export function resolveTrayIconPaths({
  packaged,
  projectRoot,
  resourcesPath,
  platform = process.platform
}: {
  packaged: boolean;
  projectRoot: string;
  resourcesPath: string;
  platform?: NodeJS.Platform;
}): string[] {
  const base = packaged ? resourcesPath : path.join(projectRoot, "resources");
  const iconsDir = path.join(base, "icons");
  if (platform === "win32") {
    return [path.join(iconsDir, "icon.ico"), path.join(iconsDir, "icon.png")];
  }
  if (platform === "darwin") {
    // macOS discovers trayTemplate@2x.png beside this 1x representation.
    // The ordinary app icon remains a small, colored fallback only.
    return [path.join(iconsDir, "trayTemplate.png"), path.join(iconsDir, "icon.png")];
  }
  return [path.join(iconsDir, "icon.png")];
}

export function loadTrayIcon(
  iconPaths: string[],
  platform: NodeJS.Platform = process.platform
): Electron.NativeImage {
  for (const iconPath of iconPaths) {
    const loaded = nativeImage.createFromPath(iconPath);
    if (loaded.isEmpty()) {
      continue;
    }
    if (platform !== "darwin") {
      return loaded;
    }
    const size = loaded.getSize();
    const image = size.width > MACOS_TRAY_ICON_SIZE || size.height > MACOS_TRAY_ICON_SIZE
      ? loaded.resize({ width: MACOS_TRAY_ICON_SIZE, height: MACOS_TRAY_ICON_SIZE, quality: "best" })
      : loaded;
    if (path.basename(iconPath).includes("Template")) {
      image.setTemplateImage(true);
    }
    return image;
  }
  return nativeImage.createEmpty();
}
