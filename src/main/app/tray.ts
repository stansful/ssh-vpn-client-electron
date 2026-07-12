import { BrowserWindow, Menu, nativeImage, Tray } from "electron";
import path from "node:path";

export interface TrayControllerOptions {
  appName: string;
  iconPaths: string[];
  platform?: NodeJS.Platform;
  isCloseToTrayEnabled: () => boolean;
  isRendererReleaseEnabled: () => boolean;
  isTrayRequired: () => boolean;
  isQuitting: () => boolean;
  onIconLoaded?: (details: { width: number; height: number; scaleFactors: number[]; template: boolean }) => void;
  onShowRequested?: () => void;
  onQuit: () => void;
  rendererReleaseDelayMs?: number;
}

export const DEFAULT_RENDERER_RELEASE_DELAY_MS = 30_000;
export const MACOS_TRAY_ICON_SIZE = 16;

interface ScheduledRendererRelease {
  window: BrowserWindow;
  timer: NodeJS.Timeout;
  cancelOnShow: () => void;
  cancelOnFocus: () => void;
  cancelOnClosed: () => void;
}

export class TrayController {
  private tray: Tray | undefined;
  private scheduledRendererRelease: ScheduledRendererRelease | undefined;

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
    tray?.destroy();
  }

  private ensure(): void {
    if (this.tray) {
      return;
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
    const tray = new Tray(icon);
    try {
      tray.setToolTip(this.options.appName);
      tray.setContextMenu(
        Menu.buildFromTemplate([
          { label: "Show Shadow SSH", click: () => this.showWindow() },
          { type: "separator" },
          { label: "Quit", click: this.options.onQuit }
        ])
      );
      tray.on("click", () => this.showWindow());
      tray.on("double-click", () => this.showWindow());
      this.tray = tray;
    } catch (error) {
      tray.destroy();
      throw error;
    }
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
