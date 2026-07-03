import { BrowserWindow, Menu, nativeImage, Tray } from "electron";
import path from "node:path";

export interface TrayControllerOptions {
  appName: string;
  iconPaths: string[];
  isCloseToTrayEnabled: () => boolean;
  isTrayRequired: () => boolean;
  isQuitting: () => boolean;
  onQuit: () => void;
}

export class TrayController {
  private tray: Tray | undefined;

  constructor(private readonly options: TrayControllerOptions) {}

  sync(): void {
    if (!this.options.isTrayRequired()) {
      this.destroy();
      return;
    }
    this.ensure();
  }

  handleWindowClose(event: Electron.Event, window: BrowserWindow): void {
    if (!this.options.isCloseToTrayEnabled() || this.options.isQuitting()) {
      return;
    }
    event.preventDefault();
    window.hide();
  }

  showWindow(): void {
    const window = BrowserWindow.getAllWindows()[0];
    if (!window) {
      return;
    }
    if (window.isMinimized()) {
      window.restore();
    }
    window.show();
    window.focus();
  }

  destroy(): void {
    this.tray?.destroy();
    this.tray = undefined;
  }

  private ensure(): void {
    if (this.tray) {
      return;
    }
    this.tray = new Tray(loadTrayIcon(this.options.iconPaths));
    this.tray.setToolTip(this.options.appName);
    this.tray.setContextMenu(
      Menu.buildFromTemplate([
        { label: "Show Shadow SSH", click: () => this.showWindow() },
        { type: "separator" },
        { label: "Quit", click: this.options.onQuit }
      ])
    );
    this.tray.on("click", () => this.showWindow());
    this.tray.on("double-click", () => this.showWindow());
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
  return platform === "win32"
    ? [path.join(iconsDir, "icon.ico"), path.join(iconsDir, "icon.png")]
    : [path.join(iconsDir, "icon.png")];
}

function loadTrayIcon(iconPaths: string[]): Electron.NativeImage {
  for (const iconPath of iconPaths) {
    const image = nativeImage.createFromPath(iconPath);
    if (!image.isEmpty()) {
      return image;
    }
  }
  return nativeImage.createEmpty();
}
