import { Notification } from "electron";
import type { AppSettings, AppUpdateFormat } from "../../shared/types.js";

export interface DesktopNotifierOptions {
  appName: string;
  /** Shown by Windows and Linux; macOS always uses the app icon. */
  iconPath?: string;
  getSettings: () => AppSettings;
  /** Should be false while the window is hidden or minimized. */
  isWindowVisible: () => boolean;
  onOpenWindow: () => void;
  onStopReconnecting?: () => void;
  onRevealUpdate?: () => void;
  platform?: NodeJS.Platform;
}

export interface DownloadedUpdateDetails {
  fileName?: string;
  sizeBytes?: number;
  /** Picks the install step; without it the file is simply run. */
  format?: AppUpdateFormat;
}

type NotificationSlot = "tunnel" | "update" | "still-running";
type NotifySetting = "notifyTunnelChanges" | "notifyUpdateDownloaded";

interface NotificationButton {
  text: string;
  run?: () => void;
}

interface NotificationContent {
  title: string;
  body: string;
  /** Windows shows every button; macOS folds extras into "Options", so it gets `macButtons`. */
  buttons?: NotificationButton[];
  macButtons?: NotificationButton[];
  macCloseText?: string;
}

/**
 * Desktop (OS) notifications for the moments System.dc.html section 05 lists.
 * Each kind replaces its previous notification instead of stacking, and the
 * live objects are kept so macOS does not withdraw them on garbage collection.
 */
export class DesktopNotifier {
  private readonly shown = new Map<NotificationSlot, Notification>();
  /**
   * The "Reconnecting…" notification while its drop is still being retried.
   * Its "Stop reconnecting" button acts only while it is this one: a copy left
   * in Notification Center or the Action Center must not end a session that
   * came back, or a different one started later.
   */
  private tunnelLost: Notification | undefined;

  constructor(private readonly options: DesktopNotifierOptions) {}

  notifyTunnelLost(name: string, detail?: string): void {
    if (!this.allows("notifyTunnelChanges")) {
      return;
    }
    const open = { text: `Open ${this.options.appName}`, run: () => this.options.onOpenWindow() };
    const onStop = this.options.onStopReconnecting;
    const lost: { notification?: Notification } = {};
    const stop = onStop
      ? {
          text: "Stop reconnecting",
          run: () => {
            if (!lost.notification || this.tunnelLost !== lost.notification) {
              return;
            }
            this.tunnelLost = undefined;
            onStop();
          }
        }
      : undefined;
    lost.notification = this.show("tunnel", {
      title: `Reconnecting to ${name}…`,
      body: detail ?? `The session dropped, so ${this.options.appName} is trying again.`,
      buttons: stop ? [open, stop] : [open],
      macButtons: stop ? [stop] : []
    });
    this.tunnelLost = lost.notification;
  }

  notifyTunnelRestored(name: string, detail?: string): void {
    if (!this.allows("notifyTunnelChanges")) {
      // No announcement, but the "Reconnecting…" one is out of date either way.
      this.withdrawTunnelLost();
      return;
    }
    this.tunnelLost = undefined;
    this.show("tunnel", {
      title: `Back online · ${name}`,
      body: detail ?? "Reconnected. The tunnel is working again."
    });
  }

  notifyReconnectStopped(name: string, reason: string): void {
    if (!this.allows("notifyTunnelChanges")) {
      this.withdrawTunnelLost();
      return;
    }
    this.tunnelLost = undefined;
    this.show("tunnel", {
      title: `Stopped reconnecting to ${name}`,
      body: reason.trim() || `Open ${this.options.appName} to see what went wrong.`,
      buttons: [{ text: `Open ${this.options.appName}`, run: () => this.options.onOpenWindow() }],
      macButtons: []
    });
  }

  /**
   * Takes back the "Reconnecting…" notification once its drop is over: the
   * tunnel came back, gave up, or the user disconnected or started another
   * session. Other notifications in the slot ("Back online") stay.
   */
  withdrawTunnelLost(): void {
    const notification = this.tunnelLost;
    if (!notification) {
      return;
    }
    this.tunnelLost = undefined;
    if (this.shown.get("tunnel") === notification) {
      this.shown.delete("tunnel");
    }
    closeQuietly(notification);
  }

  notifyUpdateDownloaded(version: string, details: DownloadedUpdateDetails = {}): void {
    if (!this.allows("notifyUpdateDownloaded")) {
      return;
    }
    const file = [details.fileName, details.sizeBytes ? formatMegabytes(details.sizeBytes) : undefined]
      .filter(Boolean)
      .join(" · ");
    const reveal = this.options.onRevealUpdate
      ? { text: "Show in folder", run: this.options.onRevealUpdate }
      : undefined;
    const later = { text: "Later" };
    this.show("update", {
      title: `Update ${version} downloaded`,
      body: `${file ? `${file}. ` : ""}Quit ${this.options.appName}, then ${installStep(details.format, this.options.appName)}.`,
      buttons: reveal ? [reveal, later] : [],
      macButtons: reveal ? [reveal] : [],
      macCloseText: reveal ? "Later" : undefined
    });
  }

  /** Returns true when shown, so the caller can persist `stillRunningNoticeShown`. */
  notifyStillRunningInTray(): boolean {
    const settings = this.options.getSettings();
    // No visibility gate: this fires exactly when the window is being hidden.
    if (!settings.notifyStillRunningInTray || settings.stillRunningNoticeShown) {
      return false;
    }
    return this.show("still-running", {
      title: `${this.options.appName} is still running`,
      body: `Closing the window keeps the tunnel on. ${this.quitHint()}`
    }) !== undefined;
  }

  /** Withdraws everything this notifier showed, e.g. before quitting. */
  dispose(): void {
    for (const notification of this.shown.values()) {
      closeQuietly(notification);
    }
    this.shown.clear();
    this.tunnelLost = undefined;
  }

  private allows(setting: NotifySetting): boolean {
    const settings = this.options.getSettings();
    if (!settings[setting]) {
      return false;
    }
    // With the window open the app shows in-app toasts instead, never both.
    return !(settings.notifyOnlyWhenHidden && this.options.isWindowVisible());
  }

  private quitHint(): string {
    switch (this.platform()) {
      case "darwin":
        return `To exit, click the ${this.options.appName} icon in the menu bar and choose Quit.`;
      default:
        return "To exit, right-click the tray icon and choose Quit.";
    }
  }

  private platform(): NodeJS.Platform {
    return this.options.platform ?? process.platform;
  }

  private show(slot: NotificationSlot, content: NotificationContent): Notification | undefined {
    try {
      if (!Notification.isSupported()) {
        return undefined;
      }
      const platform = this.platform();
      // Linux notification servers have no Electron action support; a click opens the window.
      const buttons = platform === "darwin"
        ? content.macButtons ?? content.buttons ?? []
        : platform === "win32"
          ? content.buttons ?? []
          : [];
      const notification = new Notification({
        title: content.title,
        body: content.body,
        ...(this.options.iconPath && platform !== "darwin" ? { icon: this.options.iconPath } : {}),
        ...(buttons.length > 0 ? { actions: buttons.map(({ text }) => ({ type: "button" as const, text })) } : {}),
        ...(platform === "darwin" && content.macCloseText ? { closeButtonText: content.macCloseText } : {})
      });
      const forget = (): void => {
        if (this.shown.get(slot) === notification) {
          this.shown.delete(slot);
        }
      };
      notification.on("click", () => {
        forget();
        this.options.onOpenWindow();
      });
      notification.on("action", (details, legacyIndex) => {
        forget();
        const index = typeof details?.actionIndex === "number" ? details.actionIndex : legacyIndex;
        buttons[index]?.run?.();
      });
      notification.on("close", forget);
      notification.on("failed", forget);

      const previous = this.shown.get(slot);
      if (previous) {
        closeQuietly(previous);
      }
      this.shown.set(slot, notification);
      notification.show();
      return notification;
    } catch {
      this.shown.delete(slot);
      return undefined;
    }
  }
}

function closeQuietly(notification: Notification): void {
  try {
    notification.close();
  } catch {
    // The OS may already have withdrawn it.
  }
}

function formatMegabytes(bytes: number): string {
  return `${Math.max(1, Math.round(bytes / (1024 * 1024)))} MB`;
}

/** What follows "Quit Shadow SSH, then …" for a downloaded update. */
function installStep(format: AppUpdateFormat | undefined, appName: string): string {
  switch (format) {
    case "macos-dmg":
      return `open the new file and drag ${appName} into Applications`;
    case "linux-appimage":
      return "run the new AppImage";
    case "linux-deb":
      return "install the new package";
    default:
      return "run the new file";
  }
}
