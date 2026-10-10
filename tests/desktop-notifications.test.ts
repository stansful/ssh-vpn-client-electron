import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_SETTINGS } from "../src/shared/defaults.js";
import type { AppSettings } from "../src/shared/types.js";
import type { DesktopNotifierOptions } from "../src/main/app/notifications.js";

const electron = vi.hoisted(() => {
  class FakeNotification {
    static instances: FakeNotification[] = [];
    static supported = true;
    static isSupported(): boolean {
      return FakeNotification.supported;
    }

    readonly handlers = new Map<string, (...args: unknown[]) => void>();
    readonly show = vi.fn();
    readonly close = vi.fn();

    constructor(readonly options: Electron.NotificationConstructorOptions) {
      FakeNotification.instances.push(this);
    }

    on(event: string, handler: (...args: unknown[]) => void): this {
      this.handlers.set(event, handler);
      return this;
    }

    emit(event: string, ...args: unknown[]): void {
      this.handlers.get(event)?.(...args);
    }
  }
  return { FakeNotification };
});

vi.mock("electron", () => ({ Notification: electron.FakeNotification }));

const { DesktopNotifier } = await import("../src/main/app/notifications.js");

afterEach(() => {
  electron.FakeNotification.instances = [];
  electron.FakeNotification.supported = true;
});

function lastNotification(): InstanceType<typeof electron.FakeNotification> {
  const notification = electron.FakeNotification.instances.at(-1);
  if (!notification) {
    throw new Error("No notification was shown.");
  }
  return notification;
}

function createNotifier({
  settings = {},
  visible = false,
  ...options
}: { settings?: Partial<AppSettings>; visible?: boolean } & Partial<DesktopNotifierOptions> = {}): {
  notifier: InstanceType<typeof DesktopNotifier>;
  onOpenWindow: ReturnType<typeof vi.fn>;
  onStopReconnecting: ReturnType<typeof vi.fn>;
  onRevealUpdate: ReturnType<typeof vi.fn>;
} {
  const onOpenWindow = vi.fn();
  const onStopReconnecting = vi.fn();
  const onRevealUpdate = vi.fn();
  const notifier = new DesktopNotifier({
    appName: "Shadow SSH",
    iconPath: "/resources/icons/icon.png",
    platform: "win32",
    getSettings: () => ({ ...DEFAULT_SETTINGS, ...settings }),
    isWindowVisible: () => visible,
    onOpenWindow,
    onStopReconnecting,
    onRevealUpdate,
    ...options
  });
  return { notifier, onOpenWindow, onStopReconnecting, onRevealUpdate };
}

describe("desktop notifications", () => {
  it("announces a lost tunnel with Open and Stop reconnecting on Windows", () => {
    const { notifier, onOpenWindow, onStopReconnecting } = createNotifier();

    notifier.notifyTunnelLost("Frankfurt-01");

    const notification = lastNotification();
    expect(notification.options).toMatchObject({
      title: "Reconnecting to Frankfurt-01…",
      body: "The session dropped, so Shadow SSH is trying again.",
      icon: "/resources/icons/icon.png",
      actions: [
        { type: "button", text: "Open Shadow SSH" },
        { type: "button", text: "Stop reconnecting" }
      ]
    });
    expect(notification.show).toHaveBeenCalledOnce();

    notification.emit("action", { actionIndex: 1 }, 1);
    expect(onStopReconnecting).toHaveBeenCalledOnce();
    notification.emit("action", { actionIndex: 0 }, 0);
    notification.emit("click");
    expect(onOpenWindow).toHaveBeenCalledTimes(2);
  });

  it("keeps the board copy for the reason when the caller has one", () => {
    const { notifier } = createNotifier();

    notifier.notifyTunnelLost(
      "Frankfurt-01",
      "Your network changed, so the session dropped. Trying again, attempt 3. Routing stays on for 30 s."
    );

    expect(lastNotification().options.body).toBe(
      "Your network changed, so the session dropped. Trying again, attempt 3. Routing stays on for 30 s."
    );
  });

  it("uses a single action on macOS, where clicking the notification opens the app", () => {
    const { notifier } = createNotifier({ platform: "darwin" });

    notifier.notifyTunnelLost("Frankfurt-01");

    expect(lastNotification().options.actions).toEqual([{ type: "button", text: "Stop reconnecting" }]);
    expect(lastNotification().options.icon).toBeUndefined();
  });

  it("omits actions on Linux, where clicking opens the window", () => {
    const { notifier, onOpenWindow } = createNotifier({ platform: "linux" });

    notifier.notifyTunnelLost("Frankfurt-01");
    lastNotification().emit("click");

    expect(lastNotification().options.actions).toBeUndefined();
    expect(onOpenWindow).toHaveBeenCalledOnce();
  });

  it("replaces the lost-tunnel notification when the tunnel comes back", () => {
    const { notifier } = createNotifier();

    notifier.notifyTunnelLost("Frankfurt-01");
    const lost = lastNotification();
    notifier.notifyTunnelRestored("Frankfurt-01");

    expect(lost.close).toHaveBeenCalledOnce();
    expect(lastNotification().options).toMatchObject({
      title: "Back online · Frankfurt-01",
      body: "Reconnected. The tunnel is working again."
    });
  });

  it("ignores Stop reconnecting on a notification whose drop is already over", () => {
    const { notifier, onStopReconnecting } = createNotifier();
    notifier.notifyTunnelLost("Frankfurt-01");
    const lost = lastNotification();

    notifier.withdrawTunnelLost();
    expect(lost.close).toHaveBeenCalledOnce();
    // The OS can still deliver a click on a copy left in the notification centre.
    lost.emit("action", { actionIndex: 1 }, 1);

    expect(onStopReconnecting).not.toHaveBeenCalled();
  });

  it("withdraws the lost-tunnel notification when the return is not announced", () => {
    let visible = false;
    const { notifier, onStopReconnecting } = createNotifier({ isWindowVisible: () => visible });
    notifier.notifyTunnelLost("Frankfurt-01");
    const lost = lastNotification();

    // The user opened the window, so "Back online" is an in-app toast instead.
    visible = true;
    notifier.notifyTunnelRestored("Frankfurt-01");
    lost.emit("action", { actionIndex: 1 }, 1);

    expect(electron.FakeNotification.instances).toHaveLength(1);
    expect(lost.close).toHaveBeenCalledOnce();
    expect(onStopReconnecting).not.toHaveBeenCalled();
  });

  it("keeps Back online when the drop is withdrawn after it", () => {
    const { notifier } = createNotifier();
    notifier.notifyTunnelLost("Frankfurt-01");
    notifier.notifyTunnelRestored("Frankfurt-01");
    const restored = lastNotification();

    notifier.withdrawTunnelLost();

    expect(restored.close).not.toHaveBeenCalled();
  });

  it("acts on Stop reconnecting only once, from the newest drop", () => {
    const { notifier, onStopReconnecting } = createNotifier();
    notifier.notifyTunnelLost("Frankfurt-01");
    const first = lastNotification();
    notifier.notifyTunnelLost("Amsterdam-edge");
    const second = lastNotification();

    first.emit("action", { actionIndex: 1 }, 1);
    expect(onStopReconnecting).not.toHaveBeenCalled();
    second.emit("action", { actionIndex: 1 }, 1);
    second.emit("action", { actionIndex: 1 }, 1);
    expect(onStopReconnecting).toHaveBeenCalledOnce();
  });

  it("reports why reconnecting stopped", () => {
    const { notifier } = createNotifier();

    notifier.notifyReconnectStopped("Frankfurt-01", "Frankfurt-01 rejected the password.");

    expect(lastNotification().options).toMatchObject({
      title: "Stopped reconnecting to Frankfurt-01",
      body: "Frankfurt-01 rejected the password.",
      actions: [{ type: "button", text: "Open Shadow SSH" }]
    });
  });

  it("offers Show in folder and Later for a downloaded update", () => {
    const { notifier, onRevealUpdate } = createNotifier();

    notifier.notifyUpdateDownloaded("2.3.0", {
      fileName: "shadow-ssh-2.3.0-windows-portable-x64.exe",
      sizeBytes: 92 * 1024 * 1024
    });

    const notification = lastNotification();
    expect(notification.options).toMatchObject({
      title: "Update 2.3.0 downloaded",
      body: "shadow-ssh-2.3.0-windows-portable-x64.exe · 92 MB. Quit Shadow SSH, then run the new file.",
      actions: [
        { type: "button", text: "Show in folder" },
        { type: "button", text: "Later" }
      ]
    });
    notification.emit("action", { actionIndex: 1 }, 1);
    expect(onRevealUpdate).not.toHaveBeenCalled();
    notification.emit("action", { actionIndex: 0 }, 0);
    expect(onRevealUpdate).toHaveBeenCalledOnce();
  });

  it("says how each downloaded file replaces the running build", () => {
    const { notifier } = createNotifier();

    notifier.notifyUpdateDownloaded("2.3.0", { format: "macos-dmg" });
    expect(lastNotification().options.body).toBe("Quit Shadow SSH, then open the new file and drag Shadow SSH into Applications.");
    notifier.notifyUpdateDownloaded("2.3.0", { format: "linux-appimage" });
    expect(lastNotification().options.body).toBe("Quit Shadow SSH, then run the new AppImage.");
    notifier.notifyUpdateDownloaded("2.3.0", { format: "linux-deb" });
    expect(lastNotification().options.body).toBe("Quit Shadow SSH, then install the new package.");
    notifier.notifyUpdateDownloaded("2.3.0", { format: "windows-portable" });
    expect(lastNotification().options.body).toBe("Quit Shadow SSH, then run the new file.");
  });

  it("uses the macOS close button for Later", () => {
    const { notifier } = createNotifier({ platform: "darwin" });

    notifier.notifyUpdateDownloaded("2.3.0");

    expect(lastNotification().options).toMatchObject({
      body: "Quit Shadow SSH, then run the new file.",
      actions: [{ type: "button", text: "Show in folder" }],
      closeButtonText: "Later"
    });
  });

  it("respects each switch and stays quiet while the window is visible", () => {
    createNotifier({ settings: { notifyTunnelChanges: false } }).notifier.notifyTunnelLost("Frankfurt-01");
    createNotifier({ settings: { notifyTunnelChanges: false } }).notifier.notifyTunnelRestored("Frankfurt-01");
    createNotifier({ settings: { notifyTunnelChanges: false } }).notifier.notifyReconnectStopped("Frankfurt-01", "x");
    createNotifier({ settings: { notifyUpdateDownloaded: false } }).notifier.notifyUpdateDownloaded("2.3.0");
    createNotifier({ visible: true }).notifier.notifyTunnelLost("Frankfurt-01");
    createNotifier({ visible: true }).notifier.notifyUpdateDownloaded("2.3.0");
    expect(electron.FakeNotification.instances).toHaveLength(0);

    createNotifier({ visible: true, settings: { notifyOnlyWhenHidden: false } }).notifier.notifyTunnelLost("Frankfurt-01");
    expect(electron.FakeNotification.instances).toHaveLength(1);
  });

  it("does nothing where the OS has no notifications", () => {
    electron.FakeNotification.supported = false;
    const { notifier } = createNotifier();

    notifier.notifyTunnelLost("Frankfurt-01");

    expect(notifier.notifyStillRunningInTray()).toBe(false);
    expect(electron.FakeNotification.instances).toHaveLength(0);
  });

  it("tells once that the app keeps running in the tray", () => {
    const { notifier, onOpenWindow } = createNotifier({ visible: true });

    expect(notifier.notifyStillRunningInTray()).toBe(true);
    expect(lastNotification().options).toMatchObject({
      title: "Shadow SSH is still running",
      body: "Closing the window keeps the tunnel on. To exit, right-click the tray icon and choose Quit."
    });
    lastNotification().emit("click");
    expect(onOpenWindow).toHaveBeenCalledOnce();

    expect(createNotifier({ settings: { stillRunningNoticeShown: true } }).notifier.notifyStillRunningInTray()).toBe(false);
    expect(createNotifier({ settings: { notifyStillRunningInTray: false } }).notifier.notifyStillRunningInTray()).toBe(false);
    expect(electron.FakeNotification.instances).toHaveLength(1);
  });

  it("points macOS users at the menu bar to quit", () => {
    const { notifier } = createNotifier({ platform: "darwin" });

    notifier.notifyStillRunningInTray();

    expect(lastNotification().options.body).toBe(
      "Closing the window keeps the tunnel on. To exit, click the Shadow SSH icon in the menu bar and choose Quit."
    );
  });

  it("returns false when the OS refuses to show the notification", () => {
    const { notifier } = createNotifier();
    vi.spyOn(electron.FakeNotification.prototype, "on").mockImplementationOnce(() => {
      throw new Error("toast failed");
    });

    expect(notifier.notifyStillRunningInTray()).toBe(false);
  });

  it("withdraws its notifications on dispose", () => {
    const { notifier } = createNotifier();
    notifier.notifyTunnelLost("Frankfurt-01");
    notifier.notifyUpdateDownloaded("2.3.0");

    notifier.dispose();

    for (const notification of electron.FakeNotification.instances) {
      expect(notification.close).toHaveBeenCalledOnce();
    }
  });
});
