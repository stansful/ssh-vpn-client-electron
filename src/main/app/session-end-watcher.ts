/**
 * Windows tells a running program that the session is ending - sign-out,
 * restart, shutdown - only through its top-level windows. With the window
 * released to the tray (the default after half a minute there) or a start
 * minimised to it, Shadow has none, and signing out left the system proxy
 * pointing at a port nothing listens on until Shadow ran again. An invisible
 * native window, with no web contents and never shown, stands in for as long
 * as there is no other.
 */

/** The part of a native window this needs; Electron's BaseWindow in the app. */
export interface SessionEndWindow {
  on(event: "session-end", listener: (event: { reasons: string[] }) => void): unknown;
  once(event: "closed", listener: () => void): unknown;
  isDestroyed(): boolean;
  destroy(): void;
}

export interface SessionEndWatcherOptions {
  /** Creates the invisible window. */
  createWindow: () => SessionEndWindow;
  /** The session is ending; `reasons` are Windows' own, possibly none. */
  onSessionEnd: (reasons: string[]) => void;
}

export class SessionEndWatcher {
  private window: SessionEndWindow | undefined;

  constructor(private readonly options: SessionEndWatcherOptions) {}

  /** Whether the invisible window is up. */
  get watching(): boolean {
    return this.window !== undefined;
  }

  /**
   * Keeps the invisible window up exactly while it is needed: on Windows,
   * with no other window, and not while quitting - a window of its own would
   * keep "all windows closed" from ever being reported, which is how the app
   * quits when it does not live in the tray.
   */
  update(state: { windows: boolean; platform: NodeJS.Platform; quitting: boolean }): void {
    if (state.platform !== "win32" || state.windows || state.quitting) {
      this.stop();
      return;
    }
    if (this.window) {
      return;
    }
    const window = this.options.createWindow();
    window.on("session-end", (event) => this.options.onSessionEnd(event.reasons ?? []));
    window.once("closed", () => {
      if (this.window === window) {
        this.window = undefined;
      }
    });
    this.window = window;
  }

  stop(): void {
    const window = this.window;
    this.window = undefined;
    if (window && !window.isDestroyed()) {
      window.destroy();
    }
  }
}
