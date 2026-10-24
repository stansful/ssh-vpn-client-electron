import { createHmac, randomBytes } from "node:crypto";
import { SECRET_CLIPBOARD_CLEAR_MS } from "../../shared/defaults.js";

export { SECRET_CLIPBOARD_CLEAR_MS };

export interface SecretClipboard {
  readText(): string;
  writeText(text: string): void;
  clear(): void;
}

export interface SecretClipboardGuardOptions {
  clearAfterMs?: number;
  setTimer?: (callback: () => void, ms: number) => unknown;
  clearTimer?: (timer: unknown) => void;
}

/**
 * Tracks the one secret (a private key, a profile link) this app put on the
 * clipboard. It keeps only a keyed digest, never the text: after
 * `clearAfterMs` the clipboard is emptied if it still holds that secret, and
 * meanwhile the renderer's Paste gets nothing back, so a compromised renderer
 * cannot copy a secret and read it straight back. Anything the user copies
 * afterwards is theirs and is never touched.
 *
 * Electron can't mark the entry as excluded from Windows clipboard history
 * or cloud sync: every clipboard write replaces the whole clipboard, so the
 * text and the "ExcludeClipboardContentFromMonitorProcessing" /
 * "CanIncludeInClipboardHistory" formats can't be put there together.
 */
export class SecretClipboardGuard {
  private readonly key = randomBytes(32);
  private readonly clearAfterMs: number;
  private readonly setTimer: (callback: () => void, ms: number) => unknown;
  private readonly cancelTimer: (timer: unknown) => void;
  private digest: string | undefined;
  private timer: unknown;

  constructor(
    private readonly clipboard: SecretClipboard,
    options: SecretClipboardGuardOptions = {}
  ) {
    this.clearAfterMs = options.clearAfterMs ?? SECRET_CLIPBOARD_CLEAR_MS;
    this.setTimer =
      options.setTimer ??
      ((callback, ms) => {
        const timer = setTimeout(callback, ms);
        timer.unref();
        return timer;
      });
    this.cancelTimer = options.clearTimer ?? ((timer) => clearTimeout(timer as NodeJS.Timeout));
  }

  /** Puts a secret on the clipboard and schedules its removal. */
  writeSecret(secret: string): void {
    this.clipboard.writeText(secret);
    this.digest = this.digestOf(secret);
    this.stopTimer();
    this.timer = this.setTimer(() => {
      this.timer = undefined;
      this.clearIfStillHeld();
    }, this.clearAfterMs);
  }

  /**
   * Text the user copied, or undefined while the clipboard still holds the
   * secret this app put there - so Paste can say why it gives nothing back,
   * rather than calling the clipboard empty.
   */
  readText(): string | undefined {
    const text = this.clipboard.readText();
    return this.holds(text) ? undefined : text;
  }

  /** Empties the clipboard now if it still holds the secret (also used on quit). */
  clearIfStillHeld(): void {
    const digest = this.digest;
    if (digest === undefined) {
      return;
    }
    try {
      if (this.digestOf(this.clipboard.readText()) === digest) {
        this.clipboard.clear();
      }
    } finally {
      this.forget();
    }
  }

  /** The secret is no longer tracked (the user copied something else, or it was cleared). */
  private forget(): void {
    this.digest = undefined;
    this.stopTimer();
  }

  private holds(text: string): boolean {
    if (this.digest === undefined) {
      return false;
    }
    if (this.digestOf(text) === this.digest) {
      return true;
    }
    // Something else was copied since: that is the user's, and the secret is gone.
    this.forget();
    return false;
  }

  private stopTimer(): void {
    if (this.timer !== undefined) {
      this.cancelTimer(this.timer);
      this.timer = undefined;
    }
  }

  private digestOf(text: string): string {
    return createHmac("sha256", this.key).update(text, "utf8").digest("base64");
  }
}
