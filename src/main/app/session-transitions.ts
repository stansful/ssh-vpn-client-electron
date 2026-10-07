import type { ConnectionState } from "../../shared/types.js";

export type TunnelTransition =
  | { kind: "lost" }
  | { kind: "restored" }
  | { kind: "stopped"; reason: string };

/**
 * How long an Error that follows a live session waits before it is called
 * final. Xray reports Error first and Reconnecting only after its routing and
 * process are torn down, which can take seconds on Windows - also when a
 * restart attempt fails on the way - while SSH stays in Error when it gives up.
 */
export const ERROR_SETTLE_DELAY_MS = 6_000;

/**
 * Finds the moments a user should hear about while the window is hidden: a
 * working tunnel dropped, came back, or stopped trying. Only sessions that
 * reached Connected count, so a first attempt that fails is not "lost".
 */
export class TunnelTransitionTracker {
  private live = false;
  private lostAnnounced = false;
  private pendingStopReason: string | undefined;

  /** A user Connect or Disconnect starts a new story. */
  reset(): void {
    this.live = false;
    this.lostAnnounced = false;
    this.pendingStopReason = undefined;
  }

  /** True while an Error waits for `settle()`. */
  get hasPendingStop(): boolean {
    return this.pendingStopReason !== undefined;
  }

  /** A drop was announced and the session has neither come back nor given up yet. */
  get isRecovering(): boolean {
    return this.lostAnnounced;
  }

  observe(state: ConnectionState, message: string): TunnelTransition[] {
    switch (state) {
      case "Connected": {
        this.pendingStopReason = undefined;
        const restored = this.live && this.lostAnnounced;
        this.live = true;
        this.lostAnnounced = false;
        return restored ? [{ kind: "restored" }] : [];
      }
      case "Reconnecting": {
        this.pendingStopReason = undefined;
        if (!this.live || this.lostAnnounced) {
          return [];
        }
        this.lostAnnounced = true;
        return [{ kind: "lost" }];
      }
      case "Error": {
        if (!this.live) {
          return [];
        }
        // Final only if nothing follows: a failed Xray restart attempt also
        // passes through Error before its next Reconnecting, and the drop it
        // belongs to stays announced so its return can still be reported.
        this.pendingStopReason = message;
        return [];
      }
      case "Disconnecting":
      case "Disconnected":
        this.reset();
        return [];
      case "Connecting":
        // Xray restarts through Connecting; a user Connect calls reset() first.
        return [];
    }
  }

  /** Called `ERROR_SETTLE_DELAY_MS` after an Error that left a stop pending. */
  settle(): TunnelTransition[] {
    const reason = this.pendingStopReason;
    if (reason === undefined) {
      return [];
    }
    this.reset();
    return [{ kind: "stopped", reason }];
  }
}
