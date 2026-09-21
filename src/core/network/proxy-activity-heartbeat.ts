import type { ProxyActivityStats } from "./socks5-proxy.js";

/** How often the heartbeat samples the listener, when wired to a timer. */
export const PROXY_HEARTBEAT_INTERVAL_MS = 30_000;

/**
 * Turns the listener's monotonic counters into a periodic one-line summary of
 * what changed since the last sample.
 *
 * It exists to make a data-plane stall legible while it is happening. The
 * routing log says a connection was sent to the tunnel; it cannot say whether
 * bytes then crossed it. When the browser freezes, this line answers the only
 * question that matters - is the tunnel accepting connections and moving data,
 * or is it holding open connections that carry nothing:
 *
 *   active climbing, down/up flat  -> the tunnel accepts and then stalls
 *                                     (downstream of routing - transport/server)
 *   active zero                    -> the client stopped dialling the proxy
 *                                     (its own connection pool is wedged)
 *
 * A fully idle interval is skipped so a quiet tunnel does not fill the log.
 */
export class ProxyActivityHeartbeat {
  private previous: ProxyActivityStats | undefined;

  constructor(
    private readonly read: () => ProxyActivityStats | undefined,
    private readonly emit: (message: string) => void
  ) {}

  /** Captures a baseline so the first tick reports one interval's delta. */
  start(): void {
    this.previous = this.read();
  }

  reset(): void {
    this.previous = undefined;
  }

  tick(): void {
    const current = this.read();
    if (!current) {
      // The listener is gone; drop the baseline so a new one starts clean.
      this.previous = undefined;
      return;
    }
    const previous = this.previous;
    this.previous = current;
    if (!previous) {
      return;
    }

    const openedDelta = current.accepted - previous.accepted;
    const establishedDelta = current.established - previous.established;
    const erroredDelta = current.errored - previous.errored;
    const downDelta = current.bytesToClient - previous.bytesToClient;
    const upDelta = current.bytesToChannel - previous.bytesToChannel;

    // Nothing open and nothing moved: a genuinely idle interval, not worth a line.
    if (current.active === 0 && openedDelta === 0 && erroredDelta === 0 && downDelta === 0 && upDelta === 0) {
      return;
    }

    this.emit(
      `Local proxy activity: active=${current.active}, pendingOpens=${current.pendingChannelOpens}, ` +
        `opened=${openedDelta}, established=${establishedDelta}, errored=${erroredDelta}, ` +
        `down=${formatBytes(downDelta)}, up=${formatBytes(upDelta)} since last check.`
    );
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KiB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}
