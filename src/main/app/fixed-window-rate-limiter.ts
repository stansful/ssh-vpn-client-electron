export interface RateLimitDecision {
  allowed: boolean;
  suppressedSinceLastWindow: number;
}

/** Keeps high-volume diagnostic producers from growing serialized I/O queues. */
export class FixedWindowRateLimiter {
  private windowStartedAt: number | undefined;
  private acceptedInWindow = 0;
  private suppressedInWindow = 0;

  constructor(
    private readonly maxPerWindow: number,
    private readonly windowMs: number
  ) {
    if (!Number.isInteger(maxPerWindow) || maxPerWindow <= 0 || !Number.isFinite(windowMs) || windowMs <= 0) {
      throw new Error("Rate limiter bounds must be positive.");
    }
  }

  take(now = Date.now()): RateLimitDecision {
    if (
      this.windowStartedAt === undefined ||
      now < this.windowStartedAt ||
      now - this.windowStartedAt >= this.windowMs
    ) {
      const suppressedSinceLastWindow = this.suppressedInWindow;
      this.windowStartedAt = now;
      this.acceptedInWindow = 1;
      this.suppressedInWindow = 0;
      return { allowed: true, suppressedSinceLastWindow };
    }

    if (this.acceptedInWindow < this.maxPerWindow) {
      this.acceptedInWindow += 1;
      return { allowed: true, suppressedSinceLastWindow: 0 };
    }

    this.suppressedInWindow += 1;
    return { allowed: false, suppressedSinceLastWindow: 0 };
  }
}
