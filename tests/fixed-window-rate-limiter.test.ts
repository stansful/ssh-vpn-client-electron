import { describe, expect, it } from "vitest";
import { FixedWindowRateLimiter } from "../src/main/app/fixed-window-rate-limiter.js";

describe("fixed-window rate limiter", () => {
  it("bounds a burst and reports the suppressed count in the next window", () => {
    const limiter = new FixedWindowRateLimiter(2, 1000);

    expect(limiter.take(0)).toEqual({ allowed: true, suppressedSinceLastWindow: 0 });
    expect(limiter.take(1)).toEqual({ allowed: true, suppressedSinceLastWindow: 0 });
    expect(limiter.take(2).allowed).toBe(false);
    expect(limiter.take(3).allowed).toBe(false);
    expect(limiter.take(1000)).toEqual({ allowed: true, suppressedSinceLastWindow: 2 });
  });

  it("starts a fresh window if the clock moves backwards", () => {
    const limiter = new FixedWindowRateLimiter(1, 1000);
    expect(limiter.take(100).allowed).toBe(true);
    expect(limiter.take(101).allowed).toBe(false);
    expect(limiter.take(50)).toEqual({ allowed: true, suppressedSinceLastWindow: 1 });
  });

  it("rejects invalid bounds", () => {
    expect(() => new FixedWindowRateLimiter(0, 1000)).toThrow(/positive/u);
    expect(() => new FixedWindowRateLimiter(1, 0)).toThrow(/positive/u);
  });
});
