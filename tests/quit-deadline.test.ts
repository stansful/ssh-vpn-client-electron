import { afterEach, describe, expect, it, vi } from "vitest";
import { QUIT_DEADLINE_MS, settleBeforeDeadline } from "../src/main/app/quit-deadline.js";

afterEach(() => {
  vi.useRealTimers();
});

describe("quit deadline", () => {
  it("waits for a cleanup that finishes in time", async () => {
    vi.useFakeTimers();
    let finish!: () => void;
    const cleanup = new Promise<void>((resolve) => {
      finish = resolve;
    });
    const outcome = settleBeforeDeadline(cleanup);
    await vi.advanceTimersByTimeAsync(QUIT_DEADLINE_MS - 1);
    finish();
    await expect(outcome).resolves.toBe("completed");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("gives up on a cleanup stuck behind a connect after ten seconds", async () => {
    vi.useFakeTimers();
    expect(QUIT_DEADLINE_MS).toBe(10_000);
    const outcome = settleBeforeDeadline(new Promise<void>(() => undefined));
    let settled: string | undefined;
    void outcome.then((value) => {
      settled = value;
    });
    await vi.advanceTimersByTimeAsync(QUIT_DEADLINE_MS - 1);
    expect(settled).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    expect(settled).toBe("deadline");
  });

  it("counts a failed cleanup as finished and never rejects", async () => {
    await expect(settleBeforeDeadline(Promise.reject(new Error("dispose failed")), { deadlineMs: 1_000 })).resolves.toBe("completed");
  });

  it("takes its own deadline", async () => {
    vi.useFakeTimers();
    const outcome = settleBeforeDeadline(new Promise<void>(() => undefined), { deadlineMs: 5_000 });
    await vi.advanceTimersByTimeAsync(5_000);
    await expect(outcome).resolves.toBe("deadline");
  });
});
