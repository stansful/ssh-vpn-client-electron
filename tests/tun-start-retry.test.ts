import { describe, expect, it } from "vitest";
import type { DataplaneStartRequest } from "../src/service/local-ipc-protocol.js";
import { startDataplaneWithRetry } from "../src/service/tun-routing.js";

// A TUN start the user gave up on - Disconnect while netsh crawls - must not
// spend a second attempt, and the whole wait, before the teardown can run.

const request = {} as DataplaneStartRequest;

describe("TUN start retries", () => {
  it("retries a failed start, then gives the last error back", async () => {
    let calls = 0;
    const retries: number[] = [];
    await expect(
      startDataplaneWithRetry(
        {
          start: async () => {
            calls += 1;
            throw new Error(`attempt ${calls} failed`);
          }
        },
        request,
        { attempts: 2, sleep: async () => undefined, onRetry: (attempt) => retries.push(attempt) }
      )
    ).rejects.toThrow("attempt 2 failed");
    expect(calls).toBe(2);
    expect(retries).toEqual([1]);
  });

  it("stops waiting the moment it is abandoned, and makes no further attempt", async () => {
    const abort = new AbortController();
    const signals: Array<AbortSignal | undefined> = [];
    const attempt = startDataplaneWithRetry(
      {
        start: (_request, signal) => {
          signals.push(signal);
          // Like the helper client: the wait ends when the signal fires.
          return new Promise<void>((_resolve, reject) => {
            signal?.addEventListener("abort", () => reject(new Error("abandoned")), { once: true });
          });
        }
      },
      request,
      { attempts: 2, sleep: async () => undefined, signal: abort.signal }
    );
    abort.abort();
    await expect(attempt).rejects.toThrow("abandoned");
    expect(signals).toEqual([abort.signal]);
  });

  it("makes no further attempt when abandoned between attempts", async () => {
    const abort = new AbortController();
    let calls = 0;
    await expect(
      startDataplaneWithRetry(
        {
          start: async () => {
            calls += 1;
            throw new Error("netsh failed");
          }
        },
        request,
        {
          attempts: 3,
          sleep: async () => {
            abort.abort();
          },
          signal: abort.signal
        }
      )
    ).rejects.toThrow("netsh failed");
    expect(calls).toBe(1);
  });

  it("cuts the pause between attempts short when abandoned", async () => {
    const abort = new AbortController();
    let calls = 0;
    const startedAt = Date.now();
    const attempt = startDataplaneWithRetry(
      {
        start: async () => {
          calls += 1;
          throw new Error("netsh failed");
        }
      },
      request,
      { attempts: 2, delayMs: 10_000, signal: abort.signal, onRetry: () => setTimeout(() => abort.abort(), 10) }
    );
    await expect(attempt).rejects.toThrow("netsh failed");
    expect(calls).toBe(1);
    expect(Date.now() - startedAt).toBeLessThan(5_000);
  });
});
