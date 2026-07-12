import { describe, expect, it, vi } from "vitest";
import { refreshPublicProxyProfiles } from "../src/main/app/public-proxy-refresh.js";
import type { AppStorage } from "../src/main/storage/app-storage.js";
import { createDefaultStore } from "../src/shared/defaults.js";
import type { FetchImplementation } from "../src/shared/http-fetch.js";
import type { ImportProxyProfilesResult } from "../src/shared/types.js";

describe("app-originated HTTP fetches", () => {
  it("uses the injected fetch implementation for public proxy refresh", async () => {
    const source = "vless://client@example.com:443?security=tls#profile";
    const requests: Array<{ input: string; init?: RequestInit }> = [];
    const fetchImpl = vi.fn(async (input: string, init?: RequestInit) => {
      requests.push({ input, init });
      return new Response(source, { status: 200 });
    });
    const importProxyProfiles = vi.fn(async (): Promise<{ store: ReturnType<typeof createDefaultStore>; result: ImportProxyProfilesResult }> => ({
      store: createDefaultStore(),
      result: { imported: 1, updated: 0, skipped: 0, failed: 0, errors: [] }
    }));
    const storage = { importProxyProfiles } as unknown as AppStorage;

    const result = await refreshPublicProxyProfiles(storage, { fetchImpl });

    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(new Headers(requests[0]?.init?.headers).get("cache-control")).toBe("no-store");
    expect(requests[0]?.input).toContain("hub.mos.ru");
    expect(requests[0]?.init?.signal).toBeInstanceOf(AbortSignal);
    expect(importProxyProfiles).toHaveBeenCalledWith(expect.objectContaining({ text: source, source: "remote" }));
    expect(result.imported).toBe(1);
  });

  it("enforces the public refresh cap while streaming an unknown-length response", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("12345678"));
        controller.enqueue(new TextEncoder().encode("90abcdef"));
        controller.close();
      }
    });
    const fetchImpl = vi.fn(async () => new Response(body, { status: 200 }));
    const importProxyProfiles = vi.fn();
    const storage = { importProxyProfiles } as unknown as AppStorage;

    await expect(refreshPublicProxyProfiles(storage, { fetchImpl, maxBytes: 10 })).rejects.toThrow("larger than the allowed limit");

    expect(importProxyProfiles).not.toHaveBeenCalled();
  });

  it("aborts an injected fetch when its deadline expires", async () => {
    const fetchImpl: FetchImplementation = (_url, init) =>
      new Promise<Response>((_resolve, reject) => {
        const rejectOnAbort = (): void => reject(init?.signal?.reason);
        if (init?.signal?.aborted) {
          rejectOnAbort();
        } else {
          init?.signal?.addEventListener("abort", rejectOnAbort, { once: true });
        }
      });

    const importProxyProfiles = vi.fn();
    const storage = { importProxyProfiles } as unknown as AppStorage;

    await expect(refreshPublicProxyProfiles(storage, { fetchImpl, timeoutMs: 5 })).rejects.toThrow("Public proxy refresh timed out");

    expect(importProxyProfiles).not.toHaveBeenCalled();
  });
});
