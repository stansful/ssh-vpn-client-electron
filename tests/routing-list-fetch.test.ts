import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchRoutingListText } from "../src/main/app/routing-list-fetch.js";

describe("routing list fetch", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("uses Node global fetch by default instead of the Electron system-proxy session", async () => {
    const fetchMock = vi.fn(async () => new Response("one.example\ntwo.example\n"));
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchRoutingListText("https://lists.example/inside.lst")).resolves.toBe(
      "one.example\ntwo.example\n"
    );
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledWith(
      "https://lists.example/inside.lst",
      expect.objectContaining({
        headers: expect.objectContaining({
          "Cache-Control": "no-store",
          Pragma: "no-cache",
          "User-Agent": "shadow-ssh-desktop-routing-list"
        }),
        signal: expect.any(AbortSignal)
      })
    );
  });

  it("keeps the bounded streaming limit when a custom transport is injected", async () => {
    const fetchImpl = vi.fn(async () => new Response("12345"));

    await expect(
      fetchRoutingListText("https://lists.example/outside.lst", { fetchImpl, maxBytes: 4 })
    ).rejects.toThrow("Routing list is larger than the allowed limit.");
  });
});
