import type { AppStorage } from "../storage/app-storage.js";
import { fetchTextWithLimit, type FetchImplementation } from "../../shared/http-fetch.js";
import type { ImportProxyProfilesResult } from "../../shared/types.js";

const PUBLIC_PROXY_SOURCE_URL = "https://hub.mos.ru/zieng2/wl/raw/main/list_universal.txt";
const MAX_PUBLIC_PROXY_SOURCE_BYTES = 2 * 1024 * 1024;
const PUBLIC_PROXY_REFRESH_TIMEOUT_MS = 30_000;

export interface RefreshPublicProxyProfilesOptions {
  fetchImpl?: FetchImplementation;
  maxBytes?: number;
  timeoutMs?: number;
}

export async function refreshPublicProxyProfiles(
  storage: AppStorage,
  options: RefreshPublicProxyProfilesOptions = {}
): Promise<ImportProxyProfilesResult> {
  const text = await fetchTextWithLimit({
    fetchImpl: options.fetchImpl,
    url: PUBLIC_PROXY_SOURCE_URL,
    headers: {
      Accept: "text/plain, */*",
      "User-Agent": "shadow-ssh-desktop-proxy-refresh"
    },
    maxBytes: options.maxBytes ?? MAX_PUBLIC_PROXY_SOURCE_BYTES,
    timeoutMs: options.timeoutMs ?? PUBLIC_PROXY_REFRESH_TIMEOUT_MS,
    failureMessagePrefix: "Public proxy refresh failed",
    limitMessage: "Remote proxy source is larger than the allowed limit.",
    timeoutMessage: "Public proxy refresh timed out."
  });
  const { result } = await storage.importProxyProfiles({
    text,
    source: "remote",
    sourceUrl: PUBLIC_PROXY_SOURCE_URL
  });
  return result;
}
