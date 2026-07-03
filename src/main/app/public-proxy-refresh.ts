import type { AppStorage } from "../storage/app-storage.js";
import type { ImportProxyProfilesResult } from "../../shared/types.js";

const PUBLIC_PROXY_SOURCE_URL = "https://hub.mos.ru/zieng2/wl/raw/main/list_universal.txt";
const MAX_PUBLIC_PROXY_SOURCE_BYTES = 2 * 1024 * 1024;

export async function refreshPublicProxyProfiles(storage: AppStorage): Promise<ImportProxyProfilesResult> {
  const response = await fetch(PUBLIC_PROXY_SOURCE_URL, {
    headers: {
      Accept: "text/plain, */*",
      "User-Agent": "shadow-ssh-desktop-proxy-refresh"
    }
  });
  if (!response.ok) {
    throw new Error(`Public proxy refresh failed: ${response.status} ${response.statusText}`);
  }
  const text = await readLimitedResponseText(response, MAX_PUBLIC_PROXY_SOURCE_BYTES);
  const { result } = await storage.importProxyProfiles({
    text,
    source: "remote",
    sourceUrl: PUBLIC_PROXY_SOURCE_URL
  });
  return result;
}

async function readLimitedResponseText(response: Response, limit: number): Promise<string> {
  const contentLength = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > limit) {
    throw new Error("Remote proxy source is larger than the allowed limit.");
  }
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > limit) {
    throw new Error("Remote proxy source is larger than the allowed limit.");
  }
  return text;
}
