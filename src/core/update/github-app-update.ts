import { createHash, randomUUID } from "node:crypto";
import { mkdir, open, readdir, rename, rm } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";
import type { FetchImplementation } from "../../shared/http-fetch.js";
import type { AppUpdateAsset, AppUpdateInfo, RuntimeArch } from "../../shared/types.js";

const RELEASE_API_URL = "https://api.github.com/repos/stansful/ssh-vpn-client-electron/releases/latest";
const RELEASE_DOWNLOAD_PREFIX = "https://github.com/stansful/ssh-vpn-client-electron/releases/download/";
const MAX_RELEASE_RESPONSE_BYTES = 1024 * 1024;
const MAX_UPDATE_DOWNLOAD_BYTES = 160 * 1024 * 1024;
const UPDATE_CHECK_TIMEOUT_MS = 30 * 1000;
const UPDATE_DOWNLOAD_TIMEOUT_MS = 10 * 60 * 1000;
const PORTABLE_UPDATE_FILE_PATTERN = /^shadow-ssh-\d+\.\d+\.\d+-windows-portable-(?:x64|arm64)\.exe$/u;

interface GitHubAsset {
  name?: string;
  size?: number;
  digest?: string;
  browser_download_url?: string;
}

interface GitHubRelease {
  tag_name?: string;
  html_url?: string;
  published_at?: string;
  assets?: GitHubAsset[];
}

export interface CheckAppUpdateOptions {
  currentVersion: string;
  arch: RuntimeArch;
  eTag?: string;
  force?: boolean;
  timeoutMs?: number;
  fetchImpl?: FetchImplementation;
}

export interface CheckAppUpdateResult {
  info: AppUpdateInfo;
  eTag?: string;
  notModified: boolean;
}

export interface DownloadUpdateAssetOptions {
  timeoutMs?: number;
  onProgress?: (downloadedBytes: number, totalBytes: number) => void;
  fetchImpl?: FetchImplementation;
}

export async function checkGitHubAppUpdate(options: CheckAppUpdateOptions): Promise<CheckAppUpdateResult> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "Cache-Control": "no-store",
    Pragma: "no-cache",
    "User-Agent": "shadow-ssh-desktop-updater",
    "X-GitHub-Api-Version": "2026-03-10"
  };
  if (options.eTag && !options.force) {
    headers["If-None-Match"] = options.eTag;
  }

  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(new Error("Update check timed out.")),
    normalizeTimeout(options.timeoutMs, UPDATE_CHECK_TIMEOUT_MS)
  );
  timeout.unref();
  try {
    return await readGitHubAppUpdate(options, headers, controller.signal);
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error("Update check timed out.", { cause: error });
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function readGitHubAppUpdate(
  options: CheckAppUpdateOptions,
  headers: Record<string, string>,
  signal: AbortSignal
): Promise<CheckAppUpdateResult> {
  // The application owns ETag validation explicitly and should not maintain a
  // duplicate browser cache entry for release metadata.
  const response = await (options.fetchImpl ?? globalThis.fetch)(RELEASE_API_URL, { headers, signal });
  const checkedAt = new Date().toISOString();
  const eTag = response.headers.get("etag") ?? undefined;
  if (response.status === 304) {
    return {
      eTag,
      notModified: true,
      info: {
        available: false,
        currentVersion: options.currentVersion,
        checkedAt,
        message: "No release changes since last update check."
      }
    };
  }
  if (!response.ok) {
    throw new Error(`GitHub update check failed: ${response.status} ${response.statusText}`);
  }

  const raw = await readLimitedText(response, MAX_RELEASE_RESPONSE_BYTES);
  const release = JSON.parse(raw) as GitHubRelease;
  const latestVersion = normalizeVersion(release.tag_name ?? "");
  if (!latestVersion) {
    throw new Error("Latest release tag is not a strict SemVer version.");
  }

  const asset = selectWindowsPortableAsset(release, latestVersion, options.arch);
  const comparison = compareSemver(latestVersion, normalizeVersion(options.currentVersion) ?? options.currentVersion);
  if (comparison <= 0) {
    return {
      eTag,
      notModified: false,
      info: {
        available: false,
        currentVersion: options.currentVersion,
        latestVersion,
        releaseUrl: release.html_url,
        publishedAt: release.published_at,
        checkedAt,
        message: `You are already on ${options.currentVersion}.`
      }
    };
  }
  if (!asset) {
    return {
      eTag,
      notModified: false,
      info: {
        available: false,
        currentVersion: options.currentVersion,
        latestVersion,
        releaseUrl: release.html_url,
        publishedAt: release.published_at,
        checkedAt,
        message: `Update ${latestVersion} is available, but no Windows ${options.arch} portable asset was found.`
      }
    };
  }

  return {
    eTag,
    notModified: false,
    info: {
      available: true,
      currentVersion: options.currentVersion,
      latestVersion,
      releaseUrl: release.html_url,
      publishedAt: release.published_at,
      asset,
      checkedAt,
      message: `Update ${latestVersion} is available for Windows ${asset.arch}.`
    }
  };
}

export async function downloadUpdateAsset(
  asset: AppUpdateAsset,
  downloadDirectory: string,
  options: DownloadUpdateAssetOptions = {}
): Promise<string> {
  if (!asset.downloadUrl.startsWith(RELEASE_DOWNLOAD_PREFIX)) {
    throw new Error("Refusing to download update from an untrusted URL.");
  }
  if (!Number.isSafeInteger(asset.size) || asset.size <= 0 || asset.size > MAX_UPDATE_DOWNLOAD_BYTES) {
    throw new Error("Update asset is larger than the allowed download limit.");
  }
  await mkdir(downloadDirectory, { recursive: true });
  const outputPath = path.join(downloadDirectory, sanitizeFileName(asset.name));
  const temporaryPath = `${outputPath}.${process.pid}.${randomUUID()}.part`;
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(new Error("Update download timed out.")),
    normalizeTimeout(options.timeoutMs, UPDATE_DOWNLOAD_TIMEOUT_MS)
  );
  timeout.unref();

  try {
    const response = await (options.fetchImpl ?? globalThis.fetch)(asset.downloadUrl, {
      signal: controller.signal,
      headers: {
        Accept: "application/octet-stream",
        // The verified asset is streamed to an atomic .part file. Caching the
        // same installer in Chromium would double disk writes and storage.
        "Cache-Control": "no-store",
        Pragma: "no-cache",
        "User-Agent": "shadow-ssh-desktop-updater"
      }
    });
    if (!response.ok) {
      throw new Error(`Update download failed: ${response.status} ${response.statusText}`);
    }
    if (!response.body) {
      throw new Error("Update download response has no body.");
    }
    const contentLength = parseContentLength(response.headers.get("content-length"));
    if (contentLength !== undefined && (contentLength > MAX_UPDATE_DOWNLOAD_BYTES || contentLength > asset.size)) {
      await response.body.cancel("Update response exceeded the expected size.").catch(() => undefined);
      throw new Error("Downloaded update is larger than the allowed limit or release metadata size.");
    }

    const digest = createHash("sha256");
    let downloadedBytes = 0;
    const handle = await open(temporaryPath, "wx");
    const reader = response.body.getReader();
    let responseCompleted = false;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          responseCompleted = true;
          break;
        }
        if (!value || value.byteLength === 0) {
          continue;
        }
        downloadedBytes += value.byteLength;
        if (downloadedBytes > MAX_UPDATE_DOWNLOAD_BYTES || downloadedBytes > asset.size) {
          await reader.cancel("Update exceeded the expected size.").catch(() => undefined);
          throw new Error("Downloaded update is larger than the allowed limit or release metadata size.");
        }
        const bytes = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
        digest.update(bytes);
        await writeAll(handle, bytes);
        options.onProgress?.(downloadedBytes, asset.size);
      }
    } finally {
      if (!responseCompleted) {
        await reader.cancel("Update download was interrupted.").catch(() => undefined);
      }
      await handle.close();
    }

    if (downloadedBytes !== asset.size) {
      throw new Error(`Downloaded update size ${downloadedBytes} does not match release metadata size ${asset.size}.`);
    }
    if (asset.digest) {
      const actual = `sha256:${digest.digest("hex")}`;
      if (actual.toLowerCase() !== asset.digest.toLowerCase()) {
        throw new Error("Downloaded update SHA-256 digest does not match the release metadata.");
      }
    }
    await rm(outputPath, { force: true });
    await rename(temporaryPath, outputPath);
    await removeSupersededUpdateFiles(downloadDirectory, path.basename(outputPath)).catch(() => undefined);
    return outputPath;
  } catch (error) {
    await rm(temporaryPath, { force: true }).catch(() => undefined);
    if (controller.signal.aborted) {
      throw new Error("Update download timed out.", { cause: error });
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

export function selectWindowsPortableAsset(release: GitHubRelease, version: string, arch: RuntimeArch): AppUpdateAsset | undefined {
  if (arch !== "x64" && arch !== "arm64") {
    return undefined;
  }
  const expected = `shadow-ssh-${version}-windows-portable-${arch}.exe`;
  const asset = release.assets?.find((candidate) => candidate.name === expected);
  if (
    !asset?.name ||
    !asset.browser_download_url ||
    !Number.isSafeInteger(asset.size) ||
    Number(asset.size) <= 0 ||
    Number(asset.size) > MAX_UPDATE_DOWNLOAD_BYTES
  ) {
    return undefined;
  }
  if (!asset.browser_download_url.startsWith(RELEASE_DOWNLOAD_PREFIX)) {
    return undefined;
  }
  return {
    name: asset.name,
    version,
    arch,
    size: Number(asset.size),
    digest: asset.digest,
    downloadUrl: asset.browser_download_url
  };
}

export function normalizeVersion(value: string): string | undefined {
  const cleaned = value.trim().replace(/^v/u, "");
  return /^\d+\.\d+\.\d+$/u.test(cleaned) ? cleaned : undefined;
}

export function compareSemver(left: string, right: string): number {
  const leftParts = left.split(".").map(Number);
  const rightParts = right.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) {
    const diff = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (diff !== 0) {
      return diff;
    }
  }
  return 0;
}

async function readLimitedText(response: Response, limit: number): Promise<string> {
  if (!response.body) {
    throw new Error("GitHub release response has no body.");
  }
  const contentLength = parseContentLength(response.headers.get("content-length"));
  if (contentLength !== undefined && contentLength > limit) {
    await response.body.cancel("GitHub release response exceeded its limit.").catch(() => undefined);
    throw new Error("GitHub release response is larger than the allowed limit.");
  }
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    if (!value || value.byteLength === 0) {
      continue;
    }
    totalBytes += value.byteLength;
    if (totalBytes > limit) {
      await reader.cancel("GitHub release response exceeded its limit.").catch(() => undefined);
      throw new Error("GitHub release response is larger than the allowed limit.");
    }
    chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
  }
  return Buffer.concat(chunks, totalBytes).toString("utf8");
}

function sanitizeFileName(value: string): string {
  return [...value]
    .map((character) => (character.charCodeAt(0) < 32 || '<>:"/\\|?*'.includes(character) ? "_" : character))
    .join("");
}

function parseContentLength(value: string | null): number | undefined {
  if (!value) {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined;
}

function normalizeTimeout(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) && Number(value) > 0 ? Number(value) : fallback;
}

async function writeAll(handle: FileHandle, bytes: Buffer): Promise<void> {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset);
    if (bytesWritten <= 0) {
      throw new Error("Unable to write downloaded update to disk.");
    }
    offset += bytesWritten;
  }
}

async function removeSupersededUpdateFiles(downloadDirectory: string, keepFileName: string): Promise<void> {
  const entries = await readdir(downloadDirectory, { withFileTypes: true });
  await Promise.all(entries.map(async (entry) => {
    if (!entry.isFile() || entry.name === keepFileName || !PORTABLE_UPDATE_FILE_PATTERN.test(entry.name)) {
      return;
    }
    await rm(path.join(downloadDirectory, entry.name), { force: true });
  }));
}
