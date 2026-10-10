import { createHash, randomUUID } from "node:crypto";
import { chmod, mkdir, open, readdir, rename, rm } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";
import type { FetchImplementation } from "../../shared/http-fetch.js";
import type { AppUpdateAsset, AppUpdateFormat, AppUpdateInfo, DesktopPlatform, RuntimeArch } from "../../shared/types.js";

const RELEASE_API_URL = "https://api.github.com/repos/stansful/ssh-vpn-client-electron/releases/latest";
const RELEASE_DOWNLOAD_PREFIX = "https://github.com/stansful/ssh-vpn-client-electron/releases/download/";
const MAX_RELEASE_RESPONSE_BYTES = 1024 * 1024;
const MAX_UPDATE_DOWNLOAD_BYTES = 160 * 1024 * 1024;
const UPDATE_CHECK_TIMEOUT_MS = 30 * 1000;
const UPDATE_DOWNLOAD_TIMEOUT_MS = 10 * 60 * 1000;
/**
 * Every release file this updater downloads, named by the `artifactName`
 * settings in package.json. electron-builder spells x64 as x86_64 for an
 * AppImage and as amd64 for a .deb.
 */
const UPDATE_FILE_PATTERN =
  /^shadow-ssh-\d+\.\d+\.\d+-(?:windows-portable-(?:x64|arm64)\.exe|macos-dmg-(?:x64|arm64)\.dmg|linux-portable-(?:x86_64|arm64)\.AppImage|linux-package-(?:amd64|arm64)\.deb)$/u;
/** `<release file>.<pid>.<uuid>.part`, left behind when the app quit or crashed mid-download. */
const UPDATE_PART_PATTERN = new RegExp(`${UPDATE_FILE_PATTERN.source.slice(0, -1)}\\.\\d+\\.[0-9a-f-]{36}\\.part$`, "u");

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
  format: AppUpdateFormat;
  /** The architecture to offer first: the machine's own, even for a translated x64 build. */
  arch: RuntimeArch;
  /** Offered when the release has no file for `arch`: the running build's own architecture. */
  fallbackArch?: RuntimeArch;
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
        format: options.format,
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

  const asset =
    selectUpdateAsset(release, latestVersion, options.format, options.arch) ??
    (options.fallbackArch && options.fallbackArch !== options.arch
      ? selectUpdateAsset(release, latestVersion, options.format, options.fallbackArch)
      : undefined);
  const comparison = compareSemver(latestVersion, normalizeVersion(options.currentVersion) ?? options.currentVersion);
  if (comparison <= 0) {
    return {
      eTag,
      notModified: false,
      info: {
        available: false,
        currentVersion: options.currentVersion,
        format: options.format,
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
        format: options.format,
        latestVersion,
        releaseUrl: release.html_url,
        publishedAt: release.published_at,
        checkedAt,
        message: `Update ${latestVersion} is available, but no ${describeUpdateFile(options.format, options.arch)} was found.`
      }
    };
  }

  return {
    eTag,
    notModified: false,
    info: {
      available: true,
      currentVersion: options.currentVersion,
      format: options.format,
      latestVersion,
      releaseUrl: release.html_url,
      publishedAt: release.published_at,
      asset,
      checkedAt,
      message: `Update ${latestVersion} is available for ${UPDATE_FORMAT_OS[asset.format]} ${asset.arch}.`
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
  // Downloads run one at a time in a single app instance, so any partial file
  // already here is abandoned; freeing it first also makes room for this one.
  await removeMatchingFiles(downloadDirectory, (name) => UPDATE_PART_PATTERN.test(name)).catch(() => undefined);
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
    if (asset.format === "linux-appimage") {
      // An AppImage runs only with the execute bit, which a download lacks.
      await chmod(temporaryPath, 0o755);
    }
    await rm(outputPath, { force: true });
    await rename(temporaryPath, outputPath);
    const keepFileName = path.basename(outputPath);
    await removeMatchingFiles(downloadDirectory, (name) => name !== keepFileName && UPDATE_FILE_PATTERN.test(name)).catch(() => undefined);
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

const UPDATE_FORMAT_OS: Record<AppUpdateFormat, string> = {
  "windows-portable": "Windows",
  "macos-dmg": "macOS",
  "linux-appimage": "Linux",
  "linux-deb": "Linux"
};

/**
 * The release file kind that replaces this build. On Linux the AppImage
 * runtime exports APPIMAGE (and APPDIR, its mount point) to the app it
 * mounted. A .deb build launched from some other AppImage inherits both, but
 * its execPath then lies outside that APPDIR. APPDIR is built from TMPDIR
 * verbatim, so it is compared canonically: execPath always is canonical.
 * An AppImage extracted and started through its AppRun exports nothing, but
 * AppRun still sits beside the executable, which a .deb install never has.
 */
export function resolveUpdateFormat(input: {
  platform: DesktopPlatform;
  execPath: string;
  env: Record<string, string | undefined>;
  realpath?: (value: string) => string;
  fileExists?: (value: string) => boolean;
}): AppUpdateFormat | undefined {
  switch (input.platform) {
    case "windows":
      return "windows-portable";
    case "macos":
      return "macos-dmg";
    case "linux": {
      const { APPIMAGE: appImage, APPDIR: appDir } = input.env;
      if (input.fileExists?.(path.posix.join(path.posix.dirname(input.execPath), "AppRun"))) {
        return "linux-appimage";
      }
      if (!appImage) {
        return "linux-deb";
      }
      if (!appDir) {
        return "linux-appimage";
      }
      const canonical = (value: string): string => {
        const resolved = path.posix.resolve(value);
        try {
          return input.realpath?.(resolved) ?? resolved;
        } catch {
          return resolved;
        }
      };
      const relative = path.posix.relative(canonical(appDir), canonical(input.execPath));
      const insideAppDir = relative !== "" && !relative.startsWith("../") && relative !== ".." && !path.posix.isAbsolute(relative);
      return insideAppDir ? "linux-appimage" : "linux-deb";
    }
    default:
      return undefined;
  }
}

/** The release file name for one version, format and architecture. */
export function updateAssetFileName(version: string, format: AppUpdateFormat, arch: Extract<RuntimeArch, "x64" | "arm64">): string {
  switch (format) {
    case "windows-portable":
      return `shadow-ssh-${version}-windows-portable-${arch}.exe`;
    case "macos-dmg":
      return `shadow-ssh-${version}-macos-dmg-${arch}.dmg`;
    case "linux-appimage":
      return `shadow-ssh-${version}-linux-portable-${arch === "x64" ? "x86_64" : "arm64"}.AppImage`;
    case "linux-deb":
      return `shadow-ssh-${version}-linux-package-${arch === "x64" ? "amd64" : "arm64"}.deb`;
  }
}

/** "Windows x64 portable EXE", "macOS arm64 DMG", "Linux x64 AppImage", "Linux arm64 .deb package". */
export function describeUpdateFile(format: AppUpdateFormat, arch: RuntimeArch): string {
  const target = `${UPDATE_FORMAT_OS[format]} ${arch}`;
  switch (format) {
    case "windows-portable":
      return `${target} portable EXE`;
    case "macos-dmg":
      return `${target} DMG`;
    case "linux-appimage":
      return `${target} AppImage`;
    case "linux-deb":
      return `${target} .deb package`;
  }
}

export function selectUpdateAsset(
  release: GitHubRelease,
  version: string,
  format: AppUpdateFormat,
  arch: RuntimeArch
): AppUpdateAsset | undefined {
  if (arch !== "x64" && arch !== "arm64") {
    return undefined;
  }
  const expected = updateAssetFileName(version, format, arch);
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
    format,
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

async function removeMatchingFiles(downloadDirectory: string, matches: (name: string) => boolean): Promise<void> {
  const entries = await readdir(downloadDirectory, { withFileTypes: true });
  await Promise.all(entries.map(async (entry) => {
    if (!entry.isFile() || !matches(entry.name)) {
      return;
    }
    await rm(path.join(downloadDirectory, entry.name), { force: true });
  }));
}
