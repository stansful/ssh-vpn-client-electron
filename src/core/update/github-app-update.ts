import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type { AppUpdateAsset, AppUpdateInfo, RuntimeArch } from "../../shared/types.js";

const RELEASE_API_URL = "https://api.github.com/repos/stansful/ssh-vpn-client-electron/releases/latest";
const RELEASE_DOWNLOAD_PREFIX = "https://github.com/stansful/ssh-vpn-client-electron/releases/download/";
const MAX_RELEASE_RESPONSE_BYTES = 1024 * 1024;
const MAX_UPDATE_DOWNLOAD_BYTES = 160 * 1024 * 1024;

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
}

export interface CheckAppUpdateResult {
  info: AppUpdateInfo;
  eTag?: string;
  notModified: boolean;
}

export async function checkGitHubAppUpdate(options: CheckAppUpdateOptions): Promise<CheckAppUpdateResult> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "shadow-ssh-desktop-updater",
    "X-GitHub-Api-Version": "2026-03-10"
  };
  if (options.eTag && !options.force) {
    headers["If-None-Match"] = options.eTag;
  }

  const response = await fetch(RELEASE_API_URL, { headers });
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

export async function downloadUpdateAsset(asset: AppUpdateAsset, downloadDirectory: string): Promise<string> {
  if (!asset.downloadUrl.startsWith(RELEASE_DOWNLOAD_PREFIX)) {
    throw new Error("Refusing to download update from an untrusted URL.");
  }
  if (asset.size > MAX_UPDATE_DOWNLOAD_BYTES) {
    throw new Error("Update asset is larger than the allowed download limit.");
  }
  const response = await fetch(asset.downloadUrl, {
    headers: {
      Accept: "application/octet-stream",
      "User-Agent": "shadow-ssh-desktop-updater"
    }
  });
  if (!response.ok) {
    throw new Error(`Update download failed: ${response.status} ${response.statusText}`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > MAX_UPDATE_DOWNLOAD_BYTES) {
    throw new Error("Downloaded update is larger than the allowed limit.");
  }
  if (asset.digest) {
    const actual = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    if (actual.toLowerCase() !== asset.digest.toLowerCase()) {
      throw new Error("Downloaded update SHA-256 digest does not match the release metadata.");
    }
  }
  await mkdir(downloadDirectory, { recursive: true });
  const outputPath = path.join(downloadDirectory, sanitizeFileName(asset.name));
  await writeFile(outputPath, bytes);
  return outputPath;
}

export function selectWindowsPortableAsset(release: GitHubRelease, version: string, arch: RuntimeArch): AppUpdateAsset | undefined {
  if (arch !== "x64" && arch !== "arm64") {
    return undefined;
  }
  const expected = `shadow-ssh-${version}-windows-portable-${arch}.exe`;
  const asset = release.assets?.find((candidate) => candidate.name === expected);
  if (!asset?.name || !asset.browser_download_url || !Number.isFinite(asset.size)) {
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
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > limit) {
    throw new Error("GitHub release response is larger than the allowed limit.");
  }
  return text;
}

function sanitizeFileName(value: string): string {
  return [...value]
    .map((character) => (character.charCodeAt(0) < 32 || '<>:"/\\|?*'.includes(character) ? "_" : character))
    .join("");
}
