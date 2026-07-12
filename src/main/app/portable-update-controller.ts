import { checkGitHubAppUpdate, downloadUpdateAsset } from "../../core/update/github-app-update.js";
import type { AppStorage } from "../storage/app-storage.js";
import type { FetchImplementation } from "../../shared/http-fetch.js";
import type { AppUpdateDownload, AppUpdateInfo, PlatformTarget } from "../../shared/types.js";

const PROGRESS_NOTIFICATION_INTERVAL_MS = 250;

export class PortableUpdateController {
  private updateInfo: AppUpdateInfo | undefined;
  private updateDownload: AppUpdateDownload = { state: "idle", downloadedBytes: 0 };
  private activeDownload: Promise<void> | undefined;
  private activeCheck: Promise<AppUpdateInfo> | undefined;
  private lastProgressNotificationAt = 0;

  constructor(
    private readonly downloadDirectory: string,
    private readonly onDownloadChanged?: (download: AppUpdateDownload) => void,
    private readonly fetchImpl: FetchImplementation = globalThis.fetch
  ) {}

  get info(): AppUpdateInfo | undefined {
    return this.updateInfo;
  }

  get download(): AppUpdateDownload {
    return structuredClone(this.updateDownload);
  }

  async check({
    currentVersion,
    platformTarget,
    storage,
    force
  }: {
    currentVersion: string;
    platformTarget: PlatformTarget;
    storage: AppStorage;
    force: boolean;
  }): Promise<AppUpdateInfo> {
    if (this.activeCheck) {
      return this.activeCheck;
    }
    const operation = this.performCheck({ currentVersion, platformTarget, storage, force });
    this.activeCheck = operation;
    try {
      return await operation;
    } finally {
      if (this.activeCheck === operation) {
        this.activeCheck = undefined;
      }
    }
  }

  private async performCheck({
    currentVersion,
    platformTarget,
    storage,
    force
  }: {
    currentVersion: string;
    platformTarget: PlatformTarget;
    storage: AppStorage;
    force: boolean;
  }): Promise<AppUpdateInfo> {
    if (this.activeDownload) {
      await this.activeDownload;
    }
    if (platformTarget.platform !== "windows") {
      this.updateInfo = {
        available: false,
        currentVersion,
        checkedAt: new Date().toISOString(),
        message: "Portable auto-update currently targets Windows x64/arm64 assets."
      };
      return this.updateInfo;
    }

    const settings = storage.getSettings();
    let result = await checkGitHubAppUpdate({
      currentVersion,
      arch: platformTarget.arch,
      eTag: settings.updateCheckCache?.eTag,
      force,
      fetchImpl: this.fetchImpl
    });
    if (result.notModified && !this.updateInfo) {
      // An ETag survives app restarts, while the selected/validated asset was
      // previously memory-only. Re-fetch once without the condition instead
      // of turning a still-available update into `available: false` on 304.
      result = await checkGitHubAppUpdate({
        currentVersion,
        arch: platformTarget.arch,
        force: true,
        fetchImpl: this.fetchImpl
      });
    }
    const previousAsset = this.updateInfo?.asset;
    this.updateInfo = result.notModified && this.updateInfo
      ? {
          ...this.updateInfo,
          currentVersion,
          checkedAt: result.info.checkedAt
        }
      : result.info;
    if (assetIdentity(previousAsset) !== assetIdentity(this.updateInfo.asset) && this.updateDownload.state !== "idle") {
      this.setDownload({ state: "idle", downloadedBytes: 0 });
    }
    await storage.updateSettings({
      updateCheckCache: {
        checkedAt: this.updateInfo.checkedAt,
        eTag: result.eTag ?? settings.updateCheckCache?.eTag,
        latestVersion: this.updateInfo.latestVersion ?? settings.updateCheckCache?.latestVersion
      }
    });
    return this.updateInfo;
  }

  async downloadSelected(): Promise<void> {
    if (this.activeCheck) {
      await this.activeCheck;
    }
    if (this.activeDownload) {
      return this.activeDownload;
    }
    const operation = this.performDownload();
    this.activeDownload = operation;
    try {
      await operation;
    } finally {
      if (this.activeDownload === operation) {
        this.activeDownload = undefined;
      }
    }
  }

  private async performDownload(): Promise<void> {
    const asset = this.updateInfo?.asset;
    if (!asset) {
      throw new Error("No downloadable update asset is selected. Check for updates first.");
    }
    this.setDownload({
      state: "downloading",
      downloadedBytes: 0,
      totalBytes: asset.size,
      percent: 0,
      message: `Downloading ${asset.name}.`
    });
    this.lastProgressNotificationAt = Date.now();
    try {
      const filePath = await downloadUpdateAsset(asset, this.downloadDirectory, {
        onProgress: (downloadedBytes, totalBytes) => this.updateProgress(downloadedBytes, totalBytes, asset.name),
        fetchImpl: this.fetchImpl
      });
      this.setDownload({
        state: "downloaded",
        downloadedBytes: asset.size,
        totalBytes: asset.size,
        percent: 100,
        filePath,
        message: `Downloaded ${asset.name}.`
      });
    } catch (error) {
      this.setDownload({
        state: "error",
        downloadedBytes: this.updateDownload.downloadedBytes,
        totalBytes: asset.size,
        message: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  private updateProgress(downloadedBytes: number, totalBytes: number, assetName: string): void {
    const now = Date.now();
    const notificationDue = now - this.lastProgressNotificationAt >= PROGRESS_NOTIFICATION_INTERVAL_MS || downloadedBytes === totalBytes;
    if (!notificationDue) {
      // Keep error/snapshot byte counts current without allocating a new
      // progress object and message for every network stream chunk.
      this.updateDownload.downloadedBytes = downloadedBytes;
      this.updateDownload.totalBytes = totalBytes;
      this.updateDownload.percent = totalBytes > 0 ? Math.min(100, (downloadedBytes / totalBytes) * 100) : undefined;
      return;
    }
    const percent = totalBytes > 0 ? Math.min(100, (downloadedBytes / totalBytes) * 100) : undefined;
    this.updateDownload = {
      state: "downloading",
      downloadedBytes,
      totalBytes,
      percent,
      message: percent === undefined ? `Downloading ${assetName}.` : `Downloading ${assetName}: ${Math.round(percent)}%.`
    };
    this.lastProgressNotificationAt = now;
    this.notifyDownloadChanged();
  }

  private setDownload(download: AppUpdateDownload): void {
    this.updateDownload = download;
    this.notifyDownloadChanged();
  }

  private notifyDownloadChanged(): void {
    this.onDownloadChanged?.(this.download);
  }
}

function assetIdentity(asset: AppUpdateInfo["asset"]): string | undefined {
  return asset ? `${asset.version}:${asset.arch}:${asset.name}:${asset.digest ?? ""}` : undefined;
}
