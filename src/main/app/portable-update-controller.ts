import { checkGitHubAppUpdate, downloadUpdateAsset } from "../../core/update/github-app-update.js";
import type { AppStorage } from "../storage/app-storage.js";
import type { AppUpdateDownload, AppUpdateInfo, PlatformTarget } from "../../shared/types.js";

export class PortableUpdateController {
  private updateInfo: AppUpdateInfo | undefined;
  private updateDownload: AppUpdateDownload = { state: "idle", downloadedBytes: 0 };

  constructor(private readonly downloadDirectory: string) {}

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
    if (platformTarget.platform !== "windows") {
      this.updateInfo = {
        available: false,
        currentVersion,
        checkedAt: new Date().toISOString(),
        message: "Portable auto-update currently targets Windows x64/arm64 assets."
      };
      return this.updateInfo;
    }

    const settings = storage.getStore().settings;
    const result = await checkGitHubAppUpdate({
      currentVersion,
      arch: platformTarget.arch,
      eTag: settings.updateCheckCache?.eTag,
      force
    });
    this.updateInfo = result.info;
    await storage.updateSettings({
      ...storage.getStore().settings,
      updateCheckCache: {
        checkedAt: this.updateInfo.checkedAt,
        eTag: result.eTag ?? settings.updateCheckCache?.eTag,
        latestVersion: this.updateInfo.latestVersion ?? settings.updateCheckCache?.latestVersion
      }
    });
    return this.updateInfo;
  }

  async downloadSelected(): Promise<void> {
    const asset = this.updateInfo?.asset;
    if (!asset) {
      throw new Error("No downloadable update asset is selected. Check for updates first.");
    }
    this.updateDownload = {
      state: "downloading",
      downloadedBytes: 0,
      totalBytes: asset.size,
      percent: 0,
      message: `Downloading ${asset.name}.`
    };
    try {
      const filePath = await downloadUpdateAsset(asset, this.downloadDirectory);
      this.updateDownload = {
        state: "downloaded",
        downloadedBytes: asset.size,
        totalBytes: asset.size,
        percent: 100,
        filePath,
        message: `Downloaded ${asset.name}.`
      };
    } catch (error) {
      this.updateDownload = {
        state: "error",
        downloadedBytes: 0,
        totalBytes: asset.size,
        message: error instanceof Error ? error.message : String(error)
      };
      throw error;
    }
  }
}
