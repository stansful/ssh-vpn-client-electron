import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { checkGitHubAppUpdate, compareSemver, downloadUpdateAsset, normalizeVersion, selectWindowsPortableAsset } from "../src/core/update/github-app-update.js";
import { PortableUpdateController } from "../src/main/app/portable-update-controller.js";
import { createDefaultStore } from "../src/shared/defaults.js";
import type { AppStorage } from "../src/main/storage/app-storage.js";
import type { AppSettings, AppStore, AppUpdateAsset } from "../src/shared/types.js";

describe("portable app update metadata", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    vi.unstubAllGlobals();
    await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it("selects the matching Windows portable asset by version and architecture", () => {
    const asset = selectWindowsPortableAsset(
      {
        tag_name: "0.2.0",
        assets: [
          {
            name: "shadow-ssh-0.2.0-windows-portable-arm64.exe",
            size: 10,
            digest: "sha256:abc",
            browser_download_url: "https://github.com/stansful/ssh-vpn-client-electron/releases/download/0.2.0/shadow-ssh-0.2.0-windows-portable-arm64.exe"
          },
          {
            name: "shadow-ssh-0.2.0-windows-portable-x64.exe",
            size: 20,
            digest: "sha256:def",
            browser_download_url: "https://github.com/stansful/ssh-vpn-client-electron/releases/download/0.2.0/shadow-ssh-0.2.0-windows-portable-x64.exe"
          }
        ]
      },
      "0.2.0",
      "x64"
    );

    expect(asset).toMatchObject({
      name: "shadow-ssh-0.2.0-windows-portable-x64.exe",
      arch: "x64",
      size: 20,
      digest: "sha256:def"
    });
  });

  it("normalizes strict SemVer tags and compares versions", () => {
    expect(normalizeVersion("v1.2.3")).toBe("1.2.3");
    expect(normalizeVersion("1.2")).toBeUndefined();
    expect(compareSemver("1.3.0", "1.2.9")).toBeGreaterThan(0);
    expect(compareSemver("1.2.0", "1.2.0")).toBe(0);
  });

  it("streams an update to disk while hashing and reporting progress", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const bytes = Buffer.alloc(512 * 1024, 0x5a);
    const asset = createAsset(bytes);
    const progress: number[] = [];
    await writeFile(path.join(directory, "shadow-ssh-0.4.0-windows-portable-x64.exe"), "old", "utf8");
    await writeFile(path.join(directory, "keep.txt"), "unrelated", "utf8");
    const fetchImpl = vi.fn(async (input: string, init?: RequestInit) => {
      void input;
      void init;
      return new Response(bytes, {
        status: 200,
        headers: { "content-length": String(bytes.length) }
      });
    });

    const filePath = await downloadUpdateAsset(asset, directory, {
      onProgress: (downloadedBytes) => progress.push(downloadedBytes),
      fetchImpl
    });

    expect(await readFile(filePath)).toEqual(bytes);
    expect(new Headers(fetchImpl.mock.calls[0]?.[1]?.headers).get("cache-control")).toBe("no-store");
    expect(progress.at(-1)).toBe(bytes.length);
    expect((await readdir(directory)).some((name) => name.endsWith(".part"))).toBe(false);
    expect((await readdir(directory)).sort()).toEqual(["keep.txt", asset.name].sort());
  });

  it("removes partial files when streamed digest verification fails", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const bytes = Buffer.from("untrusted update bytes");
    const asset = { ...createAsset(bytes), digest: `sha256:${"0".repeat(64)}` };
    const fetchImpl = vi.fn(async () => new Response(bytes, { status: 200 }));

    await expect(downloadUpdateAsset(asset, directory, { fetchImpl })).rejects.toThrow("digest does not match");

    expect(await readdir(directory)).toEqual([]);
  });

  it("coalesces concurrent update downloads into one network request", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const bytes = Buffer.alloc(64 * 1024, 0x2a);
    const asset = createAsset(bytes);
    const release = {
      tag_name: "0.5.0",
      html_url: "https://github.com/stansful/ssh-vpn-client-electron/releases/tag/0.5.0",
      assets: [{
        name: asset.name,
        size: asset.size,
        digest: asset.digest,
        browser_download_url: asset.downloadUrl
      }]
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(release), { status: 200 }))
      .mockResolvedValueOnce(new Response(bytes, { status: 200 }));
    const downloads: string[] = [];
    const controller = new PortableUpdateController(directory, (download) => downloads.push(download.state), fetchMock);
    const storage = createSettingsStorageStub();
    await controller.check({
      currentVersion: "0.4.0",
      platformTarget: {
        platform: "windows",
        arch: "x64",
        serviceExecutableName: "shadow-ssh-service.exe",
        serviceRelativePath: "native/windows/x64/shadow-ssh-service.exe",
        supportsPrivilegedService: true
      },
      storage,
      force: true
    });

    await Promise.all([controller.downloadSelected(), controller.downloadSelected()]);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(controller.download.state).toBe("downloaded");
    expect(downloads.at(-1)).toBe("downloaded");
  });

  it("coalesces bursty download chunks into bounded renderer progress notifications", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const bytes = Buffer.alloc(128 * 1024, 0x3c);
    const asset = createAsset(bytes);
    const release = {
      tag_name: asset.version,
      assets: [{
        name: asset.name,
        size: asset.size,
        digest: asset.digest,
        browser_download_url: asset.downloadUrl
      }]
    };
    const body = new ReadableStream<Uint8Array>({
      start(stream) {
        for (let offset = 0; offset < bytes.length; offset += 1024) {
          stream.enqueue(bytes.subarray(offset, offset + 1024));
        }
        stream.close();
      }
    });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(release), { status: 200 }))
      .mockResolvedValueOnce(new Response(body, { status: 200 }));
    const notifications: Array<{ state: string; downloadedBytes: number }> = [];
    const controller = new PortableUpdateController(
      directory,
      (download) => notifications.push({ state: download.state, downloadedBytes: download.downloadedBytes }),
      fetchMock
    );
    const storage = createSettingsStorageStub();
    await controller.check({
      currentVersion: "0.4.0",
      platformTarget: {
        platform: "windows",
        arch: "x64",
        serviceExecutableName: "shadow-ssh-service.exe",
        serviceRelativePath: "native/windows/x64/shadow-ssh-service.exe",
        supportsPrivilegedService: true
      },
      storage,
      force: true
    });

    await controller.downloadSelected();

    expect(notifications).toEqual([
      { state: "downloading", downloadedBytes: 0 },
      { state: "downloading", downloadedBytes: bytes.length },
      { state: "downloaded", downloadedBytes: bytes.length }
    ]);
  });

  it("coalesces concurrent update checks into one metadata request", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const bytes = Buffer.from("release");
    const asset = createAsset(bytes);
    let resolveFetch!: (response: Response) => void;
    const fetchMock = vi.fn(() => new Promise<Response>((resolve) => {
      resolveFetch = resolve;
    }));
    const controller = new PortableUpdateController(directory, undefined, fetchMock);
    const storage = createSettingsStorageStub();
    const options = {
      currentVersion: "0.4.0",
      platformTarget: {
        platform: "windows" as const,
        arch: "x64" as const,
        serviceExecutableName: "shadow-ssh-service.exe",
        serviceRelativePath: "native/windows/x64/shadow-ssh-service.exe",
        supportsPrivilegedService: true
      },
      storage,
      force: true
    };
    const first = controller.check(options);
    const second = controller.check(options);
    resolveFetch(new Response(JSON.stringify({
      tag_name: "0.5.0",
      assets: [{
        name: asset.name,
        size: asset.size,
        digest: asset.digest,
        browser_download_url: asset.downloadUrl
      }]
    }), { status: 200 }));

    await expect(Promise.all([first, second])).resolves.toHaveLength(2);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("unconditionally refreshes after a restart-time 304 so an available asset is not hidden", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const bytes = Buffer.from("release");
    const asset = createAsset(bytes);
    const release = {
      tag_name: "0.5.0",
      html_url: "https://github.com/stansful/ssh-vpn-client-electron/releases/tag/0.5.0",
      assets: [{
        name: asset.name,
        size: asset.size,
        digest: asset.digest,
        browser_download_url: asset.downloadUrl
      }]
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(null, { status: 304, headers: { etag: "cached" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify(release), { status: 200, headers: { etag: "fresh" } }));
    const storage = createSettingsStorageStub();
    await storage.updateSettings({ updateCheckCache: { checkedAt: new Date(0).toISOString(), eTag: "cached" } });
    const controller = new PortableUpdateController(directory, undefined, fetchMock);

    const info = await controller.check({
      currentVersion: "0.4.0",
      platformTarget: {
        platform: "windows",
        arch: "x64",
        serviceExecutableName: "shadow-ssh-service.exe",
        serviceRelativePath: "native/windows/x64/shadow-ssh-service.exe",
        supportsPrivilegedService: true
      },
      storage,
      force: false
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(info.available).toBe(true);
    expect(info.asset?.name).toBe(asset.name);
  });

  it("bounds and times out release metadata reads", async () => {
    const oversizedFetch = vi.fn(async () => new Response(Buffer.alloc(1024 * 1024 + 1), { status: 200 }));
    await expect(checkGitHubAppUpdate({ currentVersion: "0.4.0", arch: "x64", fetchImpl: oversizedFetch })).rejects.toThrow("larger than the allowed limit");

    const hangingFetch = vi.fn(async (_url: string, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
      })
    );
    await expect(checkGitHubAppUpdate({ currentVersion: "0.4.0", arch: "x64", timeoutMs: 5, fetchImpl: hangingFetch })).rejects.toThrow("timed out");
  });
});

function createAsset(bytes: Buffer): AppUpdateAsset {
  const name = "shadow-ssh-0.5.0-windows-portable-x64.exe";
  return {
    name,
    version: "0.5.0",
    arch: "x64",
    size: bytes.length,
    digest: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
    downloadUrl: `https://github.com/stansful/ssh-vpn-client-electron/releases/download/0.5.0/${name}`
  };
}

async function makeTempDir(cleanupDirs: string[]): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-update-"));
  cleanupDirs.push(directory);
  return directory;
}

function createSettingsStorageStub(): AppStorage {
  let store = createDefaultStore();
  return {
    getStore: () => structuredClone(store),
    getSettings: () => structuredClone(store.settings),
    updateSettings: async (patch: Partial<AppSettings>) => {
      store = { ...store, settings: { ...store.settings, ...patch } };
      return structuredClone(store) as AppStore;
    }
  } as unknown as AppStorage;
}
