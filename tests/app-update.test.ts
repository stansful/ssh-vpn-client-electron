import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  checkGitHubAppUpdate,
  compareSemver,
  describeUpdateFile,
  downloadUpdateAsset,
  normalizeVersion,
  resolveUpdateFormat,
  selectUpdateAsset,
  updateAssetFileName
} from "../src/core/update/github-app-update.js";
import { AppUpdateController } from "../src/main/app/app-update-controller.js";
import { createDefaultStore } from "../src/shared/defaults.js";
import type { AppStorage } from "../src/main/storage/app-storage.js";
import type { AppSettings, AppStore, AppUpdateAsset, AppUpdateFormat, PlatformTarget } from "../src/shared/types.js";

const RELEASE_DOWNLOAD = "https://github.com/stansful/ssh-vpn-client-electron/releases/download/2.4.0/";
/** The asset names of the real 2.4.0 release. */
const RELEASE_2_4_0_ASSETS = [
  "shadow-ssh-2.4.0-linux-package-amd64.deb",
  "shadow-ssh-2.4.0-linux-package-arm64.deb",
  "shadow-ssh-2.4.0-linux-portable-arm64.AppImage",
  "shadow-ssh-2.4.0-linux-portable-x86_64.AppImage",
  "shadow-ssh-2.4.0-macos-dmg-arm64.dmg",
  "shadow-ssh-2.4.0-macos-dmg-x64.dmg",
  "shadow-ssh-2.4.0-windows-portable-arm64.exe",
  "shadow-ssh-2.4.0-windows-portable-x64.exe"
].map((name, index) => ({ name, size: 1000 + index, digest: `sha256:${index}`, browser_download_url: `${RELEASE_DOWNLOAD}${name}` }));

describe("app update metadata", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    vi.unstubAllGlobals();
    await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it("selects the matching Windows portable asset by version and architecture", () => {
    const asset = selectUpdateAsset(
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
      "windows-portable",
      "x64"
    );

    expect(asset).toMatchObject({
      name: "shadow-ssh-0.2.0-windows-portable-x64.exe",
      arch: "x64",
      format: "windows-portable",
      size: 20,
      digest: "sha256:def"
    });
  });

  it.each<[AppUpdateFormat, "x64" | "arm64", string]>([
    ["windows-portable", "x64", "shadow-ssh-2.4.0-windows-portable-x64.exe"],
    ["windows-portable", "arm64", "shadow-ssh-2.4.0-windows-portable-arm64.exe"],
    ["macos-dmg", "x64", "shadow-ssh-2.4.0-macos-dmg-x64.dmg"],
    ["macos-dmg", "arm64", "shadow-ssh-2.4.0-macos-dmg-arm64.dmg"],
    ["linux-appimage", "x64", "shadow-ssh-2.4.0-linux-portable-x86_64.AppImage"],
    ["linux-appimage", "arm64", "shadow-ssh-2.4.0-linux-portable-arm64.AppImage"],
    ["linux-deb", "x64", "shadow-ssh-2.4.0-linux-package-amd64.deb"],
    ["linux-deb", "arm64", "shadow-ssh-2.4.0-linux-package-arm64.deb"]
  ])("selects the %s %s file of a real release", (format, arch, name) => {
    const asset = selectUpdateAsset({ tag_name: "2.4.0", assets: RELEASE_2_4_0_ASSETS }, "2.4.0", format, arch);

    expect(asset).toMatchObject({ name, version: "2.4.0", arch, format, downloadUrl: `${RELEASE_DOWNLOAD}${name}` });
  });

  it("offers nothing for an architecture the release doesn't build", () => {
    expect(selectUpdateAsset({ tag_name: "2.4.0", assets: RELEASE_2_4_0_ASSETS }, "2.4.0", "macos-dmg", "ia32")).toBeUndefined();
    expect(selectUpdateAsset({ tag_name: "2.4.0", assets: RELEASE_2_4_0_ASSETS }, "2.4.0", "linux-deb", "unknown")).toBeUndefined();
  });

  it("matches the update format to the running build", () => {
    const resolve = (platform: PlatformTarget["platform"], env: Record<string, string> = {}, execPath = "/opt/Shadow/shadow-ssh-desktop") =>
      resolveUpdateFormat({ platform, execPath, env });

    expect(resolve("windows")).toBe("windows-portable");
    expect(resolve("macos")).toBe("macos-dmg");
    expect(resolve("unknown")).toBeUndefined();
    expect(resolve("linux")).toBe("linux-deb");
    expect(resolve("linux", { APPIMAGE: "/home/alex/Shadow.AppImage", APPDIR: "/tmp/.mount_ShadowAbC" }, "/tmp/.mount_ShadowAbC/shadow-ssh-desktop")).toBe(
      "linux-appimage"
    );
    expect(resolve("linux", { APPIMAGE: "/home/alex/Shadow.AppImage" }, "/tmp/.mount_ShadowAbC/shadow-ssh-desktop")).toBe("linux-appimage");
    // A .deb build started from another AppImage inherits that AppImage's variables.
    expect(resolve("linux", { APPIMAGE: "/home/alex/Other.AppImage", APPDIR: "/tmp/.mount_OtherXyZ" })).toBe("linux-deb");
    expect(resolve("linux", { APPIMAGE: "/home/alex/Other.AppImage", APPDIR: "/tmp/.mount_Other" }, "/tmp/.mount_OtherXyZ/shadow-ssh-desktop")).toBe(
      "linux-deb"
    );
  });

  it("recognizes an AppImage whose mount point isn't spelled canonically", () => {
    const execPath = "/var/home/alex/tmp/.mount_ShadowAbC/shadow-ssh-desktop";
    const env = (APPDIR: string) => ({ APPIMAGE: "/var/home/alex/Shadow.AppImage", APPDIR });
    // The runtime builds APPDIR from TMPDIR verbatim; execPath comes from /proc/self/exe.
    const realpath = (value: string) => value.replace(/^\/home\//u, "/var/home/");

    expect(resolveUpdateFormat({ platform: "linux", execPath, env: env("/var/home/alex/tmp//.mount_ShadowAbC"), realpath })).toBe("linux-appimage");
    expect(resolveUpdateFormat({ platform: "linux", execPath, env: env("/var/home/alex/tmp/.mount_ShadowAbC/"), realpath })).toBe("linux-appimage");
    expect(resolveUpdateFormat({ platform: "linux", execPath, env: env("/home/alex/tmp/.mount_ShadowAbC"), realpath })).toBe("linux-appimage");
    expect(resolveUpdateFormat({ platform: "linux", execPath, env: env("/home/alex/tmp/.mount_Other"), realpath })).toBe("linux-deb");
    expect(
      resolveUpdateFormat({
        platform: "linux",
        execPath,
        env: env("/home/alex/tmp/.mount_ShadowAbC"),
        realpath: () => {
          throw new Error("ENOENT");
        }
      })
    ).toBe("linux-deb");
  });

  it("recognizes an extracted AppImage by the AppRun beside its executable", () => {
    const fileExists = (value: string) => value === "/home/alex/squashfs-root/AppRun";

    expect(resolveUpdateFormat({ platform: "linux", execPath: "/home/alex/squashfs-root/shadow-ssh-desktop", env: {}, fileExists })).toBe("linux-appimage");
    expect(resolveUpdateFormat({ platform: "linux", execPath: "/opt/Shadow/shadow-ssh-desktop", env: {}, fileExists })).toBe("linux-deb");
  });

  it("names the missing file for each format", () => {
    expect(describeUpdateFile("windows-portable", "arm64")).toBe("Windows arm64 portable EXE");
    expect(describeUpdateFile("macos-dmg", "x64")).toBe("macOS x64 DMG");
    expect(describeUpdateFile("linux-appimage", "x64")).toBe("Linux x64 AppImage");
    expect(describeUpdateFile("linux-deb", "arm64")).toBe("Linux arm64 .deb package");
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

  it("marks a downloaded AppImage executable and replaces earlier downloads of any format", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const bytes = Buffer.from("appimage bytes");
    const asset = createAsset(bytes, "linux-appimage");
    for (const name of [
      "shadow-ssh-0.4.0-linux-portable-x86_64.AppImage",
      "shadow-ssh-0.4.0-linux-package-amd64.deb",
      "shadow-ssh-0.4.0-macos-dmg-arm64.dmg",
      "notes.AppImage"
    ]) {
      await writeFile(path.join(directory, name), "old", "utf8");
    }

    const filePath = await downloadUpdateAsset(asset, directory, { fetchImpl: vi.fn(async () => new Response(bytes, { status: 200 })) });

    expect(path.basename(filePath)).toBe("shadow-ssh-0.5.0-linux-portable-x86_64.AppImage");
    if (process.platform !== "win32") {
      expect((await stat(filePath)).mode & 0o777).toBe(0o755);
    }
    expect((await readdir(directory)).sort()).toEqual(["notes.AppImage", asset.name].sort());
  });

  it("clears partial files an interrupted download left behind", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const bytes = Buffer.from("dmg bytes");
    const asset = createAsset(bytes, "macos-dmg");
    const abandoned = "shadow-ssh-0.4.0-linux-portable-x86_64.AppImage.999.0b3c9a52-1d1e-4f7a-9a2b-3c4d5e6f7a8b.part";
    await writeFile(path.join(directory, abandoned), "partial", "utf8");
    await writeFile(path.join(directory, "notes.part"), "unrelated", "utf8");

    await downloadUpdateAsset(asset, directory, { fetchImpl: vi.fn(async () => new Response(bytes, { status: 200 })) });

    expect((await readdir(directory)).sort()).toEqual(["notes.part", asset.name].sort());
  });

  it("leaves a downloaded DMG or .deb without the execute bit", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const bytes = Buffer.from("dmg bytes");
    const asset = createAsset(bytes, "macos-dmg");

    const filePath = await downloadUpdateAsset(asset, directory, { fetchImpl: vi.fn(async () => new Response(bytes, { status: 200 })) });

    expect(path.basename(filePath)).toBe("shadow-ssh-0.5.0-macos-dmg-x64.dmg");
    if (process.platform !== "win32") {
      expect((await stat(filePath)).mode & 0o111).toBe(0);
    }
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
    const controller = new AppUpdateController(directory, (download) => downloads.push(download.state), fetchMock);
    const storage = createSettingsStorageStub();
    await controller.check({
      currentVersion: "0.4.0",
      arch: "x64" as const,
      buildArch: "x64" as const,
      format: "windows-portable",
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
    const controller = new AppUpdateController(
      directory,
      (download) => notifications.push({ state: download.state, downloadedBytes: download.downloadedBytes }),
      fetchMock
    );
    const storage = createSettingsStorageStub();
    await controller.check({
      currentVersion: "0.4.0",
      arch: "x64" as const,
      buildArch: "x64" as const,
      format: "windows-portable",
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
    const controller = new AppUpdateController(directory, undefined, fetchMock);
    const storage = createSettingsStorageStub();
    const options = {
      currentVersion: "0.4.0",
      arch: "x64" as const,
      buildArch: "x64" as const,
      format: "windows-portable" as const,
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
    const controller = new AppUpdateController(directory, undefined, fetchMock);

    const info = await controller.check({
      currentVersion: "0.4.0",
      arch: "x64" as const,
      buildArch: "x64" as const,
      format: "windows-portable",
      storage,
      force: false
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(info.available).toBe(true);
    expect(info.asset?.name).toBe(asset.name);
  });

  it("offers the DMG on macOS and the .deb to a Linux package install", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const release = JSON.stringify({ tag_name: "2.4.0", html_url: "https://github.com/stansful/ssh-vpn-client-electron/releases/tag/2.4.0", assets: RELEASE_2_4_0_ASSETS });
    const fetchMock = vi.fn(async () => new Response(release, { status: 200 }));
    const controller = new AppUpdateController(directory, undefined, fetchMock);

    const mac = await controller.check({ currentVersion: "2.3.0", arch: "arm64", buildArch: "arm64", format: "macos-dmg", storage: createSettingsStorageStub(), force: true });
    expect(mac).toMatchObject({ available: true, format: "macos-dmg", message: "Update 2.4.0 is available for macOS arm64." });
    expect(mac.asset?.name).toBe("shadow-ssh-2.4.0-macos-dmg-arm64.dmg");

    const deb = await controller.check({ currentVersion: "2.3.0", arch: "x64", buildArch: "x64", format: "linux-deb", storage: createSettingsStorageStub(), force: true });
    expect(deb.asset?.name).toBe("shadow-ssh-2.4.0-linux-package-amd64.deb");

    const ia32 = await controller.check({ currentVersion: "2.3.0", arch: "ia32", buildArch: "ia32", format: "linux-appimage", storage: createSettingsStorageStub(), force: true });
    expect(ia32).toMatchObject({ available: false, latestVersion: "2.4.0", format: "linux-appimage" });
    expect(ia32.message).toBe("Update 2.4.0 is available, but no Linux ia32 AppImage was found.");
  });

  it("moves an x64 build running translated on an arm64 machine to the arm64 file", async () => {
    const release = (assets: typeof RELEASE_2_4_0_ASSETS) => JSON.stringify({ tag_name: "2.4.0", assets });
    const check = async (assets: typeof RELEASE_2_4_0_ASSETS, format: AppUpdateFormat) => {
      const controller = new AppUpdateController(await makeTempDir(cleanupDirs), undefined, vi.fn(async () => new Response(release(assets), { status: 200 })));
      return controller.check({ currentVersion: "2.3.0", format, arch: "arm64", buildArch: "x64", storage: createSettingsStorageStub(), force: true });
    };

    const rosetta = await check(RELEASE_2_4_0_ASSETS, "macos-dmg");
    expect(rosetta.asset).toMatchObject({ name: "shadow-ssh-2.4.0-macos-dmg-arm64.dmg", arch: "arm64" });
    expect(rosetta.message).toBe("Update 2.4.0 is available for macOS arm64.");
    expect((await check(RELEASE_2_4_0_ASSETS, "windows-portable")).asset?.name).toBe("shadow-ssh-2.4.0-windows-portable-arm64.exe");

    // A release without the arm64 file still updates the x64 build in place.
    const withoutArm = RELEASE_2_4_0_ASSETS.filter((asset) => !asset.name.includes("arm64"));
    expect((await check(withoutArm, "macos-dmg")).asset).toMatchObject({ name: "shadow-ssh-2.4.0-macos-dmg-x64.dmg", arch: "x64" });
  });

  it("doesn't ask GitHub where in-app updates aren't offered", async () => {
    const fetchMock = vi.fn();
    const controller = new AppUpdateController(await makeTempDir(cleanupDirs), undefined, fetchMock);

    const info = await controller.check({ currentVersion: "2.3.0", arch: "x64", buildArch: "x64", format: undefined, storage: createSettingsStorageStub(), force: true });

    expect(info).toMatchObject({ available: false, message: "In-app updates aren’t available on this system." });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("bounds and times out release metadata reads", async () => {
    const oversizedFetch = vi.fn(async () => new Response(Buffer.alloc(1024 * 1024 + 1), { status: 200 }));
    await expect(checkGitHubAppUpdate({ currentVersion: "0.4.0", format: "windows-portable", arch: "x64", fetchImpl: oversizedFetch })).rejects.toThrow("larger than the allowed limit");

    const hangingFetch = vi.fn(async (_url: string, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
      })
    );
    await expect(checkGitHubAppUpdate({ currentVersion: "0.4.0", format: "windows-portable", arch: "x64", timeoutMs: 5, fetchImpl: hangingFetch })).rejects.toThrow("timed out");
  });
});

function createAsset(bytes: Buffer, format: AppUpdateFormat = "windows-portable"): AppUpdateAsset {
  const name = updateAssetFileName("0.5.0", format, "x64");
  return {
    name,
    version: "0.5.0",
    arch: "x64",
    format,
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
