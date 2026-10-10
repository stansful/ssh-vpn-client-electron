import path from "node:path";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import {
  createElevationCheck,
  detectTunEnvironment,
  detectWindowsElevation,
  isElevatedIntegrityLevel,
  type ElevationAnswer
} from "../src/main/platform/tun-environment.js";
import { wintunSearchDirectories } from "../src/service/tun-routing.js";

describe("TUN environment", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it("reports TUN as unsupported outside Windows without probing anything", async () => {
    let probed = false;
    const environment = await detectTunEnvironment({
      platform: "darwin",
      appDirectory: "/Applications/Shadow.app/Contents/MacOS",
      dataDirectory: "/Users/me/Library/Application Support/Shadow SSH",
      isElevated: async () => {
        probed = true;
        return true;
      }
    });

    expect(environment).toEqual({ supported: false, elevated: false, wintunFound: false, searchedPaths: [] });
    expect(probed).toBe(false);
  });

  // The list must be the helper's own: beside the service binary, then the
  // folders the transports pass in SHADOW_SSH_WINTUN_DIRS, in that order.
  it("searches where the native helper looks, in the helper's order", async () => {
    const environment = await detectTunEnvironment({
      platform: "win32",
      arch: "x64",
      appDirectory: "/apps/shadow",
      dataDirectory: "/data/shadow",
      resourcesPath: "/apps/shadow/resources",
      portableExecutableDirectory: "/downloads",
      isElevated: async () => false,
      fileExists: async () => false
    });

    expect(environment.searchedPaths).toEqual([
      path.join("/apps/shadow/resources", "native", "windows", "x64"),
      "/downloads",
      "/apps/shadow",
      "/data/shadow"
    ]);
    expect(environment.searchedPaths.slice(1)).toEqual(
      wintunSearchDirectories("/data/shadow", { portableExecutableDirectory: "/downloads", executableDirectory: "/apps/shadow" })
    );
    expect(environment).toMatchObject({ supported: true, elevated: false, wintunFound: false });
  });

  it("finds wintun.dll in the data folder", async () => {
    const dataDirectory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-tun-"));
    cleanupDirs.push(dataDirectory);
    await writeFile(path.join(dataDirectory, "wintun.dll"), "dll", "utf8");

    const environment = await detectTunEnvironment({
      platform: "win32",
      appDirectory: path.join(dataDirectory, "app"),
      dataDirectory,
      portableExecutableDirectory: "",
      isElevated: async () => true
    });

    expect(environment).toMatchObject({ supported: true, elevated: true, wintunFound: true });
    expect(environment.searchedPaths).toContain(dataDirectory);
  });

  it("lists a folder once even when it is named with different case", async () => {
    const environment = await detectTunEnvironment({
      platform: "win32",
      appDirectory: "C:/Users/Me/Shadow SSH",
      dataDirectory: "c:/users/me/shadow ssh",
      portableExecutableDirectory: "",
      isElevated: async () => false,
      fileExists: async () => false
    });

    expect(environment.searchedPaths).toEqual(["C:/Users/Me/Shadow SSH"]);
  });

  it("treats a failed elevation check as not elevated", async () => {
    const environment = await detectTunEnvironment({
      platform: "win32",
      appDirectory: "/apps/shadow",
      dataDirectory: "/data/shadow",
      portableExecutableDirectory: "",
      isElevated: async () => {
        throw new Error("whoami timed out");
      },
      fileExists: async () => false
    });

    expect(environment.elevated).toBe(false);
  });

  it("reads elevation from the integrity level, not from group names", () => {
    expect(isElevatedIntegrityLevel('"Mandatory Label\\High Mandatory Level","Label","S-1-16-12288",""')).toBe(true);
    expect(isElevatedIntegrityLevel('"Обязательная метка\\Высокий","Метка","S-1-16-12288",""')).toBe(true);
    expect(isElevatedIntegrityLevel('"Mandatory Label\\System Mandatory Level","Label","S-1-16-16384",""')).toBe(true);
    expect(
      isElevatedIntegrityLevel('"BUILTIN\\Administrators","Alias","S-1-5-32-544","Group used for deny only"\n"Mandatory Label\\Medium Mandatory Level","Label","S-1-16-8192",""')
    ).toBe(false);
  });

  it("answers elevation from whoami, then from net session's exit code", async () => {
    const elevated = await detectWindowsElevation(async () => '"Mandatory Label\\High Mandatory Level","Label","S-1-16-12288",""');
    expect(elevated).toEqual({ elevated: true, definite: true });

    const denied = await detectWindowsElevation(async (file) => {
      throw file.endsWith("whoami.exe")
        ? Object.assign(new Error("spawn whoami.exe EACCES"), { code: "EACCES" })
        : Object.assign(new Error("Command failed: net session"), { code: 2, killed: false, signal: null });
    });
    expect(denied).toEqual({ elevated: false, definite: true });
  });

  it("does not call a timeout or a tool that could not start an answer", async () => {
    const timedOut = await detectWindowsElevation(async () => {
      throw Object.assign(new Error("Command failed"), { code: null, killed: true, signal: "SIGTERM" });
    });
    expect(timedOut).toEqual({ elevated: false, definite: false });

    const blocked = await detectWindowsElevation(async () => {
      throw Object.assign(new Error("spawn EACCES"), { code: "EACCES" });
    });
    expect(blocked).toEqual({ elevated: false, definite: false });
  });

  it("keeps a definite elevation answer and asks again after an inconclusive one", async () => {
    const answers: ElevationAnswer[] = [
      { elevated: false, definite: false },
      { elevated: true, definite: true }
    ];
    let calls = 0;
    const isElevated = createElevationCheck(async () => answers[Math.min(calls++, answers.length - 1)] ?? { elevated: false, definite: false });

    expect(await isElevated()).toBe(false);
    expect(await isElevated()).toBe(true);
    expect(await isElevated()).toBe(true);
    expect(calls).toBe(2);
  });
});
