import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const expectedElectronVersion = JSON.parse(
  readFileSync(path.join(root, "node_modules", "electron", "package.json"), "utf8")
).version;

const platformMap = new Map([
  ["--win", "win32"],
  ["--mac", "darwin"],
  ["--linux", "linux"]
]);
const xrayPlatformMap = new Map([
  ["--win", "windows"],
  ["--mac", "macos"],
  ["--linux", "linux"]
]);
const shadowDevBuildFlag = "--shadow-dev-build";

const args = process.argv.slice(2);
const platformFlag = args.find((arg) => platformMap.has(arg));
const archFlag = args.find((arg) => arg === "--x64" || arg === "--arm64");
const hasElectronDist = args.some((arg) => arg === "--config.electronDist" || arg.startsWith("--config.electronDist="));
const isShadowDevBuild = args.includes(shadowDevBuildFlag);
const builderArgs = args.filter((arg) => arg !== shadowDevBuildFlag);

if (isShadowDevBuild) {
  builderArgs.push("--config.productName=Shadow SSH Dev");
  builderArgs.push("--config.portable.artifactName=shadow-ssh-dev-${version}-windows-portable-${arch}.${ext}");
}

if (!hasElectronDist && platformFlag && archFlag) {
  const platform = platformMap.get(platformFlag);
  const arch = archFlag.slice(2);
  const cachedElectronDist = path.join(root, ".cache", `electron-${platform}-${arch}`);
  const installedElectronDist = path.join(root, "node_modules", "electron", "dist");
  if (hasExpectedElectronVersion(cachedElectronDist)) {
    builderArgs.push(`--config.electronDist=${cachedElectronDist}`);
  } else if (platform === process.platform && arch === process.arch && hasExpectedElectronVersion(installedElectronDist)) {
    builderArgs.push(`--config.electronDist=${installedElectronDist}`);
  } else {
    console.warn(`[electron-builder] Local Electron runtime not found for ${platform}/${arch}; electron-builder may download it.`);
  }
}

if (platformFlag && archFlag) {
  const xrayPlatform = xrayPlatformMap.get(platformFlag);
  const arch = archFlag.slice(2);
  const executableName = platformFlag === "--win" ? "xray.exe" : "xray";
  const runtimePath = path.join(root, "resources", "xray", xrayPlatform, arch, executableName);
  if (!existsSync(runtimePath)) {
    console.error([
      `[electron-builder] Xray runtime is missing at ${path.relative(root, runtimePath)}.`,
      "The packaged Xray transport would fail at runtime without it.",
      platformFlag === "--win"
        ? "Run `npm run xray:download-win` before building Windows portable artifacts."
        : "Run `npm run xray:download-all` or `npm run xray:download -- --target <platform>/<arch>` before packaging."
    ].join("\n"));
    process.exit(1);
  }
}

const builderCli = path.join(root, "node_modules", "electron-builder", "cli.js");
const builderEnvironment = {
  ...process.env,
  ELECTRON_BUILDER_CACHE: process.env.ELECTRON_BUILDER_CACHE || path.join(root, ".cache", "electron-builder")
};
const child = spawn(process.execPath, [builderCli, ...builderArgs], {
  cwd: root,
  env: builderEnvironment,
  stdio: "inherit",
  shell: false
});

child.on("error", (error) => {
  console.error(`[electron-builder] Unable to start: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});

function hasExpectedElectronVersion(electronDist) {
  if (!existsSync(electronDist)) {
    return false;
  }
  try {
    return readFileSync(path.join(electronDist, "version"), "utf8").trim() === expectedElectronVersion;
  } catch {
    return false;
  }
}
