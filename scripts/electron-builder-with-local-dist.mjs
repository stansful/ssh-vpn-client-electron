import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
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

  // Wintun is checked here rather than left to a warning during the native
  // build, because a Windows bundle without it is not visibly broken: the app
  // connects and falls back to the Windows proxy path, where UDP never enters
  // the tunnel and process rules cannot reach applications that ignore the
  // proxy setting.
  if (platformFlag === "--win") {
    const wintunPath = path.join(root, "native", "windows", arch, "wintun.dll");
    if (!existsSync(wintunPath) || statSync(wintunPath).size === 0) {
      console.error([
        `[electron-builder] wintun.dll is missing at ${path.relative(root, wintunPath)}.`,
        "The packaged app would have no TUN routing: UDP would never enter the tunnel",
        "and process rules would not reach applications that ignore the Windows proxy setting.",
        "Run `npm run wintun:download` before packaging Windows artifacts."
      ].join("\n"));
      process.exit(1);
    }
  }
}

const builderCli = path.join(root, "node_modules", "electron-builder", "cli.js");
const builderEnvironment = {
  ...process.env,
  ELECTRON_BUILDER_CACHE: process.env.ELECTRON_BUILDER_CACHE || path.join(root, ".cache", "electron-builder")
};
if (platformFlag === "--linux" && process.platform !== "win32" && !builderEnvironment.APPIMAGE_TOOLS_PATH) {
  const toolsPath = prepareAppImageTools(builderEnvironment.ELECTRON_BUILDER_CACHE);
  if (toolsPath) {
    builderEnvironment.APPIMAGE_TOOLS_PATH = toolsPath;
  }
}
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

/**
 * electron-builder squashes AppImages with zstd at mksquashfs' default level
 * (15) and 128 KiB blocks and has no option for either. It does take its tools
 * from APPIMAGE_TOOLS_PATH and always passes `-comp zstd` last, so a wrapper
 * that appends the level and block size makes the AppImage ~10 MB smaller.
 * The cached tools are bash dispatchers that resolve their own directory,
 * hence exec wrappers rather than symlinks.
 */
function prepareAppImageTools(builderCache) {
  const version = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")).build?.toolsets?.appimage;
  const toolsetRoot = path.join(builderCache, `appimage@${version}`);
  const toolsName = existsSync(toolsetRoot)
    ? readdirSync(toolsetRoot).find(
      (name) => name.startsWith("appimage-tools-runtime-") && !name.endsWith(".state") && isCompleteExtraction(path.join(toolsetRoot, `${name}.state`))
    )
    : undefined;
  if (!version || !toolsName) {
    console.warn("[electron-builder] AppImage tools are not cached yet; this AppImage uses the default zstd level and block size.");
    return null;
  }
  const realTools = path.join(toolsetRoot, toolsName);
  const wrapperTools = path.join(root, ".cache", "appimage-tools-zstd19");
  // electron-builder refuses an APPIMAGE_TOOLS_PATH with shell metacharacters.
  if (/[;&|`$<>"'\\]/u.test(wrapperTools)) {
    console.warn("[electron-builder] The checkout path has shell metacharacters; this AppImage uses the default zstd level and block size.");
    return null;
  }
  rmSync(wrapperTools, { recursive: true, force: true });
  mkdirSync(wrapperTools, { recursive: true });
  const writeWrapper = (tool, script) => {
    const wrapperPath = path.join(wrapperTools, tool);
    writeFileSync(wrapperPath, `#!/usr/bin/env bash\n${script}\n`);
    chmodSync(wrapperPath, 0o755);
  };
  const mksquashfs = shellQuote(path.join(realTools, "mksquashfs"));
  writeWrapper(
    "mksquashfs",
    `case " $* " in\n  *" -comp zstd "*) exec ${mksquashfs} "$@" -Xcompression-level 19 -b 1M ;;\nesac\nexec ${mksquashfs} "$@"`
  );
  writeWrapper("desktop-file-validate", `exec ${shellQuote(path.join(realTools, "desktop-file-validate"))} "$@"`);
  symlinkSync(path.join(realTools, "runtimes"), path.join(wrapperTools, "runtimes"));
  symlinkSync(path.join(realTools, "lib"), path.join(wrapperTools, "lib"));
  return wrapperTools;
}

function isCompleteExtraction(stateFile) {
  try {
    return JSON.parse(readFileSync(stateFile, "utf8")).state === "complete";
  } catch {
    return false;
  }
}

function shellQuote(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

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
