import { existsSync } from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

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

const args = process.argv.slice(2);
const platformFlag = args.find((arg) => platformMap.has(arg));
const archFlag = args.find((arg) => arg === "--x64" || arg === "--arm64");
const hasElectronDist = args.some((arg) => arg === "--config.electronDist" || arg.startsWith("--config.electronDist="));
const builderArgs = [...args];

if (!hasElectronDist && platformFlag && archFlag) {
  const platform = platformMap.get(platformFlag);
  const arch = archFlag.slice(2);
  const electronDist = path.join(".cache", `electron-${platform}-${arch}`);
  if (existsSync(electronDist)) {
    builderArgs.push(`--config.electronDist=${electronDist}`);
  } else {
    console.warn(`[electron-builder] Local Electron runtime not found at ${electronDist}; electron-builder may download it.`);
  }
}

if (platformFlag && archFlag) {
  const xrayPlatform = xrayPlatformMap.get(platformFlag);
  const arch = archFlag.slice(2);
  const executableName = platformFlag === "--win" ? "xray.exe" : "xray";
  const runtimePath = path.join("resources", "xray", xrayPlatform, arch, executableName);
  if (!existsSync(runtimePath)) {
    console.error([
      `[electron-builder] Xray runtime is missing at ${runtimePath}.`,
      "The packaged Xray transport would fail at runtime without it.",
      platformFlag === "--win"
        ? "Run `npm run xray:download-win` before building Windows portable artifacts."
        : "Run `npm run xray:download-all` or `npm run xray:download -- --target <platform>/<arch>` before packaging."
    ].join("\n"));
    process.exit(1);
  }
}

const builderBin = path.join(process.cwd(), "node_modules", ".bin", process.platform === "win32" ? "electron-builder.cmd" : "electron-builder");
const child = spawn(builderBin, builderArgs, { stdio: "inherit", shell: false });

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
