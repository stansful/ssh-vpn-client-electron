import { existsSync } from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const platformMap = new Map([
  ["--win", "win32"],
  ["--mac", "darwin"],
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

const builderBin = path.join(process.cwd(), "node_modules", ".bin", process.platform === "win32" ? "electron-builder.cmd" : "electron-builder");
const child = spawn(builderBin, builderArgs, { stdio: "inherit", shell: false });

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
