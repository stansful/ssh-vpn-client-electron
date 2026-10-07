import os from "node:os";
import path from "node:path";

export function resolveUserDataPath(name: string, platform: NodeJS.Platform = process.platform, env = process.env): string {
  if (env.SHADOW_SSH_USER_DATA_DIR) {
    return env.SHADOW_SSH_USER_DATA_DIR;
  }
  if (platform === "win32") {
    const appData = env.APPDATA || path.join(os.homedir(), "AppData", "Roaming");
    return path.join(appData, name);
  }
  if (platform === "darwin") {
    return path.join(os.homedir(), "Library", "Application Support", name);
  }
  const configHome = env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
  return path.join(configHome, name);
}

/** Where everything lives inside the app's data folder. */
export interface AppDataLayout {
  dataDirectory: string;
  storageDirectory: string;
  storePath: string;
  logDirectory: string;
  mainLogPath: string;
  routingDirectory: string;
  xrayRuntimeDirectory: string;
  updatesDirectory: string;
}

export function resolveAppDataLayout(dataDirectory: string): AppDataLayout {
  const storageDirectory = path.join(dataDirectory, "storage");
  const logDirectory = path.join(dataDirectory, "logs");
  return {
    dataDirectory,
    storageDirectory,
    storePath: path.join(storageDirectory, "app-store.v1.json"),
    logDirectory,
    mainLogPath: path.join(logDirectory, "main.log"),
    routingDirectory: path.join(dataDirectory, "routing"),
    xrayRuntimeDirectory: path.join(dataDirectory, "xray"),
    updatesDirectory: path.join(dataDirectory, "updates")
  };
}

export function resolveXrayExecutablePath({
  packaged,
  resourcesPath,
  projectRoot,
  platform = process.platform,
  arch = process.arch,
  env = process.env
}: {
  packaged: boolean;
  resourcesPath: string;
  projectRoot: string;
  platform?: NodeJS.Platform;
  arch?: string;
  env?: NodeJS.ProcessEnv;
}): string | undefined {
  if (env.SHADOW_SSH_XRAY_PATH) {
    return env.SHADOW_SSH_XRAY_PATH;
  }
  const platformFolder = xrayPlatformFolder(platform);
  if (!platformFolder) {
    return undefined;
  }
  const executableName = platform === "win32" ? "xray.exe" : "xray";
  const baseDirectory = packaged ? resourcesPath : path.join(projectRoot, "resources");
  return path.join(baseDirectory, "xray", platformFolder, arch, executableName);
}

function xrayPlatformFolder(platform: NodeJS.Platform): string | undefined {
  if (platform === "win32") {
    return "windows";
  }
  if (platform === "darwin") {
    return "macos";
  }
  if (platform === "linux") {
    return "linux";
  }
  return undefined;
}
