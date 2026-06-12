import { existsSync } from "node:fs";
import path from "node:path";
import type { DesktopPlatform, PlatformTarget, RuntimeArch } from "../../shared/types.js";

export function detectDesktopPlatform(rawPlatform = process.platform): DesktopPlatform {
  if (rawPlatform === "win32") {
    return "windows";
  }
  if (rawPlatform === "darwin") {
    return "macos";
  }
  if (rawPlatform === "linux") {
    return "linux";
  }
  return "unknown";
}

export function detectRuntimeArch(rawArch = process.arch): RuntimeArch {
  if (rawArch === "x64" || rawArch === "arm64" || rawArch === "ia32") {
    return rawArch;
  }
  return "unknown";
}

export function createPlatformTarget(rawPlatform = process.platform, rawArch = process.arch): PlatformTarget {
  const platform = detectDesktopPlatform(rawPlatform);
  const arch = detectRuntimeArch(rawArch);
  const serviceExecutableName = platform === "windows" ? "shadow-ssh-service.exe" : "shadow-ssh-service";
  const serviceRelativePath = path.join("native", platform, arch, serviceExecutableName);

  return {
    platform,
    arch,
    serviceExecutableName,
    serviceRelativePath,
    supportsPrivilegedService: platform !== "unknown" && arch !== "unknown"
  };
}

export function resolveNativeServicePath(projectRoot: string, target: PlatformTarget): string {
  return path.join(projectRoot, target.serviceRelativePath);
}

export function nativeServiceExists(projectRoot: string, target: PlatformTarget): boolean {
  return target.supportsPrivilegedService && existsSync(resolveNativeServicePath(projectRoot, target));
}
