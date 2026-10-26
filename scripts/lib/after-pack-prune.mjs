import { rm, stat } from "node:fs/promises";
import path from "node:path";

// electron-builder `afterPack` hook. It runs after extraResources are copied
// and before fuses and signing, so a signed bundle never changes afterwards.
//
// - default_app.asar, version: electron-builder only cleans the Electron
//   runtime it unpacks itself, and we pack from a local electronDist.
// - dxcompiler.dll, dxil.dll: the DXC shader compiler for WebGPU on D3D12.
//   The app uses neither; Dawn falls back to FXC without them.
// - SwiftShader and the Vulkan loader: the software GPU fallback for machines
//   without a usable GPU (VMs, RDP, blocklisted drivers). Removed only with
//   SHADOW_SSH_PRUNE_SWIFTSHADER=1 until a GPU-less smoke test passes.

const MAC_LIBRARIES = "Frameworks/Electron Framework.framework/Versions/A/Libraries";

const RUNTIME_FILES = {
  win32: {
    always: ["resources/default_app.asar", "version", "dxcompiler.dll", "dxil.dll"],
    gpuFallback: ["vk_swiftshader.dll", "vk_swiftshader_icd.json", "vulkan-1.dll"]
  },
  linux: {
    always: ["resources/default_app.asar", "version"],
    gpuFallback: ["libvk_swiftshader.so", "vk_swiftshader_icd.json", "libvulkan.so.1"]
  },
  darwin: {
    always: ["Resources/default_app.asar"],
    gpuFallback: [`${MAC_LIBRARIES}/libvk_swiftshader.dylib`, `${MAC_LIBRARIES}/vk_swiftshader_icd.json`]
  }
};

export function shouldPruneGpuFallback(env = process.env) {
  return env.SHADOW_SSH_PRUNE_SWIFTSHADER === "1";
}

/** Paths relative to the bundle root: the app directory, or `<App>.app/Contents` on macOS. */
export function prunedRuntimeFiles(platform, { gpuFallback = shouldPruneGpuFallback() } = {}) {
  const files = RUNTIME_FILES[platform];
  if (!files) {
    return [];
  }
  return gpuFallback ? [...files.always, ...files.gpuFallback] : [...files.always];
}

export default async function afterPack(context) {
  const platform = context.electronPlatformName;
  const bundleRoot = platform === "darwin"
    ? path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`, "Contents")
    : context.appOutDir;
  let removedBytes = 0;
  for (const relativePath of prunedRuntimeFiles(platform)) {
    const filePath = path.join(bundleRoot, relativePath);
    let size;
    try {
      ({ size } = await stat(filePath));
    } catch (error) {
      if (error.code === "ENOENT") {
        continue;
      }
      throw error;
    }
    await rm(filePath, { force: true });
    removedBytes += size;
  }
  console.log(`[after-pack] Pruned ${(removedBytes / 1e6).toFixed(1)} MB of unused Electron runtime from ${platform}.`);
}
