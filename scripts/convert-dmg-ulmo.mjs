import { execFileSync } from "node:child_process";
import { renameSync, rmSync } from "node:fs";

// electron-builder `afterAllArtifactBuild` hook. Its dmg.format only offers
// up to bzip2 (UDBZ); LZMA (ULMO) makes the DMG 15-21 MB smaller and needs
// macOS 10.15, below Electron's own minimum. If DMGs are ever signed or
// notarized, do it here after the conversion: rewriting the image drops a
// signature electron-builder put on it.

export default async function afterAllArtifactBuild(buildResult) {
  const dmgs = buildResult.artifactPaths.filter((artifactPath) => artifactPath.endsWith(".dmg"));
  if (dmgs.length === 0 || process.platform !== "darwin") {
    return [];
  }
  for (const dmg of dmgs) {
    const converted = dmg.replace(/\.dmg$/u, ".ulmo.dmg");
    execFileSync("hdiutil", ["convert", dmg, "-format", "ULMO", "-ov", "-quiet", "-o", converted], { stdio: "inherit" });
    execFileSync("hdiutil", ["verify", "-quiet", converted], { stdio: "inherit" });
    renameSync(converted, dmg);
    // The differential-update blockmap describes the bzip2 image.
    rmSync(`${dmg}.blockmap`, { force: true });
    console.log(`[after-all-artifact-build] Re-encoded ${dmg} as ULMO.`);
  }
  return [];
}
