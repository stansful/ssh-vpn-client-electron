import { spawnSync } from "node:child_process";
import path from "node:path";

// macOS half of the Electron fuses (`build.electronFuses` in package.json).
//
// @electron/fuses' resetAdHocDarwinSignature re-signs the whole bundle with
// `codesign --deep`, which seals Info.plist and app.asar into the main
// executable's signature. Its code hash then changes with every release, and
// the "Shadow SSH Safe Storage" Keychain entry - whose access list names that
// hash, for a bundle with no Developer ID - asks again after every update,
// before the window opens. Left alone, the main executable keeps Electron's
// own linker signature, which is the same for every release on one Electron
// version.
//
// The fuse wire lives in Electron Framework, not in the main executable, so
// the fuses are flipped here and only that framework is re-signed ad hoc:
// all an arm64 Mac needs to load the flipped binary. electron-builder flips
// the fuses again after this hook, with resetAdHocDarwinSignature off: the
// same values give the same bytes, so the signature made here still holds.

export const MAC_FUSE_FRAMEWORK = path.join("Contents", "Frameworks", "Electron Framework.framework");

/**
 * Flips a macOS bundle's fuses and re-signs Electron Framework alone. Does
 * nothing for other platforms. `run` and `platform` are seams for tests.
 */
export async function flipMacFusesKeepingSignature(context, { run = spawnSync, platform = process.platform } = {}) {
  if (context.electronPlatformName !== "darwin") {
    return;
  }
  const fuses = context.packager.config.electronFuses;
  if (!fuses) {
    return;
  }
  if (fuses.resetAdHocDarwinSignature) {
    throw new Error(
      "build.electronFuses.resetAdHocDarwinSignature must be false: the afterPack hook re-signs Electron Framework itself, and a re-signed bundle changes its Keychain identity with every release."
    );
  }
  if (platform !== "darwin") {
    throw new Error("macOS bundles are packed on macOS: the flipped Electron Framework has to be re-signed with codesign.");
  }
  const framework = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`, MAC_FUSE_FRAMEWORK);
  // Electron ships its x64 macOS build unsigned (only the arm64 linker signs
  // ad hoc). An unsigned framework has no signature to invalidate, and
  // codesign refuses to sign it without --deep because its helpers are
  // unsigned too, so it is flipped and left unsigned like the rest of the bundle.
  const probe = run("codesign", ["--display", framework], { encoding: "utf8" });
  if (probe.error) {
    throw probe.error;
  }
  const probeStderr = String(probe.stderr ?? "").trim();
  const unsigned = probe.status !== 0 && /code object is not signed at all/u.test(probeStderr);
  if (probe.status !== 0 && !unsigned) {
    throw new Error(`codesign --display ${framework} failed with status ${probe.status}: ${probeStderr}`);
  }
  await context.packager.addElectronFuses(context, await context.packager.generateFuseConfig(fuses));
  if (unsigned) {
    console.log(`[after-pack] Flipped the Electron fuses; ${MAC_FUSE_FRAMEWORK} is unsigned in this Electron build, so nothing is re-signed.`);
    return;
  }
  const result = run(
    "codesign",
    ["--sign", "-", "--force", "--preserve-metadata=entitlements,requirements,flags,runtime", framework],
    { encoding: "utf8" }
  );
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`Ad-hoc codesign of ${framework} failed with status ${result.status}: ${String(result.stderr ?? "").trim()}`);
  }
  console.log(`[after-pack] Flipped the Electron fuses and re-signed only ${MAC_FUSE_FRAMEWORK}; the main executable keeps its signature.`);
}
