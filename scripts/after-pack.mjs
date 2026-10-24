import pruneElectronRuntime from "./after-pack-prune.mjs";
import { flipMacFusesKeepingSignature } from "./mac-fuses.mjs";

// electron-builder `afterPack` hook: drops the parts of the Electron runtime
// the app does not use (after-pack-prune.mjs), then, on macOS, flips the fuses
// with only Electron Framework re-signed (mac-fuses.mjs). Pruning comes first,
// so the framework's new signature covers what is left of it.
export default async function afterPack(context) {
  await pruneElectronRuntime(context);
  await flipMacFusesKeepingSignature(context);
}
