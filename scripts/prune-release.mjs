import { readFileSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Runs after verify-production-artifacts.mjs, which still needs the unpacked
// bundles to check the architecture of the embedded service and Xray runtime.
// Everything except the distributable packages is removed afterwards:
// unpacked folders, builder debug/config dumps, update metadata (*.yml) and
// differential-update blockmaps.

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { version } = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
const releaseDirectory = path.join(root, "release");
const escapedVersion = version.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
const distributablePattern = new RegExp(
  `^shadow-ssh-${escapedVersion}-(?:windows-portable-[a-z0-9_]+\\.exe|macos-dmg-[a-z0-9_]+\\.dmg|linux-portable-[a-z0-9_]+\\.AppImage|linux-package-[a-z0-9_]+\\.deb)$`,
  "u"
);

let entries;
try {
  entries = readdirSync(releaseDirectory, { withFileTypes: true });
} catch (error) {
  console.error(`[release] Unable to read release/: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}

const kept = [];
for (const entry of entries) {
  if (entry.isFile() && distributablePattern.test(entry.name)) {
    kept.push(entry.name);
    continue;
  }
  rmSync(path.join(releaseDirectory, entry.name), { recursive: true, force: true });
}

if (kept.length === 0) {
  console.error("[release] No distributable packages left in release/.");
  process.exit(1);
}

console.log(`[release] Kept ${kept.length} distributable package(s):`);
for (const name of kept.sort()) {
  console.log(`  ${name}`);
}
