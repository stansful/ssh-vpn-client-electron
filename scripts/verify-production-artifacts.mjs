import {
  closeSync,
  existsSync,
  fstatSync,
  openSync,
  readFileSync,
  readSync,
  statSync
} from "node:fs";
import { Buffer } from "node:buffer";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageMetadata = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));

let options;
try {
  options = parseOptions(process.argv.slice(2));
} catch (error) {
  console.error(`[release] ${toErrorMessage(error)}`);
  printUsage();
  process.exit(1);
}

if (options.help) {
  printUsage();
  process.exit(0);
}

const releaseDirectory = options.releaseDirectory ?? path.join(root, "release");
const targets = createTargets(packageMetadata.version).filter((target) => options.platforms.has(target.platform));

if (options.plan) {
  console.log(`Expected production targets (${targets.length}):`);
  for (const target of targets) {
    console.log(`[${target.platform}] ${target.label} -> ${target.output}`);
  }
  process.exit(0);
}

console.log(`[release] Verifying ${targets.length} production targets in ${displayPath(releaseDirectory)}.`);
const failures = [];

for (const target of targets) {
  try {
    target.verify(releaseDirectory);
    console.log(`  OK  ${target.label}`);
  } catch (error) {
    failures.push({ target, error });
    console.error(`  ERR ${target.label}: ${toErrorMessage(error)}`);
  }
}

if (failures.length > 0) {
  console.error(`[release] Incomplete production release: ${failures.length}/${targets.length} target(s) failed verification.`);
  process.exit(1);
}

console.log(`[release] Complete production release: ${targets.length}/${targets.length} targets verified.`);

function createTargets(version) {
  const targets = [];

  for (const arch of ["x64", "arm64"]) {
    const unpackedDirectory = arch === "x64" ? "win-unpacked" : "win-arm64-unpacked";
    targets.push({
      platform: "win",
      label: `Windows ${arch} unpacked`,
      output: `${unpackedDirectory}/Shadow SSH.exe`,
      verify: (releaseRoot) => verifyWindowsBundle(releaseRoot, unpackedDirectory, arch)
    });
    targets.push(createPackageTarget({
      platform: "win",
      label: `Windows ${arch} portable EXE`,
      output: `shadow-ssh-${version}-windows-portable-${arch}.exe`,
      format: "pe"
    }));
    targets.push(createPackageTarget({
      platform: "win",
      label: `Windows ${arch} NSIS installer`,
      output: `shadow-ssh-${version}-windows-installer-${arch}.exe`,
      format: "pe"
    }));
  }

  for (const arch of ["x64", "arm64"]) {
    const unpackedDirectory = arch === "x64" ? "mac" : "mac-arm64";
    targets.push({
      platform: "mac",
      label: `macOS ${arch} application`,
      output: `${unpackedDirectory}/Shadow SSH.app`,
      verify: (releaseRoot) => verifyMacBundle(releaseRoot, unpackedDirectory, arch)
    });
    targets.push(createPackageTarget({
      platform: "mac",
      label: `macOS ${arch} DMG`,
      output: `shadow-ssh-${version}-macos-dmg-${arch}.dmg`,
      format: "dmg"
    }));
  }

  for (const arch of ["x64", "arm64"]) {
    const unpackedDirectory = arch === "x64" ? "linux-unpacked" : "linux-arm64-unpacked";
    const artifactArch = arch === "x64" ? "x86_64" : "arm64";
    targets.push({
      platform: "linux",
      label: `Linux ${arch} AppImage`,
      output: `shadow-ssh-${version}-linux-portable-${artifactArch}.AppImage`,
      verify: (releaseRoot) => {
        const artifactPath = path.join(releaseRoot, `shadow-ssh-${version}-linux-portable-${artifactArch}.AppImage`);
        verifyBinaryPackage(artifactPath, "elf");
        verifyArchitecture(artifactPath, arch);
        verifyLinuxBundle(releaseRoot, unpackedDirectory, arch);
      }
    });
    targets.push(createPackageTarget({
      platform: "linux",
      label: `Linux ${arch} DEB package`,
      output: `shadow-ssh-${version}-linux-package-${arch === "x64" ? "amd64" : "arm64"}.deb`,
      format: "deb"
    }));
  }

  return targets;
}

function createPackageTarget({ platform, label, output, format }) {
  return {
    platform,
    label,
    output,
    verify: (releaseRoot) => verifyBinaryPackage(path.join(releaseRoot, output), format)
  };
}

function verifyWindowsBundle(releaseRoot, unpackedDirectory, arch) {
  const bundleRoot = path.join(releaseRoot, unpackedDirectory);
  verifyArchitecture(path.join(bundleRoot, "Shadow SSH.exe"), arch);
  requireFile(path.join(bundleRoot, "resources", "app.asar"));
  verifyArchitecture(
    path.join(bundleRoot, "resources", "native", "windows", arch, "shadow-ssh-service.exe"),
    arch
  );
  verifyArchitecture(path.join(bundleRoot, "resources", "xray", "windows", arch, "xray.exe"), arch);
}

function verifyMacBundle(releaseRoot, unpackedDirectory, arch) {
  const bundleRoot = path.join(releaseRoot, unpackedDirectory, "Shadow SSH.app", "Contents");
  verifyArchitecture(path.join(bundleRoot, "MacOS", "Shadow SSH"), arch);
  requireFile(path.join(bundleRoot, "Resources", "app.asar"));
  verifyArchitecture(
    path.join(bundleRoot, "Resources", "native", "macos", arch, "shadow-ssh-service"),
    arch
  );
  verifyArchitecture(path.join(bundleRoot, "Resources", "xray", "macos", arch, "xray"), arch);
}

function verifyLinuxBundle(releaseRoot, unpackedDirectory, arch) {
  const bundleRoot = path.join(releaseRoot, unpackedDirectory);
  verifyArchitecture(path.join(bundleRoot, "shadow-ssh-desktop"), arch);
  requireFile(path.join(bundleRoot, "resources", "app.asar"));
  verifyArchitecture(
    path.join(bundleRoot, "resources", "native", "linux", arch, "shadow-ssh-service"),
    arch
  );
  verifyArchitecture(path.join(bundleRoot, "resources", "xray", "linux", arch, "xray"), arch);
}

function verifyBinaryPackage(filePath, format) {
  const fileSize = requireFile(filePath);
  if (fileSize < 1024) {
    throw new Error(`${displayPath(filePath)} is unexpectedly small (${fileSize} bytes)`);
  }

  if (format === "pe") {
    requireBytes(filePath, 0, Buffer.from("MZ"));
    return;
  }
  if (format === "elf") {
    requireBytes(filePath, 0, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
    return;
  }
  if (format === "deb") {
    requireBytes(filePath, 0, Buffer.from("!<arch>\n"));
    return;
  }
  if (format === "dmg") {
    if (fileSize < 512) {
      throw new Error(`${displayPath(filePath)} has no UDIF footer`);
    }
    requireBytes(filePath, fileSize - 512, Buffer.from("koly"));
    return;
  }
  throw new Error(`Unsupported package format: ${format}`);
}

function verifyArchitecture(filePath, expectedArchitecture) {
  requireFile(filePath);
  const actualArchitecture = detectArchitecture(filePath);
  if (actualArchitecture !== expectedArchitecture) {
    throw new Error(
      `${displayPath(filePath)} has ${actualArchitecture ?? "an unknown"} architecture; expected ${expectedArchitecture}`
    );
  }
}

function detectArchitecture(filePath) {
  const header = readChunk(filePath, 0, 4096);

  if (header.length >= 20 && header.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    const machine = header[5] === 2 ? header.readUInt16BE(18) : header.readUInt16LE(18);
    return machine === 62 ? "x64" : machine === 183 ? "arm64" : `ELF machine ${machine}`;
  }

  if (header.length >= 8 && header.readUInt32LE(0) === 0xfeedfacf) {
    const cpuType = header.readUInt32LE(4);
    return cpuType === 0x01000007 ? "x64" : cpuType === 0x0100000c ? "arm64" : `Mach-O CPU ${cpuType}`;
  }

  if (header.length >= 64 && header.subarray(0, 2).equals(Buffer.from("MZ"))) {
    const peOffset = header.readUInt32LE(0x3c);
    const peHeader = peOffset + 6 <= header.length ? header.subarray(peOffset, peOffset + 6) : readChunk(filePath, peOffset, 6);
    if (peHeader.length >= 6 && peHeader.subarray(0, 4).equals(Buffer.from("PE\0\0"))) {
      const machine = peHeader.readUInt16LE(4);
      return machine === 0x8664 ? "x64" : machine === 0xaa64 ? "arm64" : `PE machine 0x${machine.toString(16)}`;
    }
  }

  return null;
}

function requireFile(filePath) {
  if (!existsSync(filePath)) {
    throw new Error(`missing ${displayPath(filePath)}`);
  }
  const stats = statSync(filePath);
  if (!stats.isFile()) {
    throw new Error(`${displayPath(filePath)} is not a file`);
  }
  if (stats.size === 0) {
    throw new Error(`${displayPath(filePath)} is empty`);
  }
  return stats.size;
}

function requireBytes(filePath, position, expected) {
  const actual = readChunk(filePath, position, expected.length);
  if (!actual.equals(expected)) {
    throw new Error(`${displayPath(filePath)} has an invalid ${position === 0 ? "header" : "footer"}`);
  }
}

function readChunk(filePath, position, length) {
  const descriptor = openSync(filePath, "r");
  try {
    const fileSize = fstatSync(descriptor).size;
    if (position < 0 || position >= fileSize) {
      return Buffer.alloc(0);
    }
    const output = Buffer.alloc(Math.min(length, fileSize - position));
    const bytesRead = readSync(descriptor, output, 0, output.length, position);
    return output.subarray(0, bytesRead);
  } finally {
    closeSync(descriptor);
  }
}

function parseOptions(args) {
  const platforms = new Set();
  let releaseDirectory;
  let plan = false;
  let help = false;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--win" || argument === "--mac" || argument === "--linux") {
      platforms.add(argument.slice(2));
    } else if (argument === "--plan") {
      plan = true;
    } else if (argument === "--help" || argument === "-h") {
      help = true;
    } else if (argument === "--release-dir") {
      const value = args[index + 1];
      if (!value) {
        throw new Error("--release-dir requires a path");
      }
      releaseDirectory = path.resolve(root, value);
      index += 1;
    } else if (argument.startsWith("--release-dir=")) {
      releaseDirectory = path.resolve(root, argument.slice("--release-dir=".length));
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }

  if (platforms.size === 0) {
    platforms.add("win");
    platforms.add("mac");
    platforms.add("linux");
  }

  return { platforms, releaseDirectory, plan, help };
}

function displayPath(filePath) {
  const relativePath = path.relative(root, filePath);
  return relativePath && !relativePath.startsWith("..") ? relativePath : filePath;
}

function toErrorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function printUsage() {
  console.log([
    "Usage: node scripts/verify-production-artifacts.mjs [options]",
    "",
    "Options:",
    "  --win | --mac | --linux  Verify one or more platform matrices (default: all)",
    "  --release-dir <path>      Verify a non-default release directory",
    "  --plan                    Print the expected artifact matrix without reading files",
    "  --help                    Show this help"
  ].join("\n"));
}
