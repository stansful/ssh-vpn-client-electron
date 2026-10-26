import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Fails when an Xray runtime is missing or is not the pinned release recorded
 * in `scripts/lib/xray-checksums.json`. The binaries are committed and packaged
 * as they are, so this is the check that stands between a replaced binary and
 * a shipped build.
 */

// Test seam: lets the check run against a fixture tree.
const root = process.env.SHADOW_SSH_PROJECT_ROOT
  ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const checksumsPath = path.join(root, "scripts", "lib", "xray-checksums.json");
const targetMap = new Map([
  ["windows/x64", "xray.exe"],
  ["windows/arm64", "xray.exe"],
  ["macos/x64", "xray"],
  ["macos/arm64", "xray"],
  ["linux/x64", "xray"],
  ["linux/arm64", "xray"]
]);

const targets = parseTargets(process.argv.slice(2));
const checksums = await readChecksums();
const missing = [];
const mismatched = [];

for (const target of targets) {
  const executable = targetMap.get(target);
  const runtimePath = path.join(root, "resources", "xray", ...target.split("/"), executable);
  const relative = path.relative(root, runtimePath);
  try {
    await access(runtimePath);
  } catch {
    missing.push(relative);
    continue;
  }
  const expected = checksums.executables?.[target];
  if (typeof expected !== "string" || expected.length === 0) {
    mismatched.push(`${relative} has no recorded SHA-256`);
    continue;
  }
  const actual = await sha256File(runtimePath);
  if (actual !== expected) {
    mismatched.push(`${relative} does not match the recorded SHA-256 (expected ${expected}, got ${actual})`);
  }
}

if (missing.length > 0) {
  throw new Error([
    "Xray runtime is missing and the packaged Xray transport would fail at runtime.",
    ...missing.map((item) => `- ${item}`),
    "Run `npm run xray:download-win` for Windows artifacts or `npm run xray:download-all` for every platform."
  ].join("\n"));
}

if (mismatched.length > 0) {
  throw new Error([
    `Xray runtime is not the pinned release ${checksums.version ?? "(none recorded)"} from ${path.relative(root, checksumsPath)}:`,
    ...mismatched.map((item) => `- ${item}`),
    "Run `npm run xray:download-all` to reinstall the pinned binaries."
  ].join("\n"));
}

for (const target of targets) {
  console.log(`Xray runtime OK: ${target} (${checksums.version})`);
}

async function readChecksums() {
  try {
    const parsed = JSON.parse(await readFile(checksumsPath, "utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

async function sha256File(filePath) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(filePath)) {
    hash.update(chunk);
  }
  return hash.digest("hex");
}

function parseTargets(args) {
  if (args.includes("--all")) {
    return [...targetMap.keys()];
  }

  const explicitTargets = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--target") {
      explicitTargets.push(normalizeTarget(args[index + 1] ?? ""));
      index += 1;
      continue;
    }
    if (arg.startsWith("--target=")) {
      explicitTargets.push(normalizeTarget(arg.slice("--target=".length)));
    }
  }
  if (explicitTargets.length > 0) {
    return [...new Set(explicitTargets)];
  }

  const platform = valueAfter(args, "--platform");
  const arch = valueAfter(args, "--arch");
  if (platform && arch) {
    const platformFolder = normalizePlatform(platform);
    if (arch === "all") {
      return [...targetMap.keys()].filter((target) => target.startsWith(`${platformFolder}/`));
    }
    return [normalizeTarget(`${platformFolder}/${arch}`)];
  }

  return [normalizeTarget(`${platformFromNode(process.platform)}/${process.arch}`)];
}

function valueAfter(args, flag) {
  const exactIndex = args.indexOf(flag);
  if (exactIndex >= 0) {
    return args[exactIndex + 1];
  }
  const prefixed = args.find((arg) => arg.startsWith(`${flag}=`));
  return prefixed ? prefixed.slice(flag.length + 1) : undefined;
}

function normalizeTarget(value) {
  const [platform, arch] = value.split("/");
  const normalized = `${normalizePlatform(platform)}/${normalizeArch(arch)}`;
  if (!targetMap.has(normalized)) {
    throw new Error(`Unsupported Xray target: ${value}`);
  }
  return normalized;
}

function normalizePlatform(value) {
  if (value === "win32" || value === "win" || value === "windows") {
    return "windows";
  }
  if (value === "darwin" || value === "mac" || value === "macos") {
    return "macos";
  }
  if (value === "linux") {
    return "linux";
  }
  throw new Error(`Unsupported Xray platform: ${value}`);
}

function normalizeArch(value) {
  if (value === "x64" || value === "amd64") {
    return "x64";
  }
  if (value === "arm64" || value === "aarch64") {
    return "arm64";
  }
  throw new Error(`Unsupported Xray architecture: ${value}`);
}

function platformFromNode(platform) {
  return normalizePlatform(platform);
}
