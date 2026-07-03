import { access } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const targetMap = new Map([
  ["windows/x64", "xray.exe"],
  ["windows/arm64", "xray.exe"],
  ["macos/x64", "xray"],
  ["macos/arm64", "xray"],
  ["linux/x64", "xray"],
  ["linux/arm64", "xray"]
]);

const targets = parseTargets(process.argv.slice(2));
const missing = [];

for (const target of targets) {
  const executable = targetMap.get(target);
  const runtimePath = path.join(root, "resources", "xray", ...target.split("/"), executable);
  try {
    await access(runtimePath);
  } catch {
    missing.push(path.relative(root, runtimePath));
  }
}

if (missing.length > 0) {
  throw new Error([
    "Xray runtime is missing and the packaged Xray transport would fail at runtime.",
    ...missing.map((item) => `- ${item}`),
    "Run `npm run xray:download-win` for Windows artifacts or `npm run xray:download-all` for every platform."
  ].join("\n"));
}

for (const target of targets) {
  console.log(`Xray runtime OK: ${target}`);
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
