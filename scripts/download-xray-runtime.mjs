import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import { createWriteStream } from "node:fs";
import { chmod, copyFile, mkdir, readdir, rm } from "node:fs/promises";
import { get } from "node:https";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { spawn } from "node:child_process";
import { fileURLToPath, URL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const releaseApiUrl = "https://api.github.com/repos/XTLS/Xray-core/releases/latest";
const targetMap = new Map([
  ["windows/x64", { asset: "Xray-windows-64.zip", executable: "xray.exe" }],
  ["windows/arm64", { asset: "Xray-windows-arm64-v8a.zip", executable: "xray.exe" }],
  ["macos/x64", { asset: "Xray-macos-64.zip", executable: "xray" }],
  ["macos/arm64", { asset: "Xray-macos-arm64-v8a.zip", executable: "xray" }],
  ["linux/x64", { asset: "Xray-linux-64.zip", executable: "xray" }],
  ["linux/arm64", { asset: "Xray-linux-arm64-v8a.zip", executable: "xray" }]
]);

const cliArgs = process.argv.slice(2);
const includeGeoData = cliArgs.includes("--include-geo");
const targets = parseTargets(cliArgs.filter((arg) => arg !== "--include-geo"));
const release = await requestJson(releaseApiUrl);
const version = String(release.tag_name ?? "latest");
const cacheDir = path.join(root, ".cache", "xray", version);
await mkdir(cacheDir, { recursive: true });

for (const target of targets) {
  const descriptor = targetMap.get(target);
  if (!descriptor) {
    throw new Error(`Unsupported Xray target: ${target}`);
  }
  const asset = release.assets?.find((item) => item.name === descriptor.asset);
  if (!asset?.browser_download_url) {
    throw new Error(`Xray release ${version} does not contain ${descriptor.asset}.`);
  }

  const zipPath = path.join(cacheDir, descriptor.asset);
  await downloadFile(asset.browser_download_url, zipPath, asset.digest);

  const extractDir = path.join(cacheDir, target.replace("/", "-"));
  await rm(extractDir, { recursive: true, force: true });
  await mkdir(extractDir, { recursive: true });
  await extractZip(zipPath, extractDir);

  const executablePath = await findFile(extractDir, descriptor.executable);
  if (!executablePath) {
    throw new Error(`${descriptor.asset} does not contain ${descriptor.executable}.`);
  }

  const outputDir = path.join(root, "resources", "xray", ...target.split("/"));
  await mkdir(outputDir, { recursive: true });
  const outputExecutable = path.join(outputDir, descriptor.executable);
  await copyFile(executablePath, outputExecutable);
  if (descriptor.executable === "xray") {
    await chmod(outputExecutable, 0o755);
  }

  if (includeGeoData) {
    for (const dataFile of ["geoip.dat", "geosite.dat"]) {
      const source = await findFile(extractDir, dataFile);
      if (source) {
        await copyFile(source, path.join(outputDir, dataFile));
      }
    }
  }

  console.log(`Installed Xray ${version} for ${target} -> ${path.relative(root, outputExecutable)}`);
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

async function requestJson(url) {
  const buffer = await requestBuffer(url);
  return JSON.parse(buffer.toString("utf8"));
}

function requestBuffer(url, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    const request = get(url, { headers: { "User-Agent": "shadow-ssh-build" } }, (response) => {
      if (response.statusCode && response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        if (redirectCount > 5) {
          reject(new Error(`Too many redirects while requesting ${url}`));
          return;
        }
        resolve(requestBuffer(new URL(response.headers.location, url).toString(), redirectCount + 1));
        return;
      }
      if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) {
        response.resume();
        reject(new Error(`Request failed ${response.statusCode ?? "unknown"} for ${url}`));
        return;
      }
      const chunks = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => resolve(Buffer.concat(chunks)));
    });
    request.on("error", reject);
  });
}

async function downloadFile(url, outputPath, expectedDigest) {
  const expectedSha256 = typeof expectedDigest === "string" && expectedDigest.startsWith("sha256:")
    ? expectedDigest.slice("sha256:".length)
    : undefined;
  const hash = createHash("sha256");

  const redirected = await new Promise((resolve, reject) => {
    const request = get(url, { headers: { "User-Agent": "shadow-ssh-build" } }, (response) => {
      if (response.statusCode && response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        downloadFile(new URL(response.headers.location, url).toString(), outputPath, expectedDigest).then(() => resolve(true), reject);
        return;
      }
      if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) {
        response.resume();
        reject(new Error(`Download failed ${response.statusCode ?? "unknown"} for ${url}`));
        return;
      }
      response.on("data", (chunk) => hash.update(chunk));
      pipeline(response, createWriteStream(outputPath)).then(() => resolve(false), reject);
    });
    request.on("error", reject);
  });
  if (redirected) {
    return;
  }

  if (expectedSha256) {
    const actual = hash.digest("hex");
    if (actual !== expectedSha256) {
      throw new Error(`SHA-256 mismatch for ${path.basename(outputPath)}: expected ${expectedSha256}, got ${actual}.`);
    }
  }
}

function extractZip(zipPath, outputDir) {
  if (process.platform === "win32") {
    return run("powershell.exe", [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-Command",
      `Expand-Archive -LiteralPath ${JSON.stringify(zipPath)} -DestinationPath ${JSON.stringify(outputDir)} -Force`
    ]);
  }
  return run("unzip", ["-q", "-o", zipPath, "-d", outputDir]);
}

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} ${args.join(" ")} exited with ${code}`));
      }
    });
  });
}

async function findFile(directory, filename) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const candidate = path.join(directory, entry.name);
    if (entry.isFile() && entry.name === filename) {
      return candidate;
    }
    if (entry.isDirectory()) {
      const nested = await findFile(candidate, filename);
      if (nested) {
        return nested;
      }
    }
  }
  return undefined;
}
