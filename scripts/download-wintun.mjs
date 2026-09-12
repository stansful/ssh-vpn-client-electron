import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import { createReadStream, createWriteStream, openSync, readSync, closeSync } from "node:fs";
import { copyFile, mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { get } from "node:https";
import path from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { spawn } from "node:child_process";
import { fileURLToPath, URL } from "node:url";

/**
 * Fetches the signed `wintun.dll` that TUN mode needs, the way the Xray runtime
 * is already fetched.
 *
 * The DLL is deliberately not committed - it is a third-party signed binary -
 * but nothing fetched it either, so `npm run package:prepare` produced Windows
 * builds without it and only said so in one console warning among hundreds of
 * build lines. Those builds run, which is what made this expensive: they fall
 * back to the Windows proxy path, which carries no UDP at all and cannot hold a
 * process rule against an application that ignores the proxy setting.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const defaultVersion = "0.14.1";
const checksumsPath = path.join(root, "scripts", "wintun-checksums.json");
const maxRedirects = 5;
const requestIdleTimeoutMs = 30_000;
const maxArchiveBytes = 16 * 1024 * 1024;
// `native/windows/<arch>/` is copied verbatim into the packaged app, and the
// archive names the same architectures differently.
const targetMap = new Map([
  ["x64", { archiveArch: "amd64", peMachine: 0x8664 }],
  ["arm64", { archiveArch: "arm64", peMachine: 0xaa64 }]
]);

const args = process.argv.slice(2);
const version = valueAfter(args, "--version") ?? defaultVersion;
if (!/^[0-9][0-9A-Za-z.]{0,31}$/.test(version)) {
  throw new Error(`Invalid Wintun version: ${JSON.stringify(version)}`);
}
const targets = parseTargets(args);
const trustDownload = args.includes("--trust-download");
const archiveUrl = `https://www.wintun.net/builds/wintun-${version}.zip`;
const archiveName = `wintun-${version}.zip`;

const checksums = await readChecksums();
const expectedSha256 = checksums.archives?.[version];
const cacheDir = path.join(root, ".cache", "wintun", version);
await mkdir(cacheDir, { recursive: true });
const archivePath = path.join(cacheDir, archiveName);

const actualSha256 = await obtainArchive();
if (!expectedSha256) {
  if (!trustDownload) {
    // Refusing is the point: a third-party binary that nothing has ever
    // verified should not be installed into a shipped build by accident.
    throw new Error([
      `No recorded SHA-256 for ${archiveName}, so the download was not installed.`,
      `Downloaded from ${archiveUrl}`,
      `  sha256 ${actualSha256}`,
      "Compare it against the vendor's published value, then either add it to",
      `${path.relative(root, checksumsPath)} under "archives", or re-run with`,
      "`npm run wintun:download -- --trust-download` to record this one.",
      "Commit the recorded value so every later build verifies against it."
    ].join("\n"));
  }
  await recordChecksum(actualSha256);
  console.log(`Recorded sha256 ${actualSha256} for ${archiveName} in ${path.relative(root, checksumsPath)}.`);
}

const extractDir = path.join(cacheDir, "extracted");
await rm(extractDir, { recursive: true, force: true });
await mkdir(extractDir, { recursive: true });
await extractZip(archivePath, extractDir);

for (const target of targets) {
  const descriptor = targetMap.get(target);
  const source = await findArchitectureDll(extractDir, descriptor.archiveArch);
  if (!source) {
    throw new Error(`${archiveName} does not contain bin/${descriptor.archiveArch}/wintun.dll.`);
  }
  const outputDir = path.join(root, "native", "windows", target);
  await mkdir(outputDir, { recursive: true });
  const outputPath = path.join(outputDir, "wintun.dll");
  await copyFile(source, outputPath);
  // A DLL of the wrong architecture loads nowhere, and the archive layout is
  // the vendor's to change.
  const machine = readPeMachine(outputPath);
  if (machine !== descriptor.peMachine) {
    await rm(outputPath, { force: true });
    throw new Error(
      `bin/${descriptor.archiveArch}/wintun.dll is PE machine 0x${(machine ?? 0).toString(16)}, expected 0x${descriptor.peMachine.toString(16)} for ${target}.`
    );
  }
  console.log(`Installed Wintun ${version} for windows/${target} -> ${path.relative(root, outputPath)}`);
}

/** Returns the archive's SHA-256, downloading it unless a verified copy is cached. */
async function obtainArchive() {
  if (expectedSha256 && await fileMatchesSha256(archivePath, expectedSha256)) {
    console.log(`Reusing verified ${archiveName}`);
    return expectedSha256;
  }
  const partialPath = `${archivePath}.part-${process.pid}`;
  await rm(partialPath, { force: true });
  try {
    const digest = await downloadFile(archiveUrl, partialPath, 0);
    if (expectedSha256 && digest !== expectedSha256) {
      throw new Error(`SHA-256 mismatch for ${archiveName}: expected ${expectedSha256}, got ${digest}.`);
    }
    // Windows does not replace an existing destination with fs.rename().
    await rm(archivePath, { force: true });
    await rename(partialPath, archivePath);
    return digest;
  } finally {
    await rm(partialPath, { force: true });
  }
}

function downloadFile(url, outputPath, redirectCount) {
  const hash = createHash("sha256");
  return new Promise((resolve, reject) => {
    const request = get(url, { headers: { "User-Agent": "shadow-ssh-build" } }, (response) => {
      if (response.statusCode && response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        if (redirectCount >= maxRedirects) {
          reject(new Error(`Too many redirects while downloading ${url}`));
          return;
        }
        resolve(downloadFile(new URL(response.headers.location, url).toString(), outputPath, redirectCount + 1));
        return;
      }
      if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) {
        response.resume();
        reject(new Error(`Download failed ${response.statusCode ?? "unknown"} for ${url}`));
        return;
      }
      const limiter = byteLimitTransform(maxArchiveBytes, (chunk) => hash.update(chunk));
      pipeline(response, limiter, createWriteStream(outputPath, { flags: "wx" }))
        .then(() => resolve(hash.digest("hex")), reject);
    });
    request.setTimeout(requestIdleTimeoutMs, () => {
      request.destroy(new Error(`Download was idle for ${requestIdleTimeoutMs} ms: ${url}`));
    });
    request.on("error", reject);
  });
}

function byteLimitTransform(maxBytes, onChunk) {
  let receivedBytes = 0;
  return new Transform({
    transform(chunk, _encoding, callback) {
      receivedBytes += chunk.length;
      if (receivedBytes > maxBytes) {
        callback(new Error(`Download exceeded ${maxBytes} bytes.`));
        return;
      }
      onChunk(chunk);
      callback(undefined, chunk);
    }
  });
}

async function fileMatchesSha256(filePath, expected) {
  try {
    const hash = createHash("sha256");
    for await (const chunk of createReadStream(filePath)) {
      hash.update(chunk);
    }
    return hash.digest("hex") === expected;
  } catch {
    return false;
  }
}

async function readChecksums() {
  try {
    const parsed = JSON.parse(await readFile(checksumsPath, "utf8"));
    return parsed && typeof parsed === "object" ? parsed : { archives: {} };
  } catch {
    return { archives: {} };
  }
}

async function recordChecksum(digest) {
  const next = { ...checksums, archives: { ...checksums.archives, [version]: digest } };
  await writeFile(checksumsPath, `${JSON.stringify(next, undefined, 2)}\n`, "utf8");
}

async function findArchitectureDll(directory, archiveArch) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const candidate = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      const nested = await findArchitectureDll(candidate, archiveArch);
      if (nested) {
        return nested;
      }
      continue;
    }
    if (entry.name.toLowerCase() === "wintun.dll" && path.basename(directory).toLowerCase() === archiveArch) {
      return candidate;
    }
  }
  return undefined;
}

/** The PE machine word, or undefined when the file is not a PE image. */
function readPeMachine(filePath) {
  const header = Buffer.alloc(4096);
  const handle = openSync(filePath, "r");
  let read = 0;
  try {
    read = readSync(handle, header, 0, header.length, 0);
  } finally {
    closeSync(handle);
  }
  if (read < 64 || !header.subarray(0, 2).equals(Buffer.from("MZ"))) {
    return undefined;
  }
  const peOffset = header.readUInt32LE(0x3c);
  if (peOffset + 6 > read || !header.subarray(peOffset, peOffset + 4).equals(Buffer.from("PE\0\0"))) {
    return undefined;
  }
  return header.readUInt16LE(peOffset + 4);
}

function extractZip(zipPath, outputDir) {
  if (process.platform === "win32") {
    return run("powershell.exe", [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-Command",
      `Expand-Archive -LiteralPath ${powerShellLiteral(zipPath)} -DestinationPath ${powerShellLiteral(outputDir)} -Force`
    ]);
  }
  return run("unzip", ["-q", "-o", zipPath, "-d", outputDir]);
}

function powerShellLiteral(value) {
  return `'${value.replaceAll("'", "''")}'`;
}

function run(command, commandArgs) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, commandArgs, { stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} ${commandArgs.join(" ")} exited with ${code}`));
      }
    });
  });
}

function parseTargets(argv) {
  const arch = valueAfter(argv, "--arch");
  if (!arch || arch === "all") {
    return [...targetMap.keys()];
  }
  const normalized = arch === "amd64" ? "x64" : arch === "aarch64" ? "arm64" : arch;
  if (!targetMap.has(normalized)) {
    throw new Error(`Unsupported Wintun architecture: ${arch}`);
  }
  return [normalized];
}

function valueAfter(argv, flag) {
  const exactIndex = argv.indexOf(flag);
  if (exactIndex >= 0) {
    return argv[exactIndex + 1];
  }
  const prefixed = argv.find((arg) => arg.startsWith(`${flag}=`));
  return prefixed ? prefixed.slice(flag.length + 1) : undefined;
}
