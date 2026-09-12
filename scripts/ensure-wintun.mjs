import { Buffer } from "node:buffer";
import { closeSync, openSync, readSync } from "node:fs";
import { stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Fails the build when `wintun.dll` is missing, instead of shipping a Windows
 * app that silently cannot do TUN.
 *
 * Without the DLL the app still starts and still connects, so nothing looks
 * broken - it just falls back to the Windows proxy path, where UDP never
 * enters the tunnel (calls and games leave directly) and a process rule cannot
 * reach an application that ignores the proxy setting. That is far too quiet a
 * failure to leave to a console warning.
 */

// Test seam: lets the check run against a fixture tree.
const root = process.env.SHADOW_SSH_PROJECT_ROOT
  ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const targetMap = new Map([
  ["x64", 0x8664],
  ["arm64", 0xaa64]
]);

const targets = parseTargets(process.argv.slice(2));
const problems = [];

for (const target of targets) {
  const dllPath = path.join(root, "native", "windows", target, "wintun.dll");
  const relative = path.relative(root, dllPath);
  let size = 0;
  try {
    const stats = await stat(dllPath);
    if (!stats.isFile()) {
      problems.push(`${relative} is not a file`);
      continue;
    }
    size = stats.size;
  } catch {
    problems.push(`${relative} is missing`);
    continue;
  }
  if (size === 0) {
    problems.push(`${relative} is empty`);
    continue;
  }
  const machine = readPeMachine(dllPath);
  if (machine !== targetMap.get(target)) {
    problems.push(
      `${relative} is PE machine 0x${(machine ?? 0).toString(16)}, expected 0x${targetMap.get(target).toString(16)}`
    );
  }
}

if (problems.length > 0) {
  throw new Error([
    "Wintun is missing or unusable, and the packaged Windows build would have no TUN routing:",
    ...problems.map((item) => `- ${item}`),
    "Without it UDP never enters the tunnel - calls and games leave the machine directly -",
    "and process rules cannot reach applications that ignore the Windows proxy setting.",
    "Run `npm run wintun:download` before packaging Windows artifacts."
  ].join("\n"));
}

for (const target of targets) {
  console.log(`Wintun OK: windows/${target}`);
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
