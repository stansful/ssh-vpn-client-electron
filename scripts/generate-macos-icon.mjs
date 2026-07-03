import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = path.join(root, "resources", "icons", "icon.png");
const output = path.join(root, "resources", "icons", "icon.icns");
const scratchRoot = path.join(root, ".cache", "macos-icon");
const scratchDir = path.join(scratchRoot, String(process.pid));

const chunks = [
  { size: 16, type: "icp4" },
  { size: 32, type: "icp5" },
  { size: 64, type: "icp6" },
  { size: 128, type: "ic07" },
  { size: 256, type: "ic08" },
  { size: 512, type: "ic09" },
  { size: 1024, type: "ic10" }
];

await mkdir(scratchDir, { recursive: true });

try {
  const buffers = [];
  let totalLength = 8;

  for (const chunk of chunks) {
    const pngPath = path.join(scratchDir, `${chunk.type}-${chunk.size}.png`);
    await run("sips", ["-z", String(chunk.size), String(chunk.size), source, "--out", pngPath]);
    const png = await readFile(pngPath);
    const header = Buffer.alloc(8);
    header.write(chunk.type, 0, 4, "ascii");
    header.writeUInt32BE(png.length + 8, 4);
    buffers.push(header, png);
    totalLength += header.length + png.length;
  }

  const header = Buffer.alloc(8);
  header.write("icns", 0, 4, "ascii");
  header.writeUInt32BE(totalLength, 4);
  await writeFile(output, Buffer.concat([header, ...buffers], totalLength));
  console.log(`wrote ${path.relative(root, output)}`);
} finally {
  await rm(scratchDir, { recursive: true, force: true });
}

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "ignore" });
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
