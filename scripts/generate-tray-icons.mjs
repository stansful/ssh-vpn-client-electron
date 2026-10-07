import { Buffer } from "node:buffer";
import { deflateSync, inflateSync } from "node:zlib";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { renderSvg } from "./svg-template-raster.mjs";

// Renders the macOS menu-bar template (resources/icons/trayTemplate.svg, a 16x16 viewBox) to its
// 1x and 2x PNGs. `--check` only verifies that the committed PNGs still match the SVG.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const iconsDir = path.join(root, "resources", "icons");
const source = path.join(iconsDir, "trayTemplate.svg");
const outputs = [
  { file: path.join(iconsDir, "trayTemplate.png"), size: 16, dpi: 72 },
  { file: path.join(iconsDir, "trayTemplate@2x.png"), size: 32, dpi: 144 }
];
const checkOnly = process.argv.includes("--check");

const svg = await readFile(source, "utf8");
const stale = [];
for (const output of outputs) {
  const image = renderSvg(svg, output.size);
  if (image.width !== output.size || image.height !== output.size) {
    throw new Error(`trayTemplate.svg must have a square 16x16 viewBox; got ${image.width}x${image.height} at ${output.size} px.`);
  }
  if (maxEdgeAlpha(image) !== 0) {
    throw new Error(`trayTemplate.svg leaves ink in the outer pixel ring at ${output.size} px; keep the glyph inside 1..15.`);
  }
  const name = path.relative(root, output.file);
  if (checkOnly) {
    if (!(await matchesPng(output.file, image))) {
      stale.push(name);
    }
    continue;
  }
  await writeFile(output.file, encodeTemplatePng(image, output.dpi));
  console.log(`wrote ${name}`);
}

if (stale.length > 0) {
  console.error(`${stale.join(", ")} out of date with trayTemplate.svg; run npm run icons:tray`);
  process.exit(1);
}
if (checkOnly) {
  console.log("tray template PNGs match trayTemplate.svg");
}

function maxEdgeAlpha({ width, height, alpha }) {
  let maximum = 0;
  for (let x = 0; x < width; x += 1) {
    maximum = Math.max(maximum, alpha[x], alpha[(height - 1) * width + x]);
  }
  for (let y = 0; y < height; y += 1) {
    maximum = Math.max(maximum, alpha[y * width], alpha[y * width + width - 1]);
  }
  return maximum;
}

/** Black, alpha-only RGBA: macOS tints template images for the menu-bar appearance. */
function encodeTemplatePng({ width, height, alpha }, dpi) {
  const rowLength = width * 4;
  const raw = Buffer.alloc((rowLength + 1) * height);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      raw[y * (rowLength + 1) + 1 + x * 4 + 3] = alpha[y * width + x];
    }
  }

  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 6;

  const pixelsPerMeter = Math.round(dpi / 0.0254);
  const physical = Buffer.alloc(9);
  physical.writeUInt32BE(pixelsPerMeter, 0);
  physical.writeUInt32BE(pixelsPerMeter, 4);
  physical[8] = 1;

  return Buffer.concat([
    Buffer.from("89504e470d0a1a0a", "hex"),
    pngChunk("IHDR", header),
    pngChunk("pHYs", physical),
    pngChunk("IDAT", deflateSync(raw)),
    pngChunk("IEND", Buffer.alloc(0))
  ]);
}

/** Compares against a PNG this script wrote (8-bit RGBA, unfiltered rows); ±1 absorbs float drift between Node versions. */
async function matchesPng(file, { width, height, alpha }) {
  let input;
  try {
    input = await readFile(file);
  } catch {
    return false;
  }
  let offset = 8;
  let header;
  const data = [];
  while (offset < input.length) {
    const length = input.readUInt32BE(offset);
    const type = input.subarray(offset + 4, offset + 8).toString("ascii");
    const body = input.subarray(offset + 8, offset + 8 + length);
    if (type === "IHDR") header = body;
    if (type === "IDAT") data.push(body);
    offset += 12 + length;
  }
  if (!header || header.readUInt32BE(0) !== width || header.readUInt32BE(4) !== height || header[8] !== 8 || header[9] !== 6) {
    return false;
  }
  const raw = inflateSync(Buffer.concat(data));
  const rowLength = width * 4;
  if (raw.length !== (rowLength + 1) * height) {
    return false;
  }
  for (let y = 0; y < height; y += 1) {
    const row = y * (rowLength + 1);
    if (raw[row] !== 0) {
      return false;
    }
    for (let x = 0; x < width; x += 1) {
      const pixel = row + 1 + x * 4;
      if (raw[pixel] !== 0 || raw[pixel + 1] !== 0 || raw[pixel + 2] !== 0) {
        return false;
      }
      if (Math.abs(raw[pixel + 3] - alpha[y * width + x]) > 1) {
        return false;
      }
    }
  }
  return true;
}

function pngChunk(type, data) {
  const typeBuffer = Buffer.from(type, "ascii");
  const chunk = Buffer.alloc(12 + data.length);
  chunk.writeUInt32BE(data.length, 0);
  typeBuffer.copy(chunk, 4);
  data.copy(chunk, 8);
  chunk.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])), 8 + data.length);
  return chunk;
}

function crc32(input) {
  let crc = 0xffffffff;
  for (const byte of input) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}
