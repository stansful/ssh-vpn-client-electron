import { Buffer } from "node:buffer";
import { deflateSync } from "node:zlib";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const iconsDir = path.join(root, "resources", "icons");

async function writeTemplatePng(output, size, dpi) {
  const pixels = Buffer.alloc(size * size * 4);
  const samples = 8;
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      let covered = 0;
      for (let sampleY = 0; sampleY < samples; sampleY += 1) {
        for (let sampleX = 0; sampleX < samples; sampleX += 1) {
          const pointX = ((x + (sampleX + 0.5) / samples) * 16) / size;
          const pointY = ((y + (sampleY + 0.5) / samples) * 16) / size;
          covered += templateContains(pointX, pointY) ? 1 : 0;
        }
      }
      const offset = (y * size + x) * 4;
      pixels[offset] = 0;
      pixels[offset + 1] = 0;
      pixels[offset + 2] = 0;
      pixels[offset + 3] = Math.round((covered * 255) / (samples * samples));
    }
  }
  await writeFile(output, encodeRgbaPng({ width: size, height: size, pixels }, dpi));
}

function templateContains(x, y) {
  const shield = pointInPolygon(x, y, OUTER_SHIELD) && !pointInPolygon(x, y, INNER_SHIELD);
  const keyOuter =
    circleContains(x, y, 5.6, 6.15, 1.75) ||
    roundedRectContains(x, y, 6.65, 5.25, 5.2, 2.05, 0.58) ||
    roundedRectContains(x, y, 9.25, 6.15, 1.9, 2.7, 0.45);
  const keyHole = circleContains(x, y, 5.6, 6.15, 0.58);
  return shield || (keyOuter && !keyHole);
}

const OUTER_SHIELD = [
  [8, 1.05], [14.2, 3.15], [14.2, 7], [14, 8.55], [13.4, 10.15], [12.3, 11.8], [10.7, 13.25],
  [8, 14.85], [5.3, 13.25], [3.7, 11.8], [2.6, 10.15], [2, 8.55], [1.8, 7], [1.8, 3.15]
];
const INNER_SHIELD = [
  [8, 2.5], [12.7, 4], [12.7, 7.02], [12.5, 8.25], [12, 9.5], [11.05, 10.9], [9.7, 12.15],
  [8, 13.2], [6.3, 12.15], [4.95, 10.9], [4, 9.5], [3.5, 8.25], [3.3, 7.02], [3.3, 4]
];

await Promise.all([
  writeTemplatePng(path.join(iconsDir, "trayTemplate.png"), 16, 72),
  writeTemplatePng(path.join(iconsDir, "trayTemplate@2x.png"), 32, 144)
]);

console.log("wrote resources/icons/trayTemplate.png");
console.log("wrote resources/icons/trayTemplate@2x.png");

function pointInPolygon(x, y, polygon) {
  let inside = false;
  for (let index = 0, previous = polygon.length - 1; index < polygon.length; previous = index, index += 1) {
    const [x1, y1] = polygon[index];
    const [x2, y2] = polygon[previous];
    if ((y1 > y) !== (y2 > y) && x < ((x2 - x1) * (y - y1)) / (y2 - y1) + x1) {
      inside = !inside;
    }
  }
  return inside;
}

function circleContains(x, y, centerX, centerY, radius) {
  return (x - centerX) ** 2 + (y - centerY) ** 2 <= radius ** 2;
}

function roundedRectContains(x, y, left, top, width, height, radius) {
  const clampedX = Math.max(left + radius, Math.min(x, left + width - radius));
  const clampedY = Math.max(top + radius, Math.min(y, top + height - radius));
  return (
    x >= left &&
    x <= left + width &&
    y >= top &&
    y <= top + height &&
    (x - clampedX) ** 2 + (y - clampedY) ** 2 <= radius ** 2
  );
}

function encodeRgbaPng(image, dpi) {
  const rowLength = image.width * 4;
  const raw = Buffer.alloc((rowLength + 1) * image.height);
  for (let y = 0; y < image.height; y += 1) {
    const rawOffset = y * (rowLength + 1);
    raw[rawOffset] = 0;
    image.pixels.copy(raw, rawOffset + 1, y * rowLength, (y + 1) * rowLength);
  }

  const header = Buffer.alloc(13);
  header.writeUInt32BE(image.width, 0);
  header.writeUInt32BE(image.height, 4);
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
