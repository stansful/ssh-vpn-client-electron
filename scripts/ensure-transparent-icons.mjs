import { Buffer } from "node:buffer";
import { deflateSync, inflateSync } from "node:zlib";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pngPath = path.join(root, "resources", "icons", "icon.png");
const icoPath = path.join(root, "resources", "icons", "icon.ico");

const png = await readFile(pngPath);
const image = decodeRgbaPng(png);
removeConnectedWhiteBackground(image);
clearFullyTransparentPixels(image);
const transparentPng = encodeRgbaPng(image);
await writeFile(pngPath, transparentPng);
await writeFile(icoPath, encodeIco(image));
console.log(`wrote ${path.relative(root, pngPath)}`);
console.log(`wrote ${path.relative(root, icoPath)}`);

function decodeRgbaPng(input) {
  const signature = input.subarray(0, 8).toString("hex");
  if (signature !== "89504e470d0a1a0a") {
    throw new Error("Unsupported PNG signature.");
  }

  let offset = 8;
  let width = 0;
  let height = 0;
  const idat = [];
  while (offset < input.length) {
    const length = input.readUInt32BE(offset);
    const type = input.subarray(offset + 4, offset + 8).toString("ascii");
    const data = input.subarray(offset + 8, offset + 8 + length);
    offset += 12 + length;

    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      const bitDepth = data[8];
      const colorType = data[9];
      const interlace = data[12];
      if (bitDepth !== 8 || colorType !== 6 || interlace !== 0) {
        throw new Error("Only non-interlaced 8-bit RGBA PNG icons are supported.");
      }
    }
    if (type === "IDAT") {
      idat.push(data);
    }
    if (type === "IEND") {
      break;
    }
  }

  const bytesPerPixel = 4;
  const rowLength = width * bytesPerPixel;
  const inflated = inflateSync(Buffer.concat(idat));
  const pixels = Buffer.alloc(width * height * bytesPerPixel);
  let source = 0;
  let target = 0;
  let previous = Buffer.alloc(rowLength);

  for (let y = 0; y < height; y += 1) {
    const filter = inflated[source];
    source += 1;
    const row = Buffer.from(inflated.subarray(source, source + rowLength));
    source += rowLength;
    unfilterRow(row, previous, bytesPerPixel, filter);
    row.copy(pixels, target);
    previous = row;
    target += rowLength;
  }

  return { width, height, pixels };
}

function unfilterRow(row, previous, bytesPerPixel, filter) {
  for (let index = 0; index < row.length; index += 1) {
    const left = index >= bytesPerPixel ? row[index - bytesPerPixel] : 0;
    const up = previous[index] ?? 0;
    const upLeft = index >= bytesPerPixel ? previous[index - bytesPerPixel] ?? 0 : 0;
    if (filter === 1) {
      row[index] = (row[index] + left) & 0xff;
    } else if (filter === 2) {
      row[index] = (row[index] + up) & 0xff;
    } else if (filter === 3) {
      row[index] = (row[index] + Math.floor((left + up) / 2)) & 0xff;
    } else if (filter === 4) {
      row[index] = (row[index] + paeth(left, up, upLeft)) & 0xff;
    } else if (filter !== 0) {
      throw new Error(`Unsupported PNG row filter ${filter}.`);
    }
  }
}

function paeth(left, up, upLeft) {
  const estimate = left + up - upLeft;
  const leftDistance = Math.abs(estimate - left);
  const upDistance = Math.abs(estimate - up);
  const upLeftDistance = Math.abs(estimate - upLeft);
  if (leftDistance <= upDistance && leftDistance <= upLeftDistance) {
    return left;
  }
  return upDistance <= upLeftDistance ? up : upLeft;
}

function removeConnectedWhiteBackground(image) {
  const { width, height, pixels } = image;
  const visited = new Uint8Array(width * height);
  const queue = [];

  for (let x = 0; x < width; x += 1) {
    enqueueIfBackground(x, 0);
    enqueueIfBackground(x, height - 1);
  }
  for (let y = 0; y < height; y += 1) {
    enqueueIfBackground(0, y);
    enqueueIfBackground(width - 1, y);
  }

  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const point = queue[cursor];
    const offset = point.index * 4;
    pixels[offset + 3] = 0;
    const x = point.index % width;
    const y = Math.floor(point.index / width);
    enqueueIfBackground(x + 1, y);
    enqueueIfBackground(x - 1, y);
    enqueueIfBackground(x, y + 1);
    enqueueIfBackground(x, y - 1);
  }

  function enqueueIfBackground(x, y) {
    if (x < 0 || y < 0 || x >= width || y >= height) {
      return;
    }
    const index = y * width + x;
    if (visited[index]) {
      return;
    }
    visited[index] = 1;
    const offset = index * 4;
    if (pixels[offset + 3] > 0 && pixels[offset] >= 245 && pixels[offset + 1] >= 245 && pixels[offset + 2] >= 245) {
      queue.push({ index });
    }
  }
}

function clearFullyTransparentPixels(image) {
  const { pixels } = image;
  for (let offset = 0; offset < pixels.length; offset += 4) {
    if (pixels[offset + 3] === 0) {
      pixels[offset] = 0;
      pixels[offset + 1] = 0;
      pixels[offset + 2] = 0;
    }
  }
}

function encodeRgbaPng(image) {
  const { width, height, pixels } = image;
  const rowLength = width * 4;
  const raw = Buffer.alloc((rowLength + 1) * height);
  for (let y = 0; y < height; y += 1) {
    const rawOffset = y * (rowLength + 1);
    raw[rawOffset] = 0;
    pixels.copy(raw, rawOffset + 1, y * rowLength, (y + 1) * rowLength);
  }

  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 6;
  header[10] = 0;
  header[11] = 0;
  header[12] = 0;

  return Buffer.concat([
    Buffer.from("89504e470d0a1a0a", "hex"),
    pngChunk("IHDR", header),
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

function encodeIco(image) {
  const sizes = [256, 128, 64, 48, 32, 24, 16];
  const entries = sizes.map((size) => encodeIcoDib(resizeImage(image, size, size)));
  const headerLength = 6 + entries.length * 16;
  const header = Buffer.alloc(headerLength);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(entries.length, 4);

  let imageOffset = headerLength;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const offset = 6 + index * 16;
    header[offset] = entry.width === 256 ? 0 : entry.width;
    header[offset + 1] = entry.height === 256 ? 0 : entry.height;
    header[offset + 2] = 0;
    header[offset + 3] = 0;
    header.writeUInt16LE(1, offset + 4);
    header.writeUInt16LE(32, offset + 6);
    header.writeUInt32LE(entry.data.length, offset + 8);
    header.writeUInt32LE(imageOffset, offset + 12);
    imageOffset += entry.data.length;
  }

  return Buffer.concat([header, ...entries.map((entry) => entry.data)]);
}

function resizeImage(image, width, height) {
  if (image.width === width && image.height === height) {
    return { width, height, pixels: Buffer.from(image.pixels) };
  }
  const pixels = Buffer.alloc(width * height * 4);
  for (let y = 0; y < height; y += 1) {
    const sourceY = height === 1 ? 0 : (y * (image.height - 1)) / (height - 1);
    for (let x = 0; x < width; x += 1) {
      const sourceX = width === 1 ? 0 : (x * (image.width - 1)) / (width - 1);
      writeBilinearPixel(image, sourceX, sourceY, pixels, (y * width + x) * 4);
    }
  }
  return { width, height, pixels };
}

function writeBilinearPixel(image, sourceX, sourceY, target, targetOffset) {
  const x0 = Math.floor(sourceX);
  const y0 = Math.floor(sourceY);
  const x1 = Math.min(image.width - 1, x0 + 1);
  const y1 = Math.min(image.height - 1, y0 + 1);
  const wx = sourceX - x0;
  const wy = sourceY - y0;
  const weights = [
    { offset: (y0 * image.width + x0) * 4, weight: (1 - wx) * (1 - wy) },
    { offset: (y0 * image.width + x1) * 4, weight: wx * (1 - wy) },
    { offset: (y1 * image.width + x0) * 4, weight: (1 - wx) * wy },
    { offset: (y1 * image.width + x1) * 4, weight: wx * wy }
  ];

  let alpha = 0;
  let red = 0;
  let green = 0;
  let blue = 0;
  for (const sample of weights) {
    const sampleAlpha = image.pixels[sample.offset + 3] / 255;
    const weightedAlpha = sampleAlpha * sample.weight;
    alpha += weightedAlpha;
    red += image.pixels[sample.offset] * weightedAlpha;
    green += image.pixels[sample.offset + 1] * weightedAlpha;
    blue += image.pixels[sample.offset + 2] * weightedAlpha;
  }

  const alphaByte = clampByte(alpha * 255);
  target[targetOffset + 3] = alphaByte;
  if (alphaByte === 0) {
    target[targetOffset] = 0;
    target[targetOffset + 1] = 0;
    target[targetOffset + 2] = 0;
    return;
  }
  target[targetOffset] = clampByte(red / alpha);
  target[targetOffset + 1] = clampByte(green / alpha);
  target[targetOffset + 2] = clampByte(blue / alpha);
}

function clampByte(value) {
  return Math.max(0, Math.min(255, Math.round(value)));
}

function encodeIcoDib(image) {
  const { width, height, pixels } = image;
  const xorStride = width * 4;
  const xor = Buffer.alloc(xorStride * height);
  const maskStride = Math.ceil(width / 32) * 4;
  const mask = Buffer.alloc(maskStride * height);

  for (let y = 0; y < height; y += 1) {
    const sourceY = height - 1 - y;
    for (let x = 0; x < width; x += 1) {
      const sourceOffset = (sourceY * width + x) * 4;
      const targetOffset = y * xorStride + x * 4;
      xor[targetOffset] = pixels[sourceOffset + 2];
      xor[targetOffset + 1] = pixels[sourceOffset + 1];
      xor[targetOffset + 2] = pixels[sourceOffset];
      xor[targetOffset + 3] = pixels[sourceOffset + 3];

      if (pixels[sourceOffset + 3] < 128) {
        mask[y * maskStride + (x >> 3)] |= 0x80 >> (x & 7);
      }
    }
  }

  const header = Buffer.alloc(40);
  header.writeUInt32LE(40, 0);
  header.writeInt32LE(width, 4);
  header.writeInt32LE(height * 2, 8);
  header.writeUInt16LE(1, 12);
  header.writeUInt16LE(32, 14);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(xor.length, 20);
  header.writeInt32LE(0, 24);
  header.writeInt32LE(0, 28);
  header.writeUInt32LE(0, 32);
  header.writeUInt32LE(0, 36);

  return { width, height, data: Buffer.concat([header, xor, mask]) };
}
