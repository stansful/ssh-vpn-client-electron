import { existsSync, readFileSync } from "node:fs";
import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";

describe("build assets", () => {
  it("has Windows and Linux package icons", () => {
    expect(existsSync("resources/icons/icon.ico")).toBe(true);
    expect(existsSync("resources/icons/icon.png")).toBe(true);
  });

  it("keeps the package PNG icon background transparent", () => {
    expect(readPngCornerRgba("resources/icons/icon.png")).toEqual([0, 0, 0, 0]);
  });

  it("uses multi-size DIB Windows icons instead of a single PNG-in-ICO", () => {
    const ico = readIco("resources/icons/icon.ico");

    expect(ico.type).toBe(1);
    expect(ico.entries.map((entry) => entry.width)).toEqual([256, 128, 64, 48, 32, 24, 16]);
    for (const entry of ico.entries) {
      const image = ico.content.subarray(entry.imageOffset, entry.imageOffset + entry.bytesInResource);
      expect(image.subarray(0, 8).toString("hex")).not.toBe("89504e470d0a1a0a");
      expect(image.readUInt32LE(0)).toBe(40);
      expect(image.readInt32LE(4)).toBe(entry.width);
      expect(image.readInt32LE(8)).toBe(entry.height * 2);
      expect(image.readUInt16LE(14)).toBe(32);
    }
  });
});

function readPngCornerRgba(filePath: string): number[] {
  const input = readFileSync(filePath);
  let offset = 8;
  const idat: Buffer[] = [];
  while (offset < input.length) {
    const length = input.readUInt32BE(offset);
    const type = input.subarray(offset + 4, offset + 8).toString("ascii");
    const data = input.subarray(offset + 8, offset + 8 + length);
    offset += 12 + length;
    if (type === "IDAT") {
      idat.push(data);
    }
    if (type === "IEND") {
      break;
    }
  }
  const raw = inflateSync(Buffer.concat(idat));
  return [raw[1], raw[2], raw[3], raw[4]];
}

function readIco(filePath: string): {
  content: Buffer;
  type: number;
  entries: Array<{ width: number; height: number; bytesInResource: number; imageOffset: number }>;
} {
  const content = readFileSync(filePath);
  const count = content.readUInt16LE(4);
  const entries = [];
  for (let index = 0; index < count; index += 1) {
    const offset = 6 + index * 16;
    entries.push({
      width: content[offset] === 0 ? 256 : content[offset],
      height: content[offset + 1] === 0 ? 256 : content[offset + 1],
      bytesInResource: content.readUInt32LE(offset + 8),
      imageOffset: content.readUInt32LE(offset + 12)
    });
  }
  return {
    content,
    type: content.readUInt16LE(2),
    entries
  };
}
