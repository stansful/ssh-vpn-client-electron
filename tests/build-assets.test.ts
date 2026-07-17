import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import packageJson from "../package.json";
import packageLock from "../package-lock.json";

describe("build assets", () => {
  it("keeps package metadata versions aligned and cleans stale dist output before builds", () => {
    expect(packageLock.version).toBe(packageJson.version);
    expect(packageLock.packages[""].version).toBe(packageJson.version);
    expect(packageJson.scripts.prebuild).toContain("clean:dist");
    expect(packageJson.scripts["build:node"]).toContain("clean:node");
  });

  it("builds and verifies the complete production artifact matrix", () => {
    const scripts = packageJson.scripts;

    expect(scripts["build:prod"]).toBe("npm run build:prod-all");
    expect(scripts["build:prod-all"]).toContain("clean:release");
    expect(scripts["build:prod-all"]).toContain("package:prepare");
    expect(scripts["build:prod-all"]).toContain("pack:prod-all");
    expect(scripts["build:prod-all"]).toContain("verify:prod-artifacts");
    expect(scripts["pack:prod-all"]).toBe(
      "npm run pack:prod-win && npm run pack:prod-mac && npm run pack:prod-linux"
    );
    expect(scripts["pack:prod-win"]).toBe("npm run pack:prod-win-x64 && npm run pack:prod-win-arm64");
    expect(scripts["pack:prod-mac"]).toBe("npm run pack:prod-mac-x64 && npm run pack:prod-mac-arm64");
    expect(scripts["pack:prod-linux"]).toBe("npm run pack:prod-linux-x64 && npm run pack:prod-linux-arm64");
    expect(scripts["pack:prod-win-x64"]).toContain("--win dir portable nsis --x64");
    expect(scripts["pack:prod-win-arm64"]).toContain("--win dir portable nsis --arm64");
    expect(scripts["pack:prod-mac-x64"]).toContain("--mac dir dmg --x64");
    expect(scripts["pack:prod-mac-arm64"]).toContain("--mac dir dmg --arm64");
    expect(scripts["pack:prod-linux-x64"]).toContain("--linux AppImage deb --x64");
    expect(scripts["pack:prod-linux-arm64"]).toContain("--linux AppImage deb --arm64");
    expect(scripts["build:prod-win"]).toContain("verify:prod-artifacts -- --win");
    expect(scripts["build:prod-mac"]).toContain("verify:prod-artifacts -- --mac");
    expect(scripts["build:prod-linux"]).toContain("verify:prod-artifacts -- --linux");
    expect(scripts["build:prod-exe"]).toBe("npm run build:prod-win");
    expect(packageJson.author.email).toMatch(/@/u);
    expect(readFileSync("scripts/electron-builder-with-local-dist.mjs", "utf8")).toContain(
      'path.join(root, ".cache", "electron-builder")'
    );

    const plan = spawnSync(process.execPath, ["scripts/verify-production-artifacts.mjs", "--plan"], {
      encoding: "utf8"
    });
    expect(plan.error).toBeUndefined();
    expect(plan.status, plan.stderr).toBe(0);
    const targetLines = plan.stdout.split("\n").filter((line) => /^\[(win|mac|linux)\]/u.test(line));
    expect(targetLines).toHaveLength(14);
    expect(targetLines.filter((line) => line.startsWith("[win]")).length).toBe(6);
    expect(targetLines.filter((line) => line.startsWith("[mac]")).length).toBe(4);
    expect(targetLines.filter((line) => line.startsWith("[linux]")).length).toBe(4);
    expect(plan.stdout).toContain(`shadow-ssh-${packageJson.version}-windows-installer-arm64.exe`);
    expect(plan.stdout).toContain(`shadow-ssh-${packageJson.version}-macos-dmg-x64.dmg`);
    expect(plan.stdout).toContain(`shadow-ssh-${packageJson.version}-linux-package-amd64.deb`);
  });

  it("uses Electron's required .mjs extension for the ESM preload bridge", () => {
    expect(existsSync("src/preload/preload.mts")).toBe(true);
    expect(existsSync("src/preload/preload.ts")).toBe(false);
    expect(readFileSync("src/main/main.ts", "utf8")).toContain('"preload.mjs"');
  });

  it("has Windows and Linux package icons", () => {
    expect(existsSync("resources/icons/icon.ico")).toBe(true);
    expect(existsSync("resources/icons/icon.png")).toBe(true);
  });

  it("keeps the package PNG icon background transparent", () => {
    expect(readPngCornerRgba("resources/icons/icon.png")).toEqual([0, 0, 0, 0]);
  });

  it("ships small black-on-transparent macOS menu-bar template representations", () => {
    const oneX = readSimpleRgbaPng("resources/icons/trayTemplate.png");
    const twoX = readSimpleRgbaPng("resources/icons/trayTemplate@2x.png");

    expect([oneX.width, oneX.height]).toEqual([16, 16]);
    expect([twoX.width, twoX.height]).toEqual([32, 32]);
    for (const image of [oneX, twoX]) {
      let visiblePixels = 0;
      let transparentPixels = 0;
      for (let offset = 0; offset < image.pixels.length; offset += 4) {
        const alpha = image.pixels[offset + 3];
        if (alpha === 0) {
          transparentPixels += 1;
        } else {
          visiblePixels += 1;
          expect(Array.from(image.pixels.subarray(offset, offset + 3))).toEqual([0, 0, 0]);
        }
      }
      expect(visiblePixels).toBeGreaterThan(0);
      expect(transparentPixels).toBeGreaterThan(0);
      expect(maxEdgeAlpha(image)).toBe(0);
    }

    const macResources = JSON.stringify(packageJson.build.mac.extraResources);
    expect(macResources).toContain("trayTemplate.png");
    expect(macResources).toContain("trayTemplate@2x.png");
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

function readSimpleRgbaPng(filePath: string): { width: number; height: number; pixels: Buffer } {
  const input = readFileSync(filePath);
  let offset = 8;
  let width = 0;
  let height = 0;
  const idat: Buffer[] = [];
  while (offset < input.length) {
    const length = input.readUInt32BE(offset);
    const type = input.subarray(offset + 4, offset + 8).toString("ascii");
    const data = input.subarray(offset + 8, offset + 8 + length);
    offset += 12 + length;
    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      expect([data[8], data[9], data[12]]).toEqual([8, 6, 0]);
    } else if (type === "IDAT") {
      idat.push(data);
    } else if (type === "IEND") {
      break;
    }
  }
  const raw = inflateSync(Buffer.concat(idat));
  const pixels = Buffer.alloc(width * height * 4);
  const rowLength = width * 4;
  for (let y = 0; y < height; y += 1) {
    const sourceOffset = y * (rowLength + 1);
    expect(raw[sourceOffset]).toBe(0);
    raw.copy(pixels, y * rowLength, sourceOffset + 1, sourceOffset + 1 + rowLength);
  }
  return { width, height, pixels };
}

function maxEdgeAlpha(image: { width: number; height: number; pixels: Buffer }): number {
  let maximum = 0;
  for (let x = 0; x < image.width; x += 1) {
    maximum = Math.max(maximum, pixelAlpha(image, x, 0), pixelAlpha(image, x, image.height - 1));
  }
  for (let y = 0; y < image.height; y += 1) {
    maximum = Math.max(maximum, pixelAlpha(image, 0, y), pixelAlpha(image, image.width - 1, y));
  }
  return maximum;
}

function pixelAlpha(image: { width: number; pixels: Buffer }, x: number, y: number): number {
  return image.pixels[(y * image.width + x) * 4 + 3] ?? 0;
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
