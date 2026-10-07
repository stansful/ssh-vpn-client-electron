import { describe, expect, it, vi } from "vitest";
import type { TrayTone } from "../src/main/app/tray-icons.js";

const electron = vi.hoisted(() => ({
  createEmpty: vi.fn<() => Electron.NativeImage>(),
  createFromBitmap: vi.fn<(buffer: Buffer, options: { width: number; height: number; scaleFactor?: number }) => Electron.NativeImage>()
}));

vi.mock("electron", () => ({
  nativeImage: { createEmpty: electron.createEmpty, createFromBitmap: electron.createFromBitmap }
}));

const {
  bitmapPixelSize,
  composeTrayIcon,
  paintTrayTone,
  TRAY_OFF_OPACITY,
  windowsTrayIconPixelSize,
  windowsTrayIconSource
} = await import("../src/main/app/tray-icons.js");

// Premultiplied B, G, R, A as Electron bitmaps store them.
const WHITE = [255, 255, 255, 255];
const MINT = [0x8a, 0xd0, 0x34, 255];
const AMBER = [0x19, 0xa0, 0xf6, 255];
const RED = [0x5a, 0x55, 0xf2, 255];
const DARK_INK = [19, 17, 16, 255];
const WHITE_INK = [255, 255, 255, 255];

function solidBitmap(size: number, bgra: number[]): Uint8Array {
  const pixels = new Uint8Array(size * size * 4);
  for (let offset = 0; offset < pixels.length; offset += 4) {
    pixels.set(bgra, offset);
  }
  return pixels;
}

function pixelAt(pixels: Uint8Array, size: number, x: number, y: number): number[] {
  const offset = (y * size + x) * 4;
  return Array.from(pixels.subarray(offset, offset + 4));
}

function countPixels(pixels: Uint8Array, bgra: number[]): number {
  let count = 0;
  for (let offset = 0; offset < pixels.length; offset += 4) {
    if (bgra.every((value, index) => pixels[offset + index] === value)) {
      count += 1;
    }
  }
  return count;
}

/** Glyph pixels are anti-aliased, so count opaque pixels closer to the ink than to the badge fill. */
function countInkDominant(pixels: Uint8Array, ink: readonly number[], fill: readonly number[]): number {
  const distance = (offset: number, color: readonly number[]): number =>
    Math.abs(pixels[offset] - color[0]) + Math.abs(pixels[offset + 1] - color[1]) + Math.abs(pixels[offset + 2] - color[2]);
  let count = 0;
  for (let offset = 0; offset < pixels.length; offset += 4) {
    if (pixels[offset + 3] === 255 && distance(offset, ink) < distance(offset, fill)) {
      count += 1;
    }
  }
  return count;
}

function painted(tone: TrayTone, size: number, template: boolean): Uint8Array {
  const pixels = solidBitmap(size, template ? [0, 0, 0, 255] : WHITE);
  paintTrayTone(pixels, size, size, tone, { template });
  return pixels;
}

describe("tray icon tones", () => {
  it.each([
    ["busy", AMBER, DARK_INK],
    ["ok", MINT, DARK_INK],
    ["attention", RED, WHITE_INK]
  ] as const)("paints a %s badge in the board's signal colour with its glyph", (tone, fill, ink) => {
    for (const size of [16, 32]) {
      const pixels = painted(tone, size, false);

      expect(pixelAt(pixels, size, 0, 0)).toEqual(WHITE);
      expect(countPixels(pixels, fill)).toBeGreaterThan(size);
      expect(countInkDominant(pixels, ink, fill)).toBeGreaterThan(0);
      // A transparent gap separates the badge from the base glyph.
      expect(countPixels(pixels, [0, 0, 0, 0])).toBeGreaterThan(0);
    }
  });

  it("keeps the badge in the bottom-right corner", () => {
    const pixels = painted("ok", 32, false);

    for (let y = 0; y < 32; y += 1) {
      for (let x = 0; x < 32; x += 1) {
        if (x < 10 || y < 10) {
          expect(pixelAt(pixels, 32, x, y)).toEqual(WHITE);
        }
      }
    }
  });

  it("tells the states apart by shape in monochrome template icons", () => {
    const masks = (["busy", "ok", "attention"] as const).map((tone) => {
      const pixels = painted(tone, 16, true);
      expect(countPixels(pixels, [0, 0, 0, 255])).toBeGreaterThan(0);
      // Template badges stay black; glyphs are cut out of them.
      for (let offset = 0; offset < pixels.length; offset += 4) {
        expect([pixels[offset], pixels[offset + 1], pixels[offset + 2]]).toEqual([0, 0, 0]);
      }
      return Array.from(pixels.filter((_, index) => index % 4 === 3)).join(",");
    });

    expect(new Set(masks).size).toBe(3);
  });

  it("dims the off icon to grayscale at the board's opacity and adds no badge", () => {
    const pixels = solidBitmap(16, [0, 0, 255, 255]);
    paintTrayTone(pixels, 16, 16, "off", { template: false });

    const alpha = Math.round(255 * TRAY_OFF_OPACITY);
    const gray = Math.round(0.2126 * 255 * TRAY_OFF_OPACITY);
    expect(pixelAt(pixels, 16, 0, 0)).toEqual([gray, gray, gray, alpha]);
    expect(pixelAt(pixels, 16, 15, 15)).toEqual([gray, gray, gray, alpha]);
  });

  it("dims a template icon without colouring it", () => {
    const pixels = solidBitmap(16, [0, 0, 0, 200]);
    paintTrayTone(pixels, 16, 16, "off", { template: true });

    expect(pixelAt(pixels, 16, 8, 8)).toEqual([0, 0, 0, Math.round(200 * TRAY_OFF_OPACITY)]);
  });

  it("rejects a bitmap smaller than its dimensions", () => {
    expect(() => paintTrayTone(new Uint8Array(16), 16, 16, "ok", { template: false })).toThrow();
  });
});

describe("tray icon composition", () => {
  function fakeOutput(): Electron.NativeImage & {
    addRepresentation: ReturnType<typeof vi.fn>;
    setTemplateImage: ReturnType<typeof vi.fn>;
  } {
    const representations: unknown[] = [];
    return {
      addRepresentation: vi.fn((representation: unknown) => {
        representations.push(representation);
      }),
      setTemplateImage: vi.fn(),
      isEmpty: () => representations.length === 0
    } as unknown as Electron.NativeImage & {
      addRepresentation: ReturnType<typeof vi.fn>;
      setTemplateImage: ReturnType<typeof vi.fn>;
    };
  }

  /** Like Electron: `getSize(scale)` answers in DIP, `toBitmap({ scaleFactor })` in pixels. */
  function fakeBase({
    template = false,
    scaleFactors = [1, 2],
    bitmapSize = (scale: number) => 16 * scale
  }: {
    template?: boolean;
    scaleFactors?: number[];
    bitmapSize?: (scale: number) => number;
  } = {}): Electron.NativeImage {
    return {
      isEmpty: () => false,
      isTemplateImage: () => template,
      getScaleFactors: () => scaleFactors,
      getSize: () => ({ width: 16, height: 16 }),
      toBitmap: ({ scaleFactor = 1 }: { scaleFactor?: number } = {}) =>
        Buffer.from(solidBitmap(bitmapSize(scaleFactor), [0, 0, 0, 255]))
    } as unknown as Electron.NativeImage;
  }

  it("composes every scale representation at its pixel size and keeps the template flag", () => {
    const output = fakeOutput();
    electron.createEmpty.mockReturnValueOnce(output);

    expect(composeTrayIcon(fakeBase({ template: true }), "ok")).toBe(output);
    expect(output.addRepresentation).toHaveBeenCalledTimes(2);
    expect(output.addRepresentation).toHaveBeenCalledWith(expect.objectContaining({ scaleFactor: 1, width: 16, height: 16 }));
    expect(output.addRepresentation).toHaveBeenCalledWith(expect.objectContaining({ scaleFactor: 2, width: 32, height: 32 }));
    expect(output.setTemplateImage).toHaveBeenCalledWith(true);
  });

  it("leaves out a representation it cannot read back and keeps the others", () => {
    const output = fakeOutput();
    electron.createEmpty.mockReturnValueOnce(output);
    const base = fakeBase({ bitmapSize: (scale) => (scale === 2 ? 7 : 16) });

    expect(composeTrayIcon(base, "busy")).toBe(output);
    expect(output.addRepresentation).toHaveBeenCalledOnce();
    expect(output.addRepresentation).toHaveBeenCalledWith(expect.objectContaining({ scaleFactor: 1, width: 16, height: 16 }));
  });

  it("falls back to the base icon when no representation can be read back", () => {
    electron.createEmpty.mockReturnValueOnce(fakeOutput());
    const base = fakeBase({ bitmapSize: () => 7 });

    expect(composeTrayIcon(base, "busy")).toBe(base);
  });

  it("works out pixel sizes from DIP sizes, including fractional scales", () => {
    expect(bitmapPixelSize({ width: 16, height: 16 }, 2, 32 * 32 * 4)).toEqual({ width: 32, height: 32 });
    expect(bitmapPixelSize({ width: 16, height: 16 }, 1.25, 20 * 20 * 4)).toEqual({ width: 20, height: 20 });
    // Electron truncates 21 / 1.25 to 16 DIP; the byte length still tells.
    expect(bitmapPixelSize({ width: 16, height: 16 }, 1.25, 21 * 21 * 4)).toEqual({ width: 21, height: 21 });
    expect(bitmapPixelSize({ width: 32, height: 16 }, 2, 64 * 32 * 4)).toEqual({ width: 64, height: 32 });
    expect(bitmapPixelSize({ width: 16, height: 16 }, 2, 0)).toBeUndefined();
    expect(bitmapPixelSize({ width: 32, height: 16 }, 2, 7 * 4)).toBeUndefined();
  });

  it("returns empty or unreadable base icons unchanged", () => {
    const empty = { isEmpty: () => true } as unknown as Electron.NativeImage;
    const broken = {
      isEmpty: () => false,
      isTemplateImage: () => {
        throw new Error("gone");
      }
    } as unknown as Electron.NativeImage;

    expect(composeTrayIcon(empty, "ok")).toBe(empty);
    expect(composeTrayIcon(broken, "ok")).toBe(broken);
  });
});

describe("Windows tray icon source", () => {
  it("sizes the icon for the notification area at the display scale", () => {
    expect(windowsTrayIconPixelSize(1)).toBe(16);
    expect(windowsTrayIconPixelSize(1.25)).toBe(20);
    expect(windowsTrayIconPixelSize(1.5)).toBe(24);
    expect(windowsTrayIconPixelSize(2)).toBe(32);
    expect(windowsTrayIconPixelSize(Number.NaN)).toBe(16);
    expect(windowsTrayIconPixelSize(10)).toBe(64);
  });

  it("shrinks the ICO image to one tray-sized bitmap before a tone is painted on it", () => {
    const small = { isEmpty: () => false } as unknown as Electron.NativeImage;
    electron.createFromBitmap.mockReturnValueOnce(small);
    const resize = vi.fn(() => ({ toBitmap: () => Buffer.from(solidBitmap(20, WHITE)) }));
    const base = { isEmpty: () => false, resize } as unknown as Electron.NativeImage;

    expect(windowsTrayIconSource(base, 20)).toBe(small);
    expect(resize).toHaveBeenCalledWith({ width: 20, height: 20, quality: "best" });
    expect(electron.createFromBitmap).toHaveBeenCalledWith(expect.any(Buffer), { width: 20, height: 20, scaleFactor: 1 });
  });

  it("keeps the base icon when it cannot be shrunk", () => {
    const empty = { isEmpty: () => true } as unknown as Electron.NativeImage;
    const odd = {
      isEmpty: () => false,
      resize: () => ({ toBitmap: () => Buffer.alloc(12) })
    } as unknown as Electron.NativeImage;

    expect(windowsTrayIconSource(empty, 16)).toBe(empty);
    expect(windowsTrayIconSource(odd, 16)).toBe(odd);
  });
});
