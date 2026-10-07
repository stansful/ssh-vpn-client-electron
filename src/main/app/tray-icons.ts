import { nativeImage } from "electron";
import { DEFAULT_CUSTOM_THEME } from "../../shared/defaults.js";

export type TrayTone = "off" | "busy" | "ok" | "attention";

type BadgeTone = Exclude<TrayTone, "off">;

interface Rgb {
  r: number;
  g: number;
  b: number;
}

// Night Signal signal colours (--accent, --ok, --danger) with the board's badge ink.
const BADGE_FILL: Record<BadgeTone, Rgb> = {
  busy: DEFAULT_CUSTOM_THEME.accent,
  ok: DEFAULT_CUSTOM_THEME.success,
  attention: DEFAULT_CUSTOM_THEME.danger
};
const DARK_INK: Rgb = { r: 16, g: 17, b: 19 };
const BADGE_INK: Record<BadgeTone, Rgb> = {
  busy: DARK_INK,
  ok: DARK_INK,
  attention: { r: 255, g: 255, b: 255 }
};

/** The board dims the off icon: grayscale at 55 % opacity. */
export const TRAY_OFF_OPACITY = 0.55;
const BADGE_DIAMETER = 0.5625;
const BADGE_GAP = 0.0625;
const SUPERSAMPLE = 4;
const MIN_STROKE_HALF_WIDTH_PX = 0.62;
const MIN_DOT_RADIUS_PX = 0.72;

export interface TrayToneBitmapOptions {
  /** macOS template images carry shape only, so the badge is cut out instead of coloured. */
  template: boolean;
}

/**
 * Paints the tone onto a premultiplied 32-bit bitmap (the layout `toBitmap()`
 * returns and `addRepresentation({ buffer, width, height })` accepts) in place.
 * Only the shared colour order matters: index 3 is alpha, 0-2 are B, G, R on
 * every little-endian platform Electron ships for.
 */
export function paintTrayTone(
  pixels: Uint8Array,
  width: number,
  height: number,
  tone: TrayTone,
  { template }: TrayToneBitmapOptions
): void {
  if (pixels.length < width * height * 4) {
    throw new Error("Tray bitmap is smaller than its dimensions.");
  }
  if (tone === "off") {
    dimBitmap(pixels, width * height, template);
    return;
  }
  paintBadge(pixels, width, height, tone, template);
}

/**
 * Builds the tray image for a tone from the loaded base icon, keeping every
 * scale representation (macOS @2x, Windows ICO sizes) and the template flag.
 * A representation that cannot be read back is left out; the base icon is
 * returned only when none can.
 */
export function composeTrayIcon(base: Electron.NativeImage, tone: TrayTone): Electron.NativeImage {
  try {
    if (base.isEmpty()) {
      return base;
    }
    const template = base.isTemplateImage();
    const scaleFactors = base.getScaleFactors();
    const output = nativeImage.createEmpty();
    for (const scaleFactor of scaleFactors.length > 0 ? scaleFactors : [1]) {
      const bitmap = base.toBitmap({ scaleFactor });
      const size = bitmapPixelSize(base.getSize(scaleFactor), scaleFactor, bitmap.length);
      if (!size) {
        continue;
      }
      paintTrayTone(bitmap, size.width, size.height, tone, { template });
      output.addRepresentation({ scaleFactor, width: size.width, height: size.height, buffer: bitmap });
    }
    if (output.isEmpty()) {
      return base;
    }
    if (template) {
      output.setTemplateImage(true);
    }
    return output;
  } catch {
    return base;
  }
}

/**
 * The pixel size of the bitmap `toBitmap({ scaleFactor })` returned.
 * `getSize(scaleFactor)` answers in DIP (a 32 px @2x representation reports
 * 16x16), so the pixel size is that times the scale. Electron truncates
 * pixels / scale to whole DIP, so at a fractional scale a square bitmap may
 * be one pixel larger; the byte length settles it.
 */
export function bitmapPixelSize(
  dipSize: { width: number; height: number },
  scaleFactor: number,
  byteLength: number
): { width: number; height: number } | undefined {
  const pixels = byteLength / 4;
  if (!Number.isInteger(pixels) || pixels <= 0 || !(scaleFactor > 0)) {
    return undefined;
  }
  const width = Math.round(dipSize.width * scaleFactor);
  const height = Math.round(dipSize.height * scaleFactor);
  if (width > 0 && height > 0 && width * height === pixels) {
    return { width, height };
  }
  const side = Math.round(Math.sqrt(pixels));
  if (dipSize.width > 0 && dipSize.width === dipSize.height && side * side === pixels && Math.floor(side / scaleFactor + 1e-9) === dipSize.width) {
    return { width: side, height: side };
  }
  return undefined;
}

/** The notification area's icon size in physical pixels: 16 px at 100 % scaling. */
export function windowsTrayIconPixelSize(scaleFactor: number): number {
  const factor = Number.isFinite(scaleFactor) && scaleFactor > 0 ? scaleFactor : 1;
  return Math.min(64, Math.max(16, Math.round(16 * factor)));
}

/**
 * Windows draws a tray icon from the image's 1x bitmap and lets the shell
 * shrink it. The ICO image picks its small frame from the file, but a
 * composed image has no file, so the tone would be painted on a large frame
 * (with large-badge geometry) and then scaled down until the glyph is
 * illegible. Composing on a bitmap that is already tray-sized avoids both.
 */
export function windowsTrayIconSource(base: Electron.NativeImage, pixelSize: number): Electron.NativeImage {
  try {
    if (base.isEmpty()) {
      return base;
    }
    const resized = base.resize({ width: pixelSize, height: pixelSize, quality: "best" });
    const bitmap = resized.toBitmap({ scaleFactor: 1 });
    if (bitmap.length !== pixelSize * pixelSize * 4) {
      return base;
    }
    return nativeImage.createFromBitmap(bitmap, { width: pixelSize, height: pixelSize, scaleFactor: 1 });
  } catch {
    return base;
  }
}

function dimBitmap(pixels: Uint8Array, count: number, template: boolean): void {
  for (let index = 0; index < count; index += 1) {
    const offset = index * 4;
    if (template) {
      pixels[offset + 3] = Math.round(pixels[offset + 3] * TRAY_OFF_OPACITY);
      continue;
    }
    // Premultiplied channels stay premultiplied under a linear grayscale mix.
    const gray =
      0.0722 * pixels[offset] + 0.7152 * pixels[offset + 1] + 0.2126 * pixels[offset + 2];
    const value = Math.round(gray * TRAY_OFF_OPACITY);
    pixels[offset] = value;
    pixels[offset + 1] = value;
    pixels[offset + 2] = value;
    pixels[offset + 3] = Math.round(pixels[offset + 3] * TRAY_OFF_OPACITY);
  }
}

type SampleKind = "keep" | "clear" | "fill" | "ink";

function paintBadge(pixels: Uint8Array, width: number, height: number, tone: BadgeTone, template: boolean): void {
  const size = Math.min(width, height);
  const radius = (size * BADGE_DIAMETER) / 2;
  const gap = Math.max(1, size * BADGE_GAP);
  const centerX = width - radius;
  const centerY = height - radius;
  const outer = radius + gap;
  const glyph = createGlyph(tone, radius);
  const fill = template ? { r: 0, g: 0, b: 0 } : BADGE_FILL[tone];
  const ink = BADGE_INK[tone];
  const samples = SUPERSAMPLE * SUPERSAMPLE;

  const startX = Math.max(0, Math.floor(centerX - outer));
  const startY = Math.max(0, Math.floor(centerY - outer));
  for (let y = startY; y < height; y += 1) {
    for (let x = startX; x < width; x += 1) {
      let kept = 0;
      let blue = 0;
      let green = 0;
      let red = 0;
      let alpha = 0;
      for (let sampleY = 0; sampleY < SUPERSAMPLE; sampleY += 1) {
        for (let sampleX = 0; sampleX < SUPERSAMPLE; sampleX += 1) {
          const dx = x + (sampleX + 0.5) / SUPERSAMPLE - centerX;
          const dy = y + (sampleY + 0.5) / SUPERSAMPLE - centerY;
          const kind = classifySample(dx, dy, radius, outer, glyph, template);
          if (kind === "keep") {
            kept += 1;
          } else if (kind !== "clear") {
            const color = kind === "fill" ? fill : ink;
            blue += color.b;
            green += color.g;
            red += color.r;
            alpha += 255;
          }
        }
      }
      if (kept === samples) {
        continue;
      }
      const offset = (y * width + x) * 4;
      const keep = kept / samples;
      pixels[offset] = Math.round(pixels[offset] * keep + blue / samples);
      pixels[offset + 1] = Math.round(pixels[offset + 1] * keep + green / samples);
      pixels[offset + 2] = Math.round(pixels[offset + 2] * keep + red / samples);
      pixels[offset + 3] = Math.round(pixels[offset + 3] * keep + alpha / samples);
    }
  }
}

function classifySample(
  dx: number,
  dy: number,
  radius: number,
  outer: number,
  glyph: (x: number, y: number) => boolean,
  template: boolean
): SampleKind {
  const distance = Math.hypot(dx, dy);
  if (distance > outer) {
    return "keep";
  }
  if (distance > radius) {
    return "clear";
  }
  if (!glyph(dx, dy)) {
    return "fill";
  }
  return template ? "clear" : "ink";
}

/**
 * Glyphs follow the board's Lucide shapes (check, three dots, "!") in a 24-unit
 * box. Small badges get a larger box and a minimum stroke so the 16 px icon
 * still reads by shape, not only by colour.
 */
function createGlyph(tone: BadgeTone, radius: number): (x: number, y: number) => boolean {
  const small = radius < 6;
  const extent = small ? 0.8 : 0.6;
  const unit = (radius * extent) / 12;
  const point = (x: number, y: number): [number, number] => [(x - 12) * unit, (y - 12) * unit];
  const half = Math.max(1.6 * unit, MIN_STROKE_HALF_WIDTH_PX);

  if (tone === "ok") {
    const a = point(20, 6);
    const b = point(9, 17);
    const c = point(4, 12);
    return (x, y) => segmentDistance(x, y, a, b) <= half || segmentDistance(x, y, b, c) <= half;
  }
  if (tone === "busy") {
    const spread = small ? 7.5 : 6;
    const dots = [point(12 - spread, 12), point(12, 12), point(12 + spread, 12)];
    const dotRadius = Math.max(2.3 * unit, MIN_DOT_RADIUS_PX);
    return (x, y) => dots.some(([cx, cy]) => Math.hypot(x - cx, y - cy) <= dotRadius);
  }
  const top = point(12, small ? 5.5 : 6);
  const bottom = point(12, small ? 11.5 : 13);
  const dot = point(12, small ? 18.5 : 18);
  return (x, y) => segmentDistance(x, y, top, bottom) <= half || Math.hypot(x - dot[0], y - dot[1]) <= half;
}

function segmentDistance(x: number, y: number, [x1, y1]: [number, number], [x2, y2]: [number, number]): number {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const lengthSquared = dx * dx + dy * dy;
  const t = lengthSquared === 0 ? 0 : Math.max(0, Math.min(1, ((x - x1) * dx + (y - y1) * dy) / lengthSquared));
  return Math.hypot(x - (x1 + t * dx), y - (y1 + t * dy));
}
