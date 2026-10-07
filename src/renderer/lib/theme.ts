import { DEFAULT_CUSTOM_THEME } from "../../shared/defaults.js";
import type { AppSettings, CustomTheme, RgbColor, ThemeMode } from "../../shared/types.js";

export type ResolvedTheme = "light" | "dark";

/** Built-in palettes, used for contrast checks against the current theme. */
export const THEME_BASES: Record<ResolvedTheme, { bg: string; surface: string; text: string; muted: string; ok: string; danger: string }> = {
  dark: { bg: "#0A0B0D", surface: "#14161A", text: "#F3F1EC", muted: "#7E838B", ok: "#34D08A", danger: "#F2555A" },
  light: { bg: "#F3F3F0", surface: "#FFFFFF", text: "#15161A", muted: "#686D76", ok: "#17A065", danger: "#D9363F" }
};

/** Dark ink used on the accent when it reads better than white. */
export const ACCENT_INK_DARK = "#1A1203";

/** Custom background lighter than this picks the light scheme (native controls, scrollbars). */
export const LIGHT_BACKGROUND_LUMINANCE = 0.3;

/**
 * Resolves the stored mode to the palette the tokens should use. Custom picks
 * light or dark from the luminance of its background.
 */
export function resolveTheme(mode: ThemeMode, systemPrefersDark: boolean, customTheme: CustomTheme = DEFAULT_CUSTOM_THEME): ResolvedTheme {
  if (mode === "custom") {
    return relativeLuminance(customTheme.background) > LIGHT_BACKGROUND_LUMINANCE ? "light" : "dark";
  }
  if (mode === "system") {
    return systemPrefersDark ? "dark" : "light";
  }
  return mode;
}

/**
 * CSS custom properties written on <html> on top of the `data-theme` tokens.
 *
 * - Accent applies in every mode; its text/soft/line steps derive in CSS.
 * - Success and Danger keep each theme's own shade while they equal the
 *   defaults, and override `--ok*` / `--danger*` once the user changes them.
 * - Custom maps the five palette colours onto the tokens and mixes the
 *   in-between steps exactly like Settings → Appearance previews them.
 */
export function createThemeVars(settings: Pick<AppSettings, "theme" | "customTheme">, resolved: ResolvedTheme): Record<string, string> {
  const palette = settings.customTheme;
  const custom = settings.theme === "custom";
  const vars: Record<string, string> = {};
  const accent = rgbToHex(palette.accent);
  vars["--accent"] = accent;
  vars["--ink-on-accent"] = inkOnAccent(accent);

  const text = custom ? rgbToHex(palette.text) : THEME_BASES[resolved].text;

  if (!sameColor(palette.success, DEFAULT_CUSTOM_THEME.success)) {
    Object.assign(vars, signalVars("ok", rgbToHex(palette.success), text));
  }
  if (!sameColor(palette.danger, DEFAULT_CUSTOM_THEME.danger)) {
    Object.assign(vars, signalVars("danger", rgbToHex(palette.danger), text));
  }

  if (custom) {
    const bg = rgbToHex(palette.background);
    const surface = rgbToHex(palette.surface);
    const border = rgbToHex(palette.border);
    const muted = rgbToHex(palette.muted);
    vars["--bg"] = bg;
    vars["--bg-2"] = mixHex(bg, text, 0.045);
    vars["--surface"] = surface;
    vars["--surface-2"] = mixHex(surface, text, 0.035);
    vars["--surface-3"] = mixHex(surface, text, 0.075);
    vars["--line"] = border;
    vars["--line-2"] = mixHex(border, text, 0.16);
    vars["--text"] = text;
    vars["--text-2"] = mixHex(muted, text, 0.4);
    vars["--text-3"] = muted;
    vars["--grid-dot"] = alpha(text, 0.045);
    vars["--term-bg"] = mixHex(bg, "#000000", 0.86);
  }
  return vars;
}

/** All custom properties createThemeVars can write, so stale ones can be removed. */
export const THEME_VAR_NAMES = [
  "--accent", "--ink-on-accent",
  "--ok", "--ok-text", "--ok-soft", "--ok-line",
  "--danger", "--danger-text", "--danger-soft", "--danger-line",
  "--bg", "--bg-2", "--surface", "--surface-2", "--surface-3", "--line", "--line-2",
  "--text", "--text-2", "--text-3", "--grid-dot", "--term-bg"
] as const;

function signalVars(name: "ok" | "danger", color: string, text: string): Record<string, string> {
  return {
    [`--${name}`]: color,
    [`--${name}-text`]: mixHex(color, text, 0.3),
    [`--${name}-soft`]: alpha(color, 0.13),
    [`--${name}-line`]: alpha(color, 0.38)
  };
}

/** Dark ink or white on the accent, whichever has more contrast. */
export function inkOnAccent(accent: string): string {
  return contrastRatio("#FFFFFF", accent) > contrastRatio(ACCENT_INK_DARK, accent) ? "#FFFFFF" : ACCENT_INK_DARK;
}

export function relativeLuminance(color: RgbColor | string): number {
  const rgb = typeof color === "string" ? hexToRgb(color) : color;
  const channels = [rgb.r, rgb.g, rgb.b].map((value) => {
    const channel = clampChannel(value) / 255;
    return channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

/** WCAG contrast ratio, 1–21. */
export function contrastRatio(a: RgbColor | string, b: RgbColor | string): number {
  const first = relativeLuminance(a);
  const second = relativeLuminance(b);
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
}

/** Hue in degrees (0–360), or undefined for greys. */
export function hue(color: RgbColor | string): number | undefined {
  const { r, g, b } = typeof color === "string" ? hexToRgb(color) : color;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  if (max === min) {
    return undefined;
  }
  const delta = max - min;
  let value: number;
  if (max === r) {
    value = ((g - b) / delta) % 6;
  } else if (max === g) {
    value = (b - r) / delta + 2;
  } else {
    value = (r - g) / delta + 4;
  }
  const degrees = value * 60;
  return degrees < 0 ? degrees + 360 : degrees;
}

/** Shortest distance between two hues in degrees. */
export function hueDistance(a: RgbColor | string, b: RgbColor | string): number | undefined {
  const first = hue(a);
  const second = hue(b);
  if (first === undefined || second === undefined) {
    return undefined;
  }
  const distance = Math.abs(first - second) % 360;
  return distance > 180 ? 360 - distance : distance;
}

/** Linear sRGB mix of two HEX colours; `amount` is the share of `b`. */
export function mixHex(a: string, b: string, amount: number): string {
  const x = hexToRgb(a);
  const y = hexToRgb(b);
  return rgbToHex({
    r: x.r + (y.r - x.r) * amount,
    g: x.g + (y.g - x.g) * amount,
    b: x.b + (y.b - x.b) * amount
  });
}

export function alpha(hex: string, opacity: number): string {
  const { r, g, b } = hexToRgb(hex);
  return `rgba(${r}, ${g}, ${b}, ${opacity})`;
}

export function rgb(color: RgbColor): string {
  return `rgb(${clampChannel(color.r)}, ${clampChannel(color.g)}, ${clampChannel(color.b)})`;
}

/** "#F6A019" (upper case, like the Settings HEX fields). */
export function rgbToHex(color: RgbColor): string {
  return `#${[color.r, color.g, color.b].map((value) => clampChannel(value).toString(16).padStart(2, "0")).join("").toUpperCase()}`;
}

/** Parses "#abc", "abc", "#AABBCC"; invalid input returns black. Use parseHex to validate. */
export function hexToRgb(value: string): RgbColor {
  return parseHex(value) ?? { r: 0, g: 0, b: 0 };
}

/** Strict HEX parser for user input; undefined when it is not 3 or 6 HEX digits. */
export function parseHex(value: string): RgbColor | undefined {
  let normalized = value.trim().replace(/^#/u, "");
  if (/^[0-9a-f]{3}$/iu.test(normalized)) {
    normalized = normalized.split("").map((character) => character + character).join("");
  }
  if (!/^[0-9a-f]{6}$/iu.test(normalized)) {
    return undefined;
  }
  return {
    r: parseInt(normalized.slice(0, 2), 16),
    g: parseInt(normalized.slice(2, 4), 16),
    b: parseInt(normalized.slice(4, 6), 16)
  };
}

export function sameColor(a: RgbColor, b: RgbColor): boolean {
  return clampChannel(a.r) === clampChannel(b.r) && clampChannel(a.g) === clampChannel(b.g) && clampChannel(a.b) === clampChannel(b.b);
}

function clampChannel(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.max(0, Math.min(255, Math.round(value)));
}
