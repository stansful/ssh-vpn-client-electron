import type { CSSProperties } from "react";
import type { AppSettings, RgbColor, ThemeMode } from "../../shared/types.js";

export function resolveTheme(mode: ThemeMode): string {
  if (mode === "system") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return mode;
}

export function createThemeVars(settings: AppSettings): CSSProperties {
  const { accent, success, danger, background, surface, text, muted, border } = settings.customTheme;
  return {
    colorScheme: settings.theme === "custom" ? preferredColorScheme(background) : undefined,
    "--accent": rgb(accent),
    "--success": rgb(success),
    "--danger": rgb(danger),
    "--accent-ink": contrastInk(accent),
    "--danger-ink": contrastInk(danger),
    "--custom-accent": rgb(accent),
    "--custom-success": rgb(success),
    "--custom-danger": rgb(danger),
    "--custom-background": rgb(background),
    "--custom-surface": rgb(surface),
    "--custom-text": rgb(text),
    "--custom-muted": rgb(muted),
    "--custom-border": rgb(border)
  } as CSSProperties;
}

function contrastInk(color: RgbColor): string {
  const backgroundLuminance = relativeLuminance(color);
  const lightContrast = 1.05 / (backgroundLuminance + 0.05);
  const darkContrast = (backgroundLuminance + 0.05) / (relativeLuminance({ r: 23, g: 19, b: 13 }) + 0.05);
  return darkContrast > lightContrast ? "#17130d" : "#ffffff";
}

function preferredColorScheme(color: RgbColor): "dark" | "light" {
  return relativeLuminance(color) > 0.3 ? "light" : "dark";
}

function relativeLuminance(color: RgbColor): number {
  const channels = [color.r, color.g, color.b].map((value) => {
    const channel = clampRgb(value) / 255;
    return channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

export function rgb(color: RgbColor): string {
  return `rgb(${color.r}, ${color.g}, ${color.b})`;
}

export function rgbToHex(color: RgbColor): string {
  return `#${[color.r, color.g, color.b].map((value) => clampRgb(value).toString(16).padStart(2, "0")).join("")}`;
}

export function hexToRgb(value: string): RgbColor {
  const normalized = value.replace("#", "").trim();
  if (!/^[0-9a-f]{6}$/iu.test(normalized)) {
    return { r: 0, g: 0, b: 0 };
  }
  return {
    r: parseInt(normalized.slice(0, 2), 16),
    g: parseInt(normalized.slice(2, 4), 16),
    b: parseInt(normalized.slice(4, 6), 16)
  };
}

function clampRgb(value: number): number {
  if (Number.isNaN(value)) {
    return 0;
  }
  return Math.max(0, Math.min(255, value));
}
