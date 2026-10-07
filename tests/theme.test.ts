import { describe, expect, it } from "vitest";
import { DEFAULT_CUSTOM_THEME, DEFAULT_SETTINGS } from "../src/shared/defaults.js";
import {
  contrastRatio,
  createThemeVars,
  hueDistance,
  inkOnAccent,
  mixHex,
  parseHex,
  resolveTheme,
  rgbToHex
} from "../src/renderer/lib/theme.js";

describe("theme resolution", () => {
  it("follows the OS for System and the background luminance for Custom", () => {
    expect(resolveTheme("system", true)).toBe("dark");
    expect(resolveTheme("system", false)).toBe("light");
    expect(resolveTheme("dark", false)).toBe("dark");
    expect(resolveTheme("custom", true, DEFAULT_CUSTOM_THEME)).toBe("light");
    expect(resolveTheme("custom", false, { ...DEFAULT_CUSTOM_THEME, background: { r: 11, g: 13, b: 16 } })).toBe("dark");
  });
});

describe("theme variables", () => {
  it("leaves the theme's own signal shades alone while they are the defaults", () => {
    const variables = createThemeVars(DEFAULT_SETTINGS, "dark");

    expect(variables["--accent"]).toBe("#F6A019");
    expect(variables["--ink-on-accent"]).toBe("#1A1203");
    expect(variables["--ok"]).toBeUndefined();
    expect(variables["--danger"]).toBeUndefined();
    expect(variables["--bg"]).toBeUndefined();
  });

  it("overrides success and danger with derived text/soft/line steps once changed", () => {
    const variables = createThemeVars(
      { theme: "dark", customTheme: { ...DEFAULT_CUSTOM_THEME, success: { r: 0, g: 200, b: 255 } } },
      "dark"
    );

    expect(variables["--ok"]).toBe("#00C8FF");
    expect(variables["--ok-soft"]).toBe("rgba(0, 200, 255, 0.13)");
    expect(variables["--ok-line"]).toBe("rgba(0, 200, 255, 0.38)");
    expect(variables["--ok-text"]).toBe(mixHex("#00C8FF", "#F3F1EC", 0.3));
    expect(variables["--danger"]).toBeUndefined();
  });

  it("maps a custom palette onto the tokens and mixes the in-between steps", () => {
    const customTheme = {
      ...DEFAULT_CUSTOM_THEME,
      background: { r: 11, g: 13, b: 16 },
      surface: { r: 20, g: 22, b: 26 },
      text: { r: 240, g: 240, b: 240 },
      muted: { r: 120, g: 120, b: 130 },
      border: { r: 40, g: 44, b: 50 }
    };
    const variables = createThemeVars({ theme: "custom", customTheme }, "dark");

    expect(variables["--bg"]).toBe("#0B0D10");
    expect(variables["--surface"]).toBe("#14161A");
    expect(variables["--text"]).toBe("#F0F0F0");
    expect(variables["--text-3"]).toBe("#787882");
    expect(variables["--bg-2"]).toBe(mixHex("#0B0D10", "#F0F0F0", 0.045));
    expect(variables["--line-2"]).toBe(mixHex("#282C32", "#F0F0F0", 0.16));
    expect(variables["--term-bg"]).toBe(mixHex("#0B0D10", "#000000", 0.86));
  });

  it("picks white ink only on dark accents", () => {
    expect(inkOnAccent("#F6A019")).toBe("#1A1203");
    expect(inkOnAccent("#1F3A93")).toBe("#FFFFFF");
  });
});

describe("colour helpers", () => {
  it("parses 3 and 6 digit HEX and rejects anything else", () => {
    expect(parseHex("#abc")).toEqual({ r: 170, g: 187, b: 204 });
    expect(parseHex("F6A019")).toEqual({ r: 246, g: 160, b: 25 });
    expect(parseHex("#12345")).toBeUndefined();
    expect(parseHex("orange")).toBeUndefined();
    expect(rgbToHex({ r: 300, g: -4, b: 15.6 })).toBe("#FF0010");
  });

  it("measures contrast and hue distance for the palette checks", () => {
    expect(contrastRatio("#000000", "#FFFFFF")).toBeCloseTo(21, 5);
    expect(contrastRatio("#777777", "#777777")).toBeCloseTo(1, 5);
    expect(hueDistance("#FF0000", "#FF3300")).toBeLessThan(30);
    expect(hueDistance("#F6A019", "#2F6FD6")).toBeGreaterThan(150);
    expect(hueDistance("#808080", "#FF0000")).toBeUndefined();
  });
});
