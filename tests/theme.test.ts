import { describe, expect, it } from "vitest";
import { DEFAULT_SETTINGS } from "../src/shared/defaults.js";
import { createThemeVars } from "../src/renderer/lib/theme.js";

describe("theme variables", () => {
  it("keeps saved semantic colours active across built-in palettes", () => {
    const variables = createThemeVars(DEFAULT_SETTINGS) as Record<string, string | undefined>;

    expect(variables["--accent"]).toBe("rgb(246, 139, 0)");
    expect(variables["--success"]).toBe("rgb(31, 145, 97)");
    expect(variables["--danger"]).toBe("rgb(207, 63, 75)");
    expect(variables["--accent-ink"]).toBe("#17130d");
    expect(variables["--danger-ink"]).toBe("#ffffff");
  });

  it("chooses readable ink and native controls for a dark custom palette", () => {
    const variables = createThemeVars({
      ...DEFAULT_SETTINGS,
      theme: "custom",
      customTheme: {
        ...DEFAULT_SETTINGS.customTheme,
        accent: { r: 0, g: 160, b: 80 },
        danger: { r: 255, g: 101, b: 116 },
        background: { r: 11, g: 13, b: 16 }
      }
    }) as Record<string, string | undefined>;

    expect(variables.colorScheme).toBe("dark");
    expect(variables["--accent-ink"]).toBe("#17130d");
    expect(variables["--danger-ink"]).toBe("#17130d");
  });
});
