import type { CSSProperties } from "react";
import type { AppSettings } from "../../../shared/types.js";
import { hexToRgb, rgb, rgbToHex } from "../../lib/theme.js";

export function ThemeDesigner({
  settings,
  onChange
}: {
  settings: AppSettings;
  onChange: (patch: Partial<AppSettings>) => void;
}): JSX.Element {
  const entries = [
    ["accent", "Accent"],
    ["success", "Success"],
    ["danger", "Danger"],
    ["background", "Background"],
    ["surface", "Surface"],
    ["text", "Text"],
    ["muted", "Muted text"],
    ["border", "Borders"]
  ] as const;
  const wheelStyle = {
    background: `conic-gradient(${entries
      .map(([key], index) => `${rgb(settings.customTheme[key])} ${index * (100 / entries.length)}% ${(index + 1) * (100 / entries.length)}%`)
      .join(", ")})`
  } satisfies CSSProperties;

  return (
    <div className="theme-designer">
      <div className="theme-wheel" style={wheelStyle} aria-hidden="true">
        <div className="theme-wheel-core">Theme</div>
      </div>
      <div className="theme-swatches">
        {entries.map(([key, label]) => (
          <label key={key} className="theme-swatch">
            <input
              type="color"
              value={rgbToHex(settings.customTheme[key])}
              onChange={(event) =>
                onChange({
                  customTheme: {
                    ...settings.customTheme,
                    [key]: hexToRgb(event.target.value)
                  }
                })
              }
            />
            <span style={{ background: rgb(settings.customTheme[key]) }} />
            <strong>{label}</strong>
          </label>
        ))}
      </div>
    </div>
  );
}
