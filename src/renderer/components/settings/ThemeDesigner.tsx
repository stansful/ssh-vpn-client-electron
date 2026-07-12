import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import type { AppSettings, CustomTheme } from "../../../shared/types.js";
import { hexToRgb, rgb, rgbToHex } from "../../lib/theme.js";

const THEME_ENTRIES = [
  ["accent", "Accent"],
  ["success", "Success"],
  ["danger", "Danger"],
  ["background", "Background"],
  ["surface", "Surface"],
  ["text", "Text"],
  ["muted", "Muted text"],
  ["border", "Borders"]
] as const;

export function ThemeDesigner({
  settings,
  onChange
}: {
  settings: AppSettings;
  onChange: (patch: Partial<AppSettings>) => void;
}): JSX.Element {
  const [draftTheme, setDraftTheme] = useState(settings.customTheme);
  const pendingTheme = useRef<CustomTheme>();
  const debounceTimer = useRef<ReturnType<typeof setTimeout>>();
  const onChangeRef = useRef(onChange);
  const wheelStyle = useMemo(() => ({
    background: `conic-gradient(${THEME_ENTRIES
      .map(([key], index) => `${rgb(draftTheme[key])} ${index * (100 / THEME_ENTRIES.length)}% ${(index + 1) * (100 / THEME_ENTRIES.length)}%`)
      .join(", ")})`
  } satisfies CSSProperties), [draftTheme]);

  useEffect(() => {
    if (!pendingTheme.current) {
      setDraftTheme(settings.customTheme);
    }
  }, [settings.customTheme]);

  useEffect(() => {
    onChangeRef.current = onChange;
  }, [onChange]);

  useEffect(() => () => {
    if (debounceTimer.current) {
      clearTimeout(debounceTimer.current);
    }
    const theme = pendingTheme.current;
    pendingTheme.current = undefined;
    if (theme) {
      onChangeRef.current({ customTheme: theme });
    }
  }, []);

  function scheduleThemeUpdate(theme: CustomTheme): void {
    setDraftTheme(theme);
    pendingTheme.current = theme;
    if (debounceTimer.current) {
      clearTimeout(debounceTimer.current);
    }
    debounceTimer.current = setTimeout(flushThemeUpdate, 150);
  }

  function flushThemeUpdate(): void {
    if (debounceTimer.current) {
      clearTimeout(debounceTimer.current);
      debounceTimer.current = undefined;
    }
    const theme = pendingTheme.current;
    pendingTheme.current = undefined;
    if (theme) {
      onChange({ customTheme: theme });
    }
  }

  return (
    <div className="theme-designer">
      <div className="theme-wheel" style={wheelStyle} aria-hidden="true">
        <div className="theme-wheel-core">Theme</div>
      </div>
      <div className="theme-swatches">
        {THEME_ENTRIES.map(([key, label]) => (
          <label key={key} className="theme-swatch">
            <input
              type="color"
              value={rgbToHex(draftTheme[key])}
              onBlur={flushThemeUpdate}
              onChange={(event) => scheduleThemeUpdate({
                ...draftTheme,
                [key]: hexToRgb(event.target.value)
              })}
            />
            <span style={{ background: rgb(draftTheme[key]) }} />
            <strong>{label}</strong>
          </label>
        ))}
      </div>
    </div>
  );
}
