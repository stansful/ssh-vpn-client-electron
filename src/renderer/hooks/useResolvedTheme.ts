import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createThemeVars, resolveTheme, THEME_VAR_NAMES, type ResolvedTheme } from "../lib/theme.js";
import type { AppSettings } from "../../shared/types.js";

const DARK_SCHEME_QUERY = "(prefers-color-scheme: dark)";
const THEME_SWITCH_MS = 450;

export function systemPrefersDark(): boolean {
  return typeof window.matchMedia === "function" && window.matchMedia(DARK_SCHEME_QUERY).matches;
}

/** Follows the OS light/dark preference live. */
export function useSystemPrefersDark(): boolean {
  const [dark, setDark] = useState(systemPrefersDark);
  useEffect(() => {
    if (typeof window.matchMedia !== "function") {
      return undefined;
    }
    const media = window.matchMedia(DARK_SCHEME_QUERY);
    const synchronize = (): void => setDark(media.matches);
    synchronize();
    media.addEventListener("change", synchronize);
    return () => media.removeEventListener("change", synchronize);
  }, []);
  return dark;
}

/** The palette in use: "light" or "dark" (System follows the OS, Custom its background). */
export function useResolvedTheme(settings: Pick<AppSettings, "theme" | "customTheme"> | undefined): ResolvedTheme {
  const prefersDark = useSystemPrefersDark();
  return settings ? resolveTheme(settings.theme, prefersDark, settings.customTheme) : prefersDark ? "dark" : "light";
}

/**
 * Applies the theme to <html>: `data-theme` (light/dark), `data-theme-mode`
 * (system/light/dark/custom) and the custom properties for the user's signal
 * colours and custom palette. Before settings load it follows the OS.
 * Changes after the first paint cross-fade colours briefly.
 */
export function useApplyTheme(settings: Pick<AppSettings, "theme" | "customTheme"> | undefined): ResolvedTheme {
  const resolved = useResolvedTheme(settings);
  const firstApply = useRef(true);
  const switchTimer = useRef<number>();

  useLayoutEffect(() => {
    const root = document.documentElement;
    const previousTheme = root.getAttribute("data-theme");
    const previousMode = root.getAttribute("data-theme-mode");
    const mode = settings?.theme ?? "system";
    if (!firstApply.current && (previousTheme !== resolved || previousMode !== mode)) {
      root.setAttribute("data-theme-switching", "");
      window.clearTimeout(switchTimer.current);
      switchTimer.current = window.setTimeout(() => root.removeAttribute("data-theme-switching"), THEME_SWITCH_MS);
    }
    firstApply.current = false;
    root.setAttribute("data-theme", resolved);
    root.setAttribute("data-theme-mode", mode);

    const vars = settings ? createThemeVars(settings, resolved) : {};
    for (const name of THEME_VAR_NAMES) {
      const value = vars[name];
      if (value === undefined) {
        root.style.removeProperty(name);
      } else {
        root.style.setProperty(name, value);
      }
    }
  }, [resolved, settings]);

  useEffect(() => () => window.clearTimeout(switchTimer.current), []);

  return resolved;
}
