import { useEffect, useState } from "react";
import type { ThemeMode } from "../../shared/types.js";

const DARK_SCHEME_QUERY = "(prefers-color-scheme: dark)";

export function useResolvedTheme(mode: ThemeMode): Exclude<ThemeMode, "system"> {
  const [systemTheme, setSystemTheme] = useState<"light" | "dark">(
    () => window.matchMedia(DARK_SCHEME_QUERY).matches ? "dark" : "light"
  );

  useEffect(() => {
    if (mode !== "system") {
      return;
    }
    const media = window.matchMedia(DARK_SCHEME_QUERY);
    const synchronize = (): void => setSystemTheme(media.matches ? "dark" : "light");
    synchronize();
    media.addEventListener("change", synchronize);
    return () => media.removeEventListener("change", synchronize);
  }, [mode]);

  return mode === "system" ? systemTheme : mode;
}
