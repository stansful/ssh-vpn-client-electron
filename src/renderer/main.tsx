import "@fontsource-variable/onest";
import "@fontsource-variable/unbounded";
import "@fontsource-variable/jetbrains-mono";
import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.js";
import { systemPrefersDark } from "./hooks/useResolvedTheme.js";
import "./styles.css";

// Paint the startup screen in the OS theme before React runs; the saved
// theme replaces it once settings load.
document.documentElement.setAttribute("data-theme", systemPrefersDark() ? "dark" : "light");

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
