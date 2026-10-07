import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "./",
  plugins: [react()],
  build: {
    outDir: "dist/renderer",
    emptyOutDir: true,
    // Never inline fonts as data: URLs: the renderer CSP only allows 'self'.
    assetsInlineLimit: (filePath) => (/\.(woff2?|ttf|otf)$/u.test(filePath) ? false : undefined)
  },
  server: {
    port: 5173,
    strictPort: true
  }
});
