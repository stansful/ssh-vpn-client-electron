import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

/** Origins only `npm run dev` needs: the dev server and its hot-reload socket. */
const DEV_SERVER_CSP_SOURCES = ["ws://127.0.0.1:5173", "http://127.0.0.1:5173"];

/**
 * The CSP of the built renderer: the same policy without the dev-server
 * origins, which the packaged app must never be allowed to reach. Throws
 * when the policy can't be found, so a build never ships them by accident.
 */
export function productionContentSecurityPolicy(html: string): string {
  let found = false;
  const result = html.replace(/(<meta http-equiv="Content-Security-Policy" content=")([^"]*)(")/u, (_match, start: string, policy: string, end: string) => {
    found = true;
    const cleaned = policy
      .split(";")
      .map((directive) =>
        directive
          .trim()
          .split(/\s+/u)
          .filter((token) => token && !DEV_SERVER_CSP_SOURCES.includes(token))
          .join(" ")
      )
      .join("; ")
      .trim();
    return `${start}${cleaned}${end}`;
  });
  if (!found || DEV_SERVER_CSP_SOURCES.some((source) => result.includes(source))) {
    throw new Error("index.html: the Content-Security-Policy still allows the dev server.");
  }
  return result;
}

function productionCsp(): Plugin {
  return {
    name: "shadow-production-csp",
    apply: "build",
    transformIndexHtml: {
      order: "pre",
      handler: productionContentSecurityPolicy
    }
  };
}

export default defineConfig({
  base: "./",
  plugins: [react(), productionCsp()],
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
