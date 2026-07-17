import path from "node:path";
import { fileURLToPath } from "node:url";

export interface RuntimeFormatOptions {
  packaged: boolean;
  resourcesPath: string;
}

export function formatError(error: unknown): string {
  if (error instanceof Error) {
    return `${error.message}${error.stack ? `\n${error.stack}` : ""}`;
  }
  return String(error);
}

export function createErrorDataUrl(message: string): string {
  const html = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Shadow SSH startup error</title>
    <style>
      :root { color-scheme: dark; }
      body { margin: 0; font: 14px -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; color: #f5f6f8; background: #0b0d10; }
      main { box-sizing: border-box; width: min(760px, calc(100% - 40px)); margin: 10vh auto 0; padding: 28px; border: 1px solid #2b313b; border-radius: 20px; background: #171b22; box-shadow: 0 30px 90px rgb(0 0 0 / 34%); }
      h1 { margin: 0 0 10px; font-size: 24px; letter-spacing: -.025em; }
      p { color: #a6afbd; line-height: 1.5; }
      pre { max-height: 42vh; overflow: auto; white-space: pre-wrap; color: #ff9ba5; background: #11141a; border: 1px solid #3b252b; padding: 16px; border-radius: 12px; }
    </style>
  </head>
  <body>
    <main>
      <h1>Shadow SSH could not load the UI</h1>
      <p>Check the main process log under the application data directory.</p>
      <pre>${escapeHtml(message)}</pre>
    </main>
  </body>
</html>`;
  return `data:text/html;charset=utf-8,${encodeURIComponent(html)}`;
}

export function formatRuntimePath(options: RuntimeFormatOptions, value: string): string {
  if (!options.packaged || !value) {
    return value;
  }
  const resourcesPath = path.normalize(options.resourcesPath);
  const normalized = path.normalize(value);
  if (normalized === resourcesPath) {
    return "[app-resources]";
  }
  if (normalized.startsWith(`${resourcesPath}${path.sep}`)) {
    return path.join("[app-resources]", path.relative(resourcesPath, normalized));
  }
  return value;
}

export function formatRuntimeUrl(options: RuntimeFormatOptions, value: string): string {
  if (!options.packaged || !value) {
    return value;
  }
  try {
    const url = new URL(value);
    if (url.protocol !== "file:") {
      return value;
    }
    return `file://${formatRuntimePath(options, fileURLToPath(url))}`;
  } catch {
    return formatRuntimePath(options, value);
  }
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}
