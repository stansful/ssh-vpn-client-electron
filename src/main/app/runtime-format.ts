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
      body { margin: 0; font: 14px system-ui, sans-serif; color: #20242a; background: #f6f7f9; }
      main { padding: 32px; max-width: 860px; }
      h1 { margin: 0 0 12px; font-size: 24px; }
      pre { white-space: pre-wrap; background: #fff; border: 1px solid #d6dae0; padding: 16px; border-radius: 8px; }
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
