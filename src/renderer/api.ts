import type { ShadowSshApi } from "../shared/ipc.js";
import { createBrowserPreviewApi } from "./browser-preview-api.js";

export const api: ShadowSshApi = window.shadowSsh ?? (import.meta.env.DEV ? createBrowserPreviewApi() : missingPreloadApi());

function missingPreloadApi(): never {
  throw new Error("Shadow SSH preload API is unavailable. Start the application through Electron.");
}
