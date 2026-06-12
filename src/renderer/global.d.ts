import type { ShadowSshApi } from "../shared/ipc.js";

declare global {
  interface Window {
    shadowSsh: ShadowSshApi;
  }
}

export {};
