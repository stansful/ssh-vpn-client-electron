import type { ShadowSshApi } from "../shared/ipc.js";
import { createBrowserPreviewApi } from "./browser-preview-api.js";
import { createDefaultRuntimeStatus, createDefaultStore } from "../shared/defaults.js";

const missingPreloadMessage = "Shadow SSH preload API is unavailable. Restart the packaged application and check main.log.";

export const api: ShadowSshApi = window.shadowSsh ?? (import.meta.env.DEV ? createBrowserPreviewApi() : createMissingPreloadApi());

function createMissingPreloadApi(): ShadowSshApi {
  const reject = (): Promise<never> => Promise.reject(new Error(missingPreloadMessage));
  return {
    loadSnapshot: () =>
      Promise.resolve({
        store: createDefaultStore(),
        runtime: createDefaultRuntimeStatus({
          platform: "unknown",
          arch: "unknown",
          serviceExecutableName: "shadow-ssh-service",
          serviceRelativePath: "native/unknown/unknown/shadow-ssh-service",
          supportsPrivilegedService: false
        }),
        diagnostics: [
          {
            id: "missing-preload-api",
            at: new Date().toISOString(),
            level: "error",
            message: missingPreloadMessage
          }
        ],
        logFilePaths: [],
        terminal: []
      }),
    upsertConfig: reject,
    deleteConfig: reject,
    selectConfig: reject,
    upsertKey: reject,
    copyPrivateKey: reject,
    deleteKey: reject,
    updateSettings: reject,
    updateRoutingMode: reject,
    updateRoutingRules: reject,
    clearDiagnostics: reject,
    readLogFile: () => Promise.resolve(""),
    clearLogFile: () => Promise.resolve(""),
    listProcesses: () => Promise.resolve([]),
    connect: reject,
    disconnect: reject,
    checkTunnel: reject,
    openTerminal: reject,
    closeTerminal: reject,
    terminalInput: () => Promise.reject(new Error(missingPreloadMessage)),
    onServiceEvent: () => () => undefined
  };
}
