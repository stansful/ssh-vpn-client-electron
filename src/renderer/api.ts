import type { ShadowSshApi } from "../shared/ipc.js";
import { createBrowserPreviewApi } from "./browser-preview-api.js";

const missingPreloadMessage = "Shadow SSH preload API is unavailable. Restart the packaged application and check main.log.";

export const api: ShadowSshApi = window.shadowSsh ?? (import.meta.env.DEV ? createBrowserPreviewApi() : createMissingPreloadApi());

function createMissingPreloadApi(): ShadowSshApi {
  const reject = (): Promise<never> => Promise.reject(new Error(missingPreloadMessage));
  return {
    loadSnapshot: reject,
    upsertConfig: reject,
    deleteConfig: reject,
    selectConfig: reject,
    upsertKey: reject,
    copyPrivateKey: reject,
    deleteKey: reject,
    upsertProxyProfile: reject,
    importProxyProfiles: reject,
    refreshProxyProfiles: reject,
    selectProxyProfile: reject,
    toggleProxyProfilePin: reject,
    deleteProxyProfile: reject,
    deleteUnpinnedProxyProfiles: reject,
    updateSettings: reject,
    updateRoutingMode: reject,
    updateRoutingRules: reject,
    updateRoutingProxyListEnabled: reject,
    refreshRoutingProxyList: reject,
    updateRoutingDirectListEnabled: reject,
    refreshRoutingDirectList: reject,
    clearDiagnostics: reject,
    readLogFile: () => Promise.resolve(""),
    clearLogFile: () => Promise.resolve(""),
    listProcesses: () => Promise.resolve([]),
    connect: reject,
    connectProxy: reject,
    disconnect: reject,
    checkTunnel: reject,
    openTerminal: reject,
    closeTerminal: reject,
    terminalInput: () => Promise.reject(new Error(missingPreloadMessage)),
    checkForUpdates: reject,
    downloadUpdate: reject,
    revealDownloadedUpdate: () => Promise.resolve(false),
    copyText: reject,
    openExternal: reject,
    onServiceEvent: () => () => undefined
  };
}
