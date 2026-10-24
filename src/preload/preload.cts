/**
 * The renderer's only way into the main process. The window runs sandboxed,
 * so this file must stay a self-contained CommonJS script: a sandboxed
 * preload can require "electron" and nothing of the app's own. That is why
 * the channel names are written out here instead of imported; the type below
 * makes the compiler reject any difference from IPC_CHANNELS in
 * src/shared/ipc.ts, and tests/preload-bridge.test.ts checks it again.
 */
import { contextBridge, ipcRenderer } from "electron";
import type { IPC_CHANNELS as SharedIpcChannels, RendererEvent, ShadowSshApi } from "../shared/ipc.js";
import type {
  AppSettings,
  ImportProxyProfilesInput,
  RoutingMode,
  RoutingRule,
  UpsertProxyProfileInput,
  UpsertSshConfigInput,
  UpsertSshKeyInput
} from "../shared/types.js";

const IPC_CHANNELS: typeof SharedIpcChannels = {
  loadSnapshot: "shadow-ssh:load-snapshot",
  upsertConfig: "shadow-ssh:upsert-config",
  deleteConfig: "shadow-ssh:delete-config",
  selectConfig: "shadow-ssh:select-config",
  upsertKey: "shadow-ssh:upsert-key",
  copyPrivateKey: "shadow-ssh:copy-private-key",
  deleteKey: "shadow-ssh:delete-key",
  upsertProxyProfile: "shadow-ssh:upsert-proxy-profile",
  importProxyProfiles: "shadow-ssh:import-proxy-profiles",
  refreshProxyProfiles: "shadow-ssh:refresh-proxy-profiles",
  selectProxyProfile: "shadow-ssh:select-proxy-profile",
  toggleProxyProfilePin: "shadow-ssh:toggle-proxy-profile-pin",
  renameProxyProfile: "shadow-ssh:rename-proxy-profile",
  copyProxyProfileLink: "shadow-ssh:copy-proxy-profile-link",
  deleteProxyProfile: "shadow-ssh:delete-proxy-profile",
  deleteUnpinnedProxyProfiles: "shadow-ssh:delete-unpinned-proxy-profiles",
  updateSettings: "shadow-ssh:update-settings",
  updateRoutingMode: "shadow-ssh:update-routing-mode",
  updateRoutingRules: "shadow-ssh:update-routing-rules",
  updateRoutingProxyListEnabled: "shadow-ssh:update-routing-proxy-list-enabled",
  refreshRoutingProxyList: "shadow-ssh:refresh-routing-proxy-list",
  updateRoutingDirectListEnabled: "shadow-ssh:update-routing-direct-list-enabled",
  refreshRoutingDirectList: "shadow-ssh:refresh-routing-direct-list",
  clearDiagnostics: "shadow-ssh:clear-diagnostics",
  readLogFile: "shadow-ssh:read-log-file",
  getLogFileInfo: "shadow-ssh:get-log-file-info",
  clearLogFile: "shadow-ssh:clear-log-file",
  listProcesses: "shadow-ssh:list-processes",
  connect: "shadow-ssh:connect",
  connectProxy: "shadow-ssh:connect-proxy",
  disconnect: "shadow-ssh:disconnect",
  checkTunnel: "shadow-ssh:check-tunnel",
  openTerminal: "shadow-ssh:open-terminal",
  closeTerminal: "shadow-ssh:close-terminal",
  terminalInput: "shadow-ssh:terminal-input",
  checkForUpdates: "shadow-ssh:check-for-updates",
  downloadUpdate: "shadow-ssh:download-update",
  revealDownloadedUpdate: "shadow-ssh:reveal-downloaded-update",
  copyText: "shadow-ssh:copy-text",
  readClipboardText: "shadow-ssh:read-clipboard-text",
  openExternal: "shadow-ssh:open-external",
  dismissConnectionError: "shadow-ssh:dismiss-connection-error",
  dismissAttention: "shadow-ssh:dismiss-attention",
  openLogFolder: "shadow-ssh:open-log-folder",
  openDataFolder: "shadow-ssh:open-data-folder",
  recoverStorage: "shadow-ssh:recover-storage",
  quitApp: "shadow-ssh:quit-app",
  serviceEvent: "shadow-ssh:service-event"
};

const api: ShadowSshApi = {
  loadSnapshot: () => ipcRenderer.invoke(IPC_CHANNELS.loadSnapshot),
  upsertConfig: (input: UpsertSshConfigInput) => ipcRenderer.invoke(IPC_CHANNELS.upsertConfig, input),
  deleteConfig: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.deleteConfig, id),
  selectConfig: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.selectConfig, id),
  upsertKey: (input: UpsertSshKeyInput) => ipcRenderer.invoke(IPC_CHANNELS.upsertKey, input),
  copyPrivateKey: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.copyPrivateKey, id),
  deleteKey: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.deleteKey, id),
  upsertProxyProfile: (input: UpsertProxyProfileInput) => ipcRenderer.invoke(IPC_CHANNELS.upsertProxyProfile, input),
  importProxyProfiles: (input: ImportProxyProfilesInput) => ipcRenderer.invoke(IPC_CHANNELS.importProxyProfiles, input),
  refreshProxyProfiles: () => ipcRenderer.invoke(IPC_CHANNELS.refreshProxyProfiles),
  selectProxyProfile: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.selectProxyProfile, id),
  toggleProxyProfilePin: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.toggleProxyProfilePin, id),
  renameProxyProfile: (id: string, name: string) => ipcRenderer.invoke(IPC_CHANNELS.renameProxyProfile, id, name),
  copyProxyProfileLink: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.copyProxyProfileLink, id),
  deleteProxyProfile: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.deleteProxyProfile, id),
  deleteUnpinnedProxyProfiles: () => ipcRenderer.invoke(IPC_CHANNELS.deleteUnpinnedProxyProfiles),
  updateSettings: (patch: Partial<AppSettings>) => ipcRenderer.invoke(IPC_CHANNELS.updateSettings, patch),
  updateRoutingMode: (mode: RoutingMode) => ipcRenderer.invoke(IPC_CHANNELS.updateRoutingMode, mode),
  updateRoutingRules: (rules: RoutingRule[]) => ipcRenderer.invoke(IPC_CHANNELS.updateRoutingRules, rules),
  updateRoutingProxyListEnabled: (enabled: boolean) => ipcRenderer.invoke(IPC_CHANNELS.updateRoutingProxyListEnabled, enabled),
  refreshRoutingProxyList: () => ipcRenderer.invoke(IPC_CHANNELS.refreshRoutingProxyList),
  updateRoutingDirectListEnabled: (enabled: boolean) => ipcRenderer.invoke(IPC_CHANNELS.updateRoutingDirectListEnabled, enabled),
  refreshRoutingDirectList: () => ipcRenderer.invoke(IPC_CHANNELS.refreshRoutingDirectList),
  clearDiagnostics: () => ipcRenderer.invoke(IPC_CHANNELS.clearDiagnostics),
  readLogFile: () => ipcRenderer.invoke(IPC_CHANNELS.readLogFile),
  getLogFileInfo: () => ipcRenderer.invoke(IPC_CHANNELS.getLogFileInfo),
  clearLogFile: () => ipcRenderer.invoke(IPC_CHANNELS.clearLogFile),
  listProcesses: () => ipcRenderer.invoke(IPC_CHANNELS.listProcesses),
  connect: () => ipcRenderer.invoke(IPC_CHANNELS.connect),
  connectProxy: () => ipcRenderer.invoke(IPC_CHANNELS.connectProxy),
  disconnect: () => ipcRenderer.invoke(IPC_CHANNELS.disconnect),
  checkTunnel: (endpoint?: string) => ipcRenderer.invoke(IPC_CHANNELS.checkTunnel, endpoint),
  openTerminal: () => ipcRenderer.invoke(IPC_CHANNELS.openTerminal),
  closeTerminal: () => ipcRenderer.invoke(IPC_CHANNELS.closeTerminal),
  terminalInput: (input: string) => ipcRenderer.invoke(IPC_CHANNELS.terminalInput, input),
  checkForUpdates: (force?: boolean) => ipcRenderer.invoke(IPC_CHANNELS.checkForUpdates, force),
  downloadUpdate: () => ipcRenderer.invoke(IPC_CHANNELS.downloadUpdate),
  revealDownloadedUpdate: () => ipcRenderer.invoke(IPC_CHANNELS.revealDownloadedUpdate),
  copyText: (text: string) => ipcRenderer.invoke(IPC_CHANNELS.copyText, text),
  readClipboardText: () => ipcRenderer.invoke(IPC_CHANNELS.readClipboardText),
  openExternal: (url: string) => ipcRenderer.invoke(IPC_CHANNELS.openExternal, url),
  dismissConnectionError: () => ipcRenderer.invoke(IPC_CHANNELS.dismissConnectionError),
  dismissAttention: (id?: string) => ipcRenderer.invoke(IPC_CHANNELS.dismissAttention, id),
  openLogFolder: () => ipcRenderer.invoke(IPC_CHANNELS.openLogFolder),
  openDataFolder: () => ipcRenderer.invoke(IPC_CHANNELS.openDataFolder),
  recoverStorage: (action: "start-fresh") => ipcRenderer.invoke(IPC_CHANNELS.recoverStorage, action),
  quitApp: () => ipcRenderer.invoke(IPC_CHANNELS.quitApp),
  onServiceEvent: (callback: (event: RendererEvent) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, payload: RendererEvent): void => {
      callback(payload);
    };
    ipcRenderer.on(IPC_CHANNELS.serviceEvent, listener);
    return () => ipcRenderer.removeListener(IPC_CHANNELS.serviceEvent, listener);
  }
};

contextBridge.exposeInMainWorld("shadowSsh", api);
