import { contextBridge, ipcRenderer } from "electron";
import { IPC_CHANNELS, type RendererEvent, type ShadowSshApi } from "../shared/ipc.js";
import type {
  AppSettings,
  ImportProxyProfilesInput,
  RoutingMode,
  RoutingRule,
  UpsertProxyProfileInput,
  UpsertSshConfigInput,
  UpsertSshKeyInput
} from "../shared/types.js";

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
  openExternal: (url: string) => ipcRenderer.invoke(IPC_CHANNELS.openExternal, url),
  onServiceEvent: (callback: (event: RendererEvent) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, payload: RendererEvent): void => {
      callback(payload);
    };
    ipcRenderer.on(IPC_CHANNELS.serviceEvent, listener);
    return () => ipcRenderer.removeListener(IPC_CHANNELS.serviceEvent, listener);
  }
};

contextBridge.exposeInMainWorld("shadowSsh", api);
