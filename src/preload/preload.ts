import { contextBridge, ipcRenderer } from "electron";
import { IPC_CHANNELS, type ServiceEvent, type ShadowSshApi } from "../shared/ipc.js";
import type { AppSettings, RoutingMode, RoutingRule, UpsertSshConfigInput, UpsertSshKeyInput } from "../shared/types.js";

const api: ShadowSshApi = {
  loadSnapshot: () => ipcRenderer.invoke(IPC_CHANNELS.loadSnapshot),
  upsertConfig: (input: UpsertSshConfigInput) => ipcRenderer.invoke(IPC_CHANNELS.upsertConfig, input),
  deleteConfig: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.deleteConfig, id),
  selectConfig: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.selectConfig, id),
  upsertKey: (input: UpsertSshKeyInput) => ipcRenderer.invoke(IPC_CHANNELS.upsertKey, input),
  copyPrivateKey: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.copyPrivateKey, id),
  deleteKey: (id: string) => ipcRenderer.invoke(IPC_CHANNELS.deleteKey, id),
  updateSettings: (settings: AppSettings) => ipcRenderer.invoke(IPC_CHANNELS.updateSettings, settings),
  updateRoutingMode: (mode: RoutingMode) => ipcRenderer.invoke(IPC_CHANNELS.updateRoutingMode, mode),
  updateRoutingRules: (rules: RoutingRule[]) => ipcRenderer.invoke(IPC_CHANNELS.updateRoutingRules, rules),
  clearDiagnostics: () => ipcRenderer.invoke(IPC_CHANNELS.clearDiagnostics),
  readLogFile: () => ipcRenderer.invoke(IPC_CHANNELS.readLogFile),
  clearLogFile: () => ipcRenderer.invoke(IPC_CHANNELS.clearLogFile),
  listProcesses: () => ipcRenderer.invoke(IPC_CHANNELS.listProcesses),
  connect: () => ipcRenderer.invoke(IPC_CHANNELS.connect),
  disconnect: () => ipcRenderer.invoke(IPC_CHANNELS.disconnect),
  checkTunnel: (endpoint?: string) => ipcRenderer.invoke(IPC_CHANNELS.checkTunnel, endpoint),
  openTerminal: () => ipcRenderer.invoke(IPC_CHANNELS.openTerminal),
  closeTerminal: () => ipcRenderer.invoke(IPC_CHANNELS.closeTerminal),
  terminalInput: (input: string) => ipcRenderer.invoke(IPC_CHANNELS.terminalInput, input),
  onServiceEvent: (callback: (event: ServiceEvent) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, payload: ServiceEvent): void => {
      callback(payload);
    };
    ipcRenderer.on(IPC_CHANNELS.serviceEvent, listener);
    return () => ipcRenderer.removeListener(IPC_CHANNELS.serviceEvent, listener);
  }
};

contextBridge.exposeInMainWorld("shadowSsh", api);
