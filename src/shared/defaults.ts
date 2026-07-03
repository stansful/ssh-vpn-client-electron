import type { AppSettings, AppStore, CustomTheme, PlatformTarget, RuntimeStatus } from "./types.js";

export const STORE_SCHEMA_VERSION = 1;

export const DEFAULT_CUSTOM_THEME: CustomTheme = {
  accent: { r: 246, g: 139, b: 0 },
  success: { r: 31, g: 145, b: 97 },
  danger: { r: 207, g: 63, b: 75 },
  background: { r: 237, g: 240, b: 244 },
  surface: { r: 248, g: 249, b: 251 },
  text: { r: 23, g: 24, b: 32 },
  muted: { r: 104, g: 113, b: 129 },
  border: { r: 216, g: 221, b: 230 }
};

export const DEFAULT_SETTINGS: AppSettings = {
  theme: "system",
  customTheme: DEFAULT_CUSTOM_THEME,
  diagnosticsExpanded: false,
  terminalExpanded: false,
  checkEndpoint: "youtube.com:443",
  loggingEnabled: true,
  diagnosticsLoggingEnabled: true,
  fileLoggingEnabled: true,
  closeToTrayEnabled: true,
  startWithWindowsInTray: false,
  sidebarCollapsed: false,
  activeGlobalTab: "ssh",
  xrayConsentAccepted: false,
  showXrayWarningOnEnter: true,
  xrayRiskBannerExpanded: true
};

export function createDefaultStore(): AppStore {
  return {
    schemaVersion: STORE_SCHEMA_VERSION,
    sshConfigs: [],
    sshKeys: [],
    proxyProfiles: [],
    settings: DEFAULT_SETTINGS,
    routingMode: "proxy-all",
    routingRules: []
  };
}

export function createDefaultRuntimeStatus(platformTarget: PlatformTarget): RuntimeStatus {
  return {
    state: "Disconnected",
    message: "Native service is not connected.",
    reconnectAttempt: 0,
    transport: "simulator",
    platformTarget,
    realTunnelAvailable: false
  };
}
