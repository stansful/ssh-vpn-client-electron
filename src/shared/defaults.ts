import type { AppSettings, AppStore, CustomTheme, PlatformTarget, RuntimeStatus } from "./types.js";

/**
 * Version 2 turns tunnel-adapter capture on for stores written before it
 * existed. The first build to ship the setting wrote it as `false` and could
 * never act on it - the native helper crashed at start-up - so a stored `false`
 * from that build records nothing the user decided.
 */
export const STORE_SCHEMA_VERSION = 3;
export const RUSSIA_INSIDE_PROXY_LIST_URL = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst";
export const RUSSIA_OUTSIDE_DIRECT_LIST_URL = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/outside-raw.lst";
export const PUBLIC_PROXY_LIST_URL = "https://gitverse.ru/api/repos/zieng2/wl/raw/branch/master/list_universal.txt";
/**
 * Earlier homes of the public list. Profiles fetched from them are counted as
 * coming from the current one, so the next refresh can mark the gone ones stale.
 */
export const LEGACY_PUBLIC_PROXY_LIST_URLS: readonly string[] = ["https://hub.mos.ru/zieng2/wl/raw/main/list_universal.txt"];

/**
 * Version 3 moves the signal colours to the "Night Signal" palette. Stores
 * that still hold the version 2 defaults are migrated to these values; colours
 * a user picked are kept.
 */
export const LEGACY_DEFAULT_SIGNAL_COLORS = {
  accent: { r: 246, g: 139, b: 0 },
  success: { r: 31, g: 145, b: 97 },
  danger: { r: 207, g: 63, b: 75 }
} as const;

export const DEFAULT_CUSTOM_THEME: CustomTheme = {
  accent: { r: 246, g: 160, b: 25 },
  success: { r: 52, g: 208, b: 138 },
  danger: { r: 242, g: 85, b: 90 },
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
  releaseRendererInTrayEnabled: true,
  startWithWindowsInTray: false,
  autoConnectOnStartup: true,
  sidebarCollapsed: false,
  activeGlobalTab: "ssh",
  lastConnectedTransport: "ssh",
  xrayConsentAccepted: false,
  showXrayWarningOnEnter: true,
  xrayRiskBannerExpanded: true,
  tunDataplaneEnabled: true,
  notifyTunnelChanges: true,
  notifyUpdateDownloaded: true,
  notifyStillRunningInTray: true,
  notifyOnlyWhenHidden: true,
  stillRunningNoticeShown: false
};

export function createDefaultStore(): AppStore {
  return {
    schemaVersion: STORE_SCHEMA_VERSION,
    sshConfigs: [],
    sshKeys: [],
    proxyProfiles: [],
    settings: DEFAULT_SETTINGS,
    routingMode: "proxy-all",
    routingRules: [],
    routingProxyList: {
      enabled: false,
      sourceUrl: RUSSIA_INSIDE_PROXY_LIST_URL,
      domains: []
    },
    routingDirectList: {
      enabled: false,
      sourceUrl: RUSSIA_OUTSIDE_DIRECT_LIST_URL,
      domains: []
    }
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
