import type { TrayMenuModel, TrayTone } from "./tray.js";
import { hasSelectedRoutingTargets } from "./routing-targets.js";
import { HYSTERIA2_INSECURE_TAG, proxyProtocolLabel } from "../../shared/proxy-protocols.js";
import type { AppStore, GlobalTab, ProxyProfile, RuntimeStatus, SshConfig, TunnelCheckResult } from "../../shared/types.js";

/** Windows truncates tray tooltips past 127 characters. */
const MAX_TOOLTIP_CHARACTERS = 127;
const MAX_MENU_SERVERS = 25;
const MAX_MENU_PROFILES = 25;

export type TrayStoreView = Pick<
  AppStore,
  "sshConfigs" | "proxyProfiles" | "selectedConfigId" | "selectedProxyProfileId" | "settings" | "routingMode" | "routingRules" | "routingProxyList"
>;

export interface TrayModelInput {
  appName: string;
  platform: NodeJS.Platform;
  /** Transport that owns `runtime`. */
  activeTransport: GlobalTab;
  runtime: RuntimeStatus;
  store: TrayStoreView;
  lastTunnelCheck?: TunnelCheckResult;
  checkInProgress: boolean;
  /** False while saved data is unreadable and the recovery screen is up. */
  storageReadable: boolean;
}

interface TrayTarget {
  kind: GlobalTab;
  id?: string;
  name?: string;
}

/** The tray menu for the current state; copy follows System.dc.html section 03. */
export function buildTrayMenuModel(input: TrayModelInput): TrayMenuModel {
  const { runtime, store } = input;
  if (!input.storageReadable) {
    return {
      tone: "attention",
      statusTitle: "Saved data couldn’t be read",
      tooltip: tooltip(input.appName, "saved data couldn’t be read"),
      primary: { label: "Connect", action: "none", enabled: false, sublabel: "Recover your data first" },
      servers: [],
      switchEnabled: false,
      check: { label: "Run check", enabled: false, sublabel: "Needs a tunnel" },
      quitSublabel: "Closes Shadow"
    };
  }

  const state = runtime.state;
  const idle = state === "Disconnected";
  const target = idle ? idleTarget(store) : sessionTarget(input.activeTransport, runtime, store);
  const route = target.name ? `${transportLabel(target.kind)} · ${target.name}` : undefined;
  const blocked = store.routingMode === "selected-rules" && !hasSelectedRoutingTargets(store);
  const preview = runtime.transport === "simulator";
  const connectedWord = preview ? "Preview only" : input.platform === "win32" ? "Protected" : "Proxy ready";

  let tone: TrayTone;
  let word: string;
  let tip: string;
  let primary: TrayMenuModel["primary"];
  switch (state) {
    case "Connected":
      tone = preview ? "attention" : "ok";
      word = connectedWord;
      tip = withRoute(connectedWord.toLowerCase(), route);
      primary = { label: "Disconnect", action: "disconnect", enabled: true };
      break;
    case "Connecting":
      tone = "busy";
      word = "Connecting…";
      tip = target.name ? `connecting to ${target.name}` : "connecting";
      primary = { label: "Connecting…", action: "none", enabled: false, sublabel: "Can’t be cancelled" };
      break;
    case "Reconnecting":
      tone = "busy";
      word = "Reconnecting…";
      tip = target.name ? `reconnecting to ${target.name}` : "reconnecting";
      primary = { label: "Disconnect", action: "disconnect", enabled: true, sublabel: "Stops reconnecting" };
      break;
    case "Disconnecting":
      tone = "busy";
      word = "Disconnecting…";
      tip = "disconnecting";
      primary = { label: "Disconnecting…", action: "none", enabled: false };
      break;
    case "Error":
      tone = "attention";
      word = "Needs attention";
      tip = "needs attention";
      primary = blocked
        ? { label: "Try again", action: "none", enabled: false, sublabel: "Add a routing target first" }
        : { label: "Try again", action: "retry", enabled: true };
      break;
    case "Disconnected":
      tone = "off";
      word = "Not connected";
      tip = "not connected";
      primary = idlePrimary(target, blocked);
      break;
  }

  const servers = menuServers(store, target);
  const busy = state === "Connecting" || state === "Disconnecting";
  const live = state === "Connected" || state === "Reconnecting" || state === "Connecting";
  const switchEnabled = !busy && !blocked && servers.some((server) => server.enabled);
  let switchNote: string | undefined;
  if (blocked) {
    switchNote = "Split tunnel has nothing to route yet";
  } else if (state === "Connecting") {
    switchNote = "Wait until this attempt finishes";
  } else if (state === "Connected" || state === "Reconnecting") {
    switchNote = "Picking another one closes the current tunnel first, then connects.";
  }

  return {
    tone,
    statusTitle: !route ? word : state === "Disconnected" ? `${word} · ${route} selected` : `${word} · ${route}`,
    tooltip: tooltip(input.appName, tip),
    primary,
    servers,
    switchEnabled,
    ...(switchNote ? { switchNote } : {}),
    check: checkItem(input),
    quitSublabel: live ? "Disconnects the tunnel first" : "Closes Shadow"
  };
}

function idlePrimary(target: TrayTarget, blocked: boolean): TrayMenuModel["primary"] {
  if (!target.id) {
    return {
      label: "Connect",
      action: "none",
      enabled: false,
      sublabel: target.kind === "xray" ? "Pick an Xray profile first" : "Add a server first"
    };
  }
  if (blocked) {
    return { label: "Connect", action: "none", enabled: false, sublabel: "Add a routing target first" };
  }
  return { label: "Connect", action: "connect", enabled: true };
}

function checkItem(input: TrayModelInput): TrayMenuModel["check"] {
  const label = "Run check";
  if (input.runtime.state !== "Connected") {
    return { label, enabled: false, sublabel: "Needs a tunnel" };
  }
  if (input.checkInProgress) {
    return { label, enabled: false, sublabel: "Checking…" };
  }
  const result = input.lastTunnelCheck;
  if (!result || (result.transport !== undefined && result.transport !== input.activeTransport)) {
    return { label, enabled: true };
  }
  if (!result.ok) {
    return { label, enabled: true, sublabel: "Failed" };
  }
  const passed = result.note ? "Passed with a note" : "Passed";
  const latency = typeof result.latencyMs === "number" && Number.isFinite(result.latencyMs) ? ` · ${Math.round(result.latencyMs)} ms` : "";
  return { label, enabled: true, sublabel: `${passed}${latency}` };
}

/** What Connect would start: the last transport used and its selection, like auto-connect. */
function idleTarget(store: TrayStoreView): TrayTarget {
  const kind = store.settings.lastConnectedTransport;
  if (kind === "xray") {
    const profile = store.proxyProfiles.find((candidate) => candidate.id === store.selectedProxyProfileId);
    return { kind, id: profile?.id, name: profile?.name };
  }
  const config = store.sshConfigs.find((candidate) => candidate.id === store.selectedConfigId);
  return { kind, id: config?.id, name: config?.name };
}

function sessionTarget(kind: GlobalTab, runtime: RuntimeStatus, store: TrayStoreView): TrayTarget {
  const id = runtime.activeConfigId;
  const stored =
    kind === "xray"
      ? store.proxyProfiles.find((candidate) => candidate.id === id)?.name
      : store.sshConfigs.find((candidate) => candidate.id === id)?.name;
  return { kind, id, name: runtime.activeConfigName ?? stored };
}

function menuServers(store: TrayStoreView, current: TrayTarget): TrayMenuModel["servers"] {
  const ssh = store.sshConfigs.slice(0, MAX_MENU_SERVERS).map((config) => {
    const problem = sshConfigProblem(config);
    return {
      kind: "ssh" as const,
      id: config.id,
      label: config.name,
      checked: current.kind === "ssh" && current.id === config.id,
      enabled: problem === undefined,
      ...(problem ? { sublabel: problem } : {})
    };
  });
  const pinned = store.proxyProfiles.filter((profile) => profile.isPinned).slice(0, MAX_MENU_PROFILES);
  // The profile in use stays reachable even when it is not pinned.
  const currentProfile =
    current.kind === "xray" && current.id && !pinned.some((profile) => profile.id === current.id)
      ? store.proxyProfiles.find((profile) => profile.id === current.id)
      : undefined;
  const profiles = currentProfile ? [currentProfile, ...pinned] : pinned;
  const xray = profiles.map((profile) => {
    const unsupported = isUnsupportedProfile(profile);
    return {
      kind: "xray" as const,
      id: profile.id,
      label: profile.name,
      checked: current.kind === "xray" && current.id === profile.id,
      enabled: !unsupported,
      sublabel: unsupported ? "Unsupported" : profileSublabel(profile)
    };
  });
  return [...ssh, ...xray];
}

/** "Hysteria 2", or "Hysteria 2 · insecure=1" when the link asks to skip certificate checks without a pin. */
function profileSublabel(profile: ProxyProfile): string {
  const protocol = proxyProtocolLabel(profile.protocol);
  return profile.insecureWithoutPin ? `${protocol} · ${HYSTERIA2_INSECURE_TAG}` : protocol;
}

function sshConfigProblem(config: SshConfig): string | undefined {
  if (config.authType === "password" && !config.passwordSecretId) {
    return "No password saved";
  }
  if (config.authType === "private-key" && !config.privateKeyId) {
    return "No key chosen";
  }
  return undefined;
}

function isUnsupportedProfile(profile: ProxyProfile): boolean {
  return profile.security === "unknown" || profile.transport === "unknown";
}

function transportLabel(kind: GlobalTab): string {
  return kind === "xray" ? "Xray" : "SSH";
}

function withRoute(word: string, route: string | undefined): string {
  return route ? `${word} · ${route}` : word;
}

function tooltip(appName: string, text: string): string {
  const value = `${appName} — ${text}`;
  return value.length > MAX_TOOLTIP_CHARACTERS ? `${value.slice(0, MAX_TOOLTIP_CHARACTERS - 1)}…` : value;
}
