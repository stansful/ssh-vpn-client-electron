import type { AppEnvironment, ConnectionState, TunStatus } from "../../shared/types.js";
import { detectDesktopPlatform, detectRuntimeArch } from "../platform/targets.js";

export interface SecretsBackendFacts {
  /** `safeStorage.isEncryptionAvailable()`. */
  encryptionAvailable: boolean;
  /** `safeStorage.getSelectedStorageBackend()` on Linux. */
  selectedBackend?: string;
  insecureFallbackAllowed: boolean;
}

export interface EnvironmentFacts {
  version: string;
  platform: NodeJS.Platform;
  arch: NodeJS.Architecture;
  dataDirectory: string;
  logDirectory: string;
  isPackaged: boolean;
  buildChannel?: string;
  secrets: SecretsBackendFacts;
}

export function createAppEnvironment(facts: EnvironmentFacts): AppEnvironment {
  return {
    version: facts.version,
    platform: detectDesktopPlatform(facts.platform),
    arch: detectRuntimeArch(facts.arch),
    dataDirectory: facts.dataDirectory,
    logDirectory: facts.logDirectory,
    secretsBackend: describeSecretsBackend(facts.platform, facts.secrets),
    isDevBuild: !facts.isPackaged || facts.buildChannel === "development"
  };
}

/** Mirrors the storage rule: Linux "basic_text" is not encryption unless explicitly allowed. */
export function describeSecretsBackend(platform: NodeJS.Platform, facts: SecretsBackendFacts): string {
  if (!facts.encryptionAvailable) {
    return "unavailable";
  }
  if (platform === "win32") {
    return "Windows DPAPI";
  }
  if (platform === "darwin") {
    return "macOS Keychain";
  }
  if (platform === "linux") {
    return facts.selectedBackend === "basic_text" && !facts.insecureFallbackAllowed ? "unavailable" : "Linux keyring";
  }
  return "unavailable";
}

/** Structurally the platform probe's result (src/main/platform/tun-environment.ts). */
export interface TunEnvironmentFacts {
  supported: boolean;
  elevated: boolean;
  wintunFound: boolean;
  searchedPaths: string[];
}

export const TUN_FAILURE_NOT_ELEVATED = "Shadow SSH isn’t running as administrator";
export const TUN_FAILURE_NO_WINTUN = "wintun.dll wasn’t found";
export const TUN_FAILURE_GENERIC = "The TUN adapter couldn’t start this session. Activity has the reason.";

export interface TunStatusInputs {
  /** Undefined until the first probe finishes. */
  environment?: TunEnvironmentFacts;
  platform: NodeJS.Platform;
  /** The current setting. */
  enabled: boolean;
  /** State of the active transport. */
  sessionState: ConnectionState;
  /** `runtime.tunActive` of the active transport. */
  tunActive: boolean;
  /** The setting the current session was started with; undefined without a session. */
  sessionTunSetting?: boolean;
}

export function deriveTunStatus(inputs: TunStatusInputs): TunStatus {
  const environment = inputs.environment;
  const supported = environment?.supported ?? inputs.platform === "win32";
  const sessionLive = isLiveSessionState(inputs.sessionState);
  const active = supported && sessionLive && inputs.tunActive;
  const status: TunStatus = {
    supported,
    enabled: inputs.enabled,
    elevated: environment?.elevated ?? false,
    wintunFound: environment?.wintunFound ?? false,
    searchedPaths: environment?.searchedPaths.slice() ?? [],
    active,
    appliesOnNextConnect:
      supported && sessionLive && inputs.sessionTunSetting !== undefined && inputs.sessionTunSetting !== inputs.enabled
  };
  if (supported && inputs.enabled && environment && !active) {
    if (!environment.elevated) {
      status.lastFailure = TUN_FAILURE_NOT_ELEVATED;
    } else if (!environment.wintunFound) {
      status.lastFailure = TUN_FAILURE_NO_WINTUN;
    } else if (inputs.sessionState === "Connected" && inputs.sessionTunSetting === true) {
      status.lastFailure = TUN_FAILURE_GENERIC;
    }
  }
  return status;
}

/** A session exists and holds (or is building) routing. */
export function isLiveSessionState(state: ConnectionState): boolean {
  return state === "Connecting" || state === "Connected" || state === "Reconnecting";
}
