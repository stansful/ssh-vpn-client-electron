import type { AppSnapshot, ProxyProtocol } from "../../../shared/types.js";

/**
 * Display name of what the active transport runs (or would run): the name the
 * session started with, else the selected server/profile.
 */
export function activeTargetName(snapshot: AppSnapshot): string | undefined {
  const { runtime, store, activeTransport } = snapshot;
  if (runtime.activeConfigName) {
    return runtime.activeConfigName;
  }
  if (activeTransport === "xray") {
    const id = runtime.activeConfigId ?? store.selectedProxyProfileId;
    return store.proxyProfiles.find((profile) => profile.id === id)?.name;
  }
  const id = runtime.activeConfigId ?? store.selectedConfigId;
  return store.sshConfigs.find((config) => config.id === id)?.name;
}

/** Protocol of the profile the running Xray session started with, while it is still saved. */
export function activeProfileProtocol(snapshot: AppSnapshot): ProxyProtocol | undefined {
  const { runtime, store, activeTransport } = snapshot;
  if (activeTransport !== "xray" || !runtime.activeConfigId) {
    return undefined;
  }
  return store.proxyProfiles.find((profile) => profile.id === runtime.activeConfigId)?.protocol;
}
