import type { GlobalTab, ProxyProfile } from "../../shared/types.js";

/**
 * "Remove unpinned" ends the Xray session only when it removes the profile
 * that session runs. A pinned profile stays, and so does its tunnel.
 */
export function unpinnedRemovalEndsSession(input: {
  activeTransport: GlobalTab;
  /** `activeConfigId` of the Xray service. */
  activeProfileId: string | undefined;
  profiles: ReadonlyArray<Pick<ProxyProfile, "id" | "isPinned">>;
}): boolean {
  if (input.activeTransport !== "xray" || !input.activeProfileId) {
    return false;
  }
  const active = input.profiles.find((profile) => profile.id === input.activeProfileId);
  return active !== undefined && !active.isPinned;
}
