import type { AppStore, GlobalTab, ImportProxyProfilesResult, ProxyProfile, ProxyProfileSource, PublicProxyRefresh, RuntimeStatus } from "../../../../shared/types.js";
import { phaseOf } from "../../../lib/connection.js";
import { describeError, errorText, stripIpcPrefix } from "../../../lib/errors.js";
import { formatCount, formatDay, formatProfileAddress, formatTime, plural, profileTransportLabel, protocolKeywords, protocolLabel } from "../../../lib/format.js";
import { HYSTERIA2_INSECURE_PROFILE_WARNING, HYSTERIA2_INSECURE_TAG, type LinkPreview } from "./link-preview.js";

export type ProfileFilter = "all" | "pinned" | "gone";

/** Cards render in pages of 100 ("Show 100 more"). */
export const PROFILE_PAGE_SIZE = 100;

/** A little over the Modal exit (220 ms): dialogs reset only once they're out of sight. */
export const DIALOG_EXIT_MS = 240;

const FILTER_NAMES: Record<ProfileFilter, string> = { all: "all profiles", pinned: "Pinned", gone: "Gone from source" };

// ---------- profile facts ----------

export function sourceLabel(source: ProxyProfileSource): string {
  return source === "remote" ? "Public" : source === "clipboard" ? "Imported" : "Added by you";
}

export function sourceTitle(source: ProxyProfileSource): string {
  return source === "remote"
    ? "Came from the public list at the last refresh"
    : source === "clipboard"
      ? "Came from Import links"
      : "Added with Add profile";
}

/** Which setting Xray can't run, if any. Security wins when both are unknown. */
export function unsupportedPart(profile: Pick<ProxyProfile, "security" | "transport">): "security" | "transport" | undefined {
  if (profile.security === "unknown") {
    return "security";
  }
  return profile.transport === "unknown" ? "transport" : undefined;
}

/** host:port, with every hop port for Hysteria 2 port hopping ("example.com:443,20000-30000"). */
export function profileAddress(profile: Pick<ProxyProfile, "host" | "port" | "hopPorts">): string {
  return formatProfileAddress(profile);
}

export interface ProfileCounts {
  all: number;
  pinned: number;
  gone: number;
  goneUnpinned: number;
  unpinned: number;
}

export function countProfiles(profiles: readonly ProxyProfile[]): ProfileCounts {
  let pinned = 0;
  let gone = 0;
  let goneUnpinned = 0;
  for (const profile of profiles) {
    if (profile.isPinned) {
      pinned += 1;
    }
    if (profile.isStale) {
      gone += 1;
      if (!profile.isPinned) {
        goneUnpinned += 1;
      }
    }
  }
  return { all: profiles.length, pinned, gone, goneUnpinned, unpinned: profiles.length - pinned };
}

/**
 * Everything search looks at: name, protocol (and its scheme names, such as
 * hy2), host, host:port, ports, transport as stored and as shown ("quic"),
 * security, the insecure=1 tag, source.
 */
export function profileSearchText(profile: ProxyProfile): string {
  return [
    profile.name,
    protocolLabel(profile.protocol),
    protocolKeywords(profile.protocol),
    profile.host,
    profileAddress(profile),
    String(profile.port),
    profile.hopPorts ?? "",
    profile.transport,
    profileTransportLabel(profile),
    profile.security,
    profile.insecureWithoutPin ? HYSTERIA2_INSECURE_TAG : "",
    sourceLabel(profile.source)
  ]
    .join(" ")
    .toLowerCase();
}

export function filterProfiles(
  profiles: readonly ProxyProfile[],
  filter: ProfileFilter,
  query: string,
  searchText: (profile: ProxyProfile) => string = profileSearchText
): ProxyProfile[] {
  const needle = query.trim().toLowerCase();
  return profiles.filter((profile) => {
    if (filter === "pinned" && !profile.isPinned) {
      return false;
    }
    if (filter === "gone" && !profile.isStale) {
      return false;
    }
    return !needle || searchText(profile).includes(needle);
  });
}

// ---------- the running Xray session ----------

export type XraySessionPhase = "connected" | "preview" | "connecting" | "reconnecting" | "disconnecting";

export interface XraySession {
  phase: XraySessionPhase;
  /** Profile the session runs (or starts) with. */
  profileId?: string;
  /** Name the session started with. */
  name?: string;
}

/** The Xray session, when Xray owns the tunnel and one runs or is starting. */
export function xraySessionOf(activeTransport: GlobalTab, runtime: RuntimeStatus): XraySession | undefined {
  if (activeTransport !== "xray") {
    return undefined;
  }
  const phase = phaseOf(runtime);
  if (phase === "off" || phase === "error") {
    return undefined;
  }
  return { phase, profileId: runtime.activeConfigId, name: runtime.activeConfigName };
}

/** Removing unpinned profiles stops this session first (Connected, starting or retrying). */
export function sessionWouldStop(session: XraySession | undefined): boolean {
  return Boolean(session && session.phase !== "disconnecting");
}

// ---------- cards ----------

export interface ProfileCardView {
  address: string;
  protocol: string;
  selected: boolean;
  /** Carrying traffic (mint styling). */
  inUse: boolean;
  protoTone: "ok" | "accent" | "outline";
  badge?: { text: string; tone: "ok" | "busy" | "warn"; glyph: "dot" | "spinner" };
  transport: string;
  security: string;
  transportBad: boolean;
  securityBad: boolean;
  /**
   * Hysteria 2 link with insecure=1 and no pinSHA256: a warning tag after the
   * security one, and what it means (also in `hitTitle`).
   */
  insecure?: { tag: string; text: string };
  goneText?: string;
  unsupported?: { label: string; text: string };
  /** Footer state; the hover hint shows when there is none. */
  state?: { label: string; tone: "ok" | "accent" | "warn"; glyph: "dot" | "check" | "spinner" };
  hint: string;
  hitLabel: string;
  hitTitle: string;
  pinLabel: string;
  pinTitle: string;
  removeBlocked: boolean;
  removeLabel: string;
  removeTitle: string;
}

const SESSION_BADGE: Record<XraySessionPhase, NonNullable<ProfileCardView["badge"]>> = {
  connected: { text: "Connected", tone: "ok", glyph: "dot" },
  preview: { text: "Preview only", tone: "warn", glyph: "dot" },
  connecting: { text: "Connecting…", tone: "busy", glyph: "spinner" },
  reconnecting: { text: "Reconnecting…", tone: "busy", glyph: "spinner" },
  disconnecting: { text: "Stopping…", tone: "busy", glyph: "spinner" }
};

const SESSION_STATE: Record<XraySessionPhase, NonNullable<ProfileCardView["state"]>> = {
  connected: { label: "Connected now", tone: "ok", glyph: "dot" },
  preview: { label: "Preview only · not routing", tone: "warn", glyph: "dot" },
  connecting: { label: "Connecting now", tone: "accent", glyph: "spinner" },
  reconnecting: { label: "Reconnecting now", tone: "accent", glyph: "spinner" },
  disconnecting: { label: "Disconnecting now", tone: "accent", glyph: "spinner" }
};

export function presentProfileCard(profile: ProxyProfile, context: { selectedId?: string; session?: XraySession }): ProfileCardView {
  const { session } = context;
  const address = profileAddress(profile);
  const selected = context.selectedId === profile.id;
  const ownSession = session && session.profileId === profile.id ? session.phase : undefined;
  const inUse = ownSession === "connected";
  const bad = unsupportedPart(profile);
  const insecure = profile.insecureWithoutPin ? { tag: HYSTERIA2_INSECURE_TAG, text: HYSTERIA2_INSECURE_PROFILE_WARNING } : undefined;

  let state: ProfileCardView["state"];
  if (ownSession) {
    state = SESSION_STATE[ownSession];
  } else if (selected) {
    const label = profile.isStale ? "Selected for now" : session ? "Selected · next connect" : "Selected for Connect";
    state = { label, tone: "accent", glyph: "check" };
  }

  return {
    address,
    protocol: protocolLabel(profile.protocol),
    selected,
    inUse,
    protoTone: inUse ? "ok" : selected || ownSession ? "accent" : "outline",
    badge: ownSession ? SESSION_BADGE[ownSession] : undefined,
    transport: profileTransportLabel(profile),
    security: profile.security === "unknown" ? "?" : profile.security,
    transportBad: profile.transport === "unknown",
    securityBad: profile.security === "unknown",
    insecure,
    goneText: profile.isStale
      ? profile.isPinned
        ? "It dropped out of the public list. Pinned, so it stays until you unpin and remove it."
        : "It dropped out of the public list at a refresh. It stays here until you remove it."
      : undefined,
    unsupported: bad
      ? bad === "security"
        ? { label: "Unsupported security — can’t connect", text: "Xray can’t start this profile. Add the link again with tls, reality or none to use it." }
        : { label: "Unsupported transport — can’t connect", text: "Xray can’t start this profile. Add the link again with a supported transport, like tcp, ws, grpc or xhttp." }
      : undefined,
    state,
    hint: bad ? "Can’t be used for Connect" : "Select for Connect",
    hitLabel: bad ? `${profile.name} can’t be used: Xray doesn’t recognize its settings` : `Select ${profile.name} for Connect`,
    // The card's own tooltip: its body ignores the pointer, so the tag can't have one.
    hitTitle: insecure ? `${profile.name} · ${address}\n${insecure.text}` : `${profile.name} · ${address}`,
    pinLabel: profile.isPinned ? "Pinned" : "Pin",
    pinTitle: profile.isPinned ? "Pinned: kept when you remove unpinned profiles. Click to unpin." : "Pin to keep it when you remove unpinned profiles",
    removeBlocked: Boolean(ownSession),
    removeLabel: ownSession ? `Remove ${profile.name} (disconnect Xray first)` : `Remove ${profile.name}`,
    removeTitle: ownSession
      ? ownSession === "connected"
        ? "Connected now. Disconnect Xray to remove this profile."
        : "In use by Connect right now. Disconnect Xray to remove this profile."
      : "Remove profile"
  };
}

export interface ToastCopy {
  title: string;
  message?: string;
}

/** Selecting a profile Xray can't run. */
export function unsupportedSelectCopy(profile: ProxyProfile): ToastCopy {
  return {
    title: `Can’t use ${profile.name}`,
    message:
      unsupportedPart(profile) === "transport"
        ? "Xray doesn’t recognize its transport. Add the link again with a supported one, like tcp, ws, grpc or xhttp, then pick it."
        : "Xray doesn’t recognize its security mode. Add the link again with tls, reality or none, then pick it."
  };
}

/** Selecting a profile that dropped out of the public list. */
export function goneSelectCopy(profile: ProxyProfile): ToastCopy {
  return {
    title: "Selected for now",
    message: `${profile.name} is gone from the public list, so the next refresh, import or removal moves the selection to another profile.`
  };
}

/** Removing the profile a session runs on. */
export function removeBlockedCopy(profile: ProxyProfile, session: XraySession | undefined): ToastCopy {
  return {
    title: "Disconnect Xray first",
    message:
      session?.phase === "connected"
        ? `${profile.name} is carrying your traffic right now. Disconnect on Connect, then remove it.`
        : `${profile.name} is in use by Connect right now. Disconnect on Connect, then remove it.`
  };
}

// ---------- results bar, empty states, paging ----------

/** "Connect uses de-fra-reality" / "Next connect uses …" / "No profile selected". */
export function currentSelection(
  profiles: readonly ProxyProfile[],
  selectedId: string | undefined,
  session: XraySession | undefined
): { label: string; name?: string } {
  const selected = selectedId ? profiles.find((profile) => profile.id === selectedId) : undefined;
  if (!selected) {
    return { label: "No profile selected" };
  }
  const nextDiffers = Boolean(session && session.profileId !== selected.id);
  return { label: nextDiffers ? "Next connect uses" : "Connect uses", name: selected.name };
}

export function resultsSummary(input: {
  filter: ProfileFilter;
  query: string;
  /** Profiles that pass the filter and search. */
  matches: number;
  /** Cards on screen. */
  shown: number;
  counts: ProfileCounts;
}): { text: string; sub: string } {
  const query = input.query.trim();
  if (query) {
    return {
      text: `${formatCount(input.matches)} ${input.matches === 1 ? "match" : "matches"} for “${query}”`,
      sub: input.filter === "all" ? "Across all profiles" : `In ${FILTER_NAMES[input.filter]}`
    };
  }
  if (input.filter === "pinned") {
    return { text: `${formatCount(input.counts.pinned)} pinned`, sub: "Kept when you remove unpinned profiles" };
  }
  if (input.filter === "gone") {
    return { text: `${formatCount(input.counts.gone)} gone from source`, sub: "No longer in the public list" };
  }
  const all = input.counts.all;
  return {
    text: input.shown < input.matches ? `Showing ${formatCount(input.shown)} of ${formatCount(all)}` : all === 1 ? "1 profile" : `All ${formatCount(all)} profiles`,
    sub: "In the order you added them"
  };
}

export function noMatchCopy(filter: ProfileFilter, query: string): { title: string; text: string } {
  return {
    title: `No profiles match “${query.trim()}”`,
    text:
      filter === "all"
        ? "Search looks at names, hosts, ports, protocols and transports. Check the spelling or try part of a host."
        : `Nothing in ${FILTER_NAMES[filter]} matches. Search looks at names, hosts, ports, protocols and transports.`
  };
}

export function filterEmptyCopy(filter: Exclude<ProfileFilter, "all">): { title: string; text: string } {
  return filter === "pinned"
    ? { title: "No pinned profiles", text: "Pin the profiles you rely on. Pinned ones stay when you use Remove unpinned." }
    : { title: "Nothing gone from source", text: "Every public profile was still listed at the last refresh." };
}

export function moreBlockCopy(shown: number, total: number): { meta: string; label: string; percent: number } {
  const remaining = Math.max(0, total - shown);
  return {
    meta: `Showing ${formatCount(shown)} of ${formatCount(total)}`,
    label: remaining > PROFILE_PAGE_SIZE ? `Show ${PROFILE_PAGE_SIZE} more · ${formatCount(remaining)} left` : `Show ${formatCount(remaining)} more`,
    percent: total > 0 ? Math.round((100 * shown) / total) : 100
  };
}

// ---------- public list ----------

export interface PublicListInfo {
  /** When the public list last answered, as far as the saved profiles tell. */
  lastRefreshAt?: string;
  /** Public profiles that were in the list at that refresh. */
  listed: number;
}

/**
 * What the toolbar says about the public list. The stored refresh record is
 * exact; stores from before it existed fall back to what the saved public
 * profiles tell (their last-seen time and how many are still listed).
 */
export function publicListInfo(profiles: readonly ProxyProfile[], refresh?: PublicProxyRefresh): PublicListInfo {
  if (refresh) {
    return { lastRefreshAt: refresh.at, listed: refresh.listed };
  }
  let listed = 0;
  let lastListed: string | undefined;
  let lastGone: string | undefined;
  for (const profile of profiles) {
    if (profile.source !== "remote") {
      continue;
    }
    if (profile.isStale) {
      lastGone = latest(lastGone, profile.updatedAt);
    } else {
      listed += 1;
      lastListed = latest(lastListed, profile.lastSeenAt);
    }
  }
  return { lastRefreshAt: lastListed ?? lastGone, listed };
}

export interface RefreshFailure {
  at: Date;
  /** Lower-case clause: "the source timed out". */
  reason: string;
}

export function publicListMeta(input: {
  info: PublicListInfo;
  refreshing: boolean;
  failure?: RefreshFailure;
  now?: Date;
}): { text: string; error: boolean } {
  const { info, now = new Date() } = input;
  if (input.refreshing) {
    return { text: "Downloading the public list…", error: false };
  }
  const last = info.lastRefreshAt ? `${formatDay(info.lastRefreshAt, now)} ${formatTime(info.lastRefreshAt)}` : undefined;
  if (input.failure) {
    return {
      text: `Refresh failed at ${formatTime(input.failure.at)}: ${input.failure.reason}.${last ? ` Last good list from ${last}.` : ""}`,
      error: true
    };
  }
  if (!last) {
    return { text: "Not loaded yet. Free profiles from a fixed public source; use them only if you trust it.", error: false };
  }
  return { text: `Last refreshed ${last} · ${plural(info.listed, "profile")} in the list`, error: false };
}

/** Why a public list refresh failed: a clause for the toolbar and copy for the toast. */
export function describeRefreshFailure(error: unknown): { reason: string; message: string; technical?: string } {
  const raw = errorText(error).trim();
  const text = stripIpcPrefix(raw) || raw;
  const technical = raw || undefined;
  if (/public proxy refresh timed out/iu.test(text)) {
    return {
      reason: "the source timed out",
      message: "The source didn’t answer within 30 seconds. Nothing changed. Check your connection and try again.",
      technical
    };
  }
  const status = /^Public proxy refresh failed:\s*(.+?)\.?$/iu.exec(text);
  if (status) {
    return {
      reason: `the source answered ${status[1]}`,
      message: `The source answered ${status[1]}. Nothing changed. Try again later.`,
      technical
    };
  }
  if (/larger than the allowed limit/iu.test(text)) {
    return {
      reason: "the list was over 2 MB",
      message: "The public list is bigger than the 2 MB limit, so nothing was loaded. Nothing changed.",
      technical
    };
  }
  if (/profile count exceeds the \d+ profile limit/iu.test(text)) {
    return {
      reason: "it would pass the 10,000-profile limit",
      message: "The new public profiles would take your library past 10,000 profiles, so nothing was added or updated. Remove profiles you don’t use, then refresh again.",
      technical
    };
  }
  const described = describeError(error, { target: "the public list source" });
  if (/\b(ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENETUNREACH|ENETDOWN)\b|net::ERR_|fetch failed|socket hang up|certificate/iu.test(text)) {
    return { reason: "the source couldn’t be reached", message: `${described.message} Nothing changed.`, technical };
  }
  const clause = text.replace(/\.$/u, "");
  return {
    reason: clause ? clause.charAt(0).toLowerCase() + clause.slice(1) : "something went wrong",
    message: `${described.message} Nothing changed.`,
    technical
  };
}

export interface RefreshToast extends ToastCopy {
  tone: "success" | "warning";
}

/** Toast after a successful refresh, from the library before and after it. */
export function summarizeRefresh(before: AppStore, after: AppStore, result: ImportProxyProfilesResult): RefreshToast {
  const staleBefore = new Set(before.proxyProfiles.filter((profile) => profile.isStale).map((profile) => profile.id));
  const existedBefore = new Set(before.proxyProfiles.map((profile) => profile.id));
  const gone = after.proxyProfiles.filter((profile) => profile.isStale && existedBefore.has(profile.id) && !staleBefore.has(profile.id)).length;
  const selectedAfter = after.proxyProfiles.find((profile) => profile.id === after.selectedProxyProfileId);
  let moved = "";
  if (before.selectedProxyProfileId && before.selectedProxyProfileId !== after.selectedProxyProfileId) {
    moved = selectedAfter ? ` Connect now uses ${selectedAfter.name}.` : " No profile is selected for Connect now.";
  }
  const received = result.imported + result.updated;

  if (before.proxyProfiles.length === 0) {
    if (received === 0) {
      return { tone: "warning", title: "The public list came back empty", message: "None of its lines were usable links, so nothing was added. Try again later." };
    }
    return {
      tone: "success",
      title: "Public list loaded",
      message: `${plural(result.imported, "new profile")}.${selectedAfter ? ` ${selectedAfter.name} is selected for Connect.` : ""}`
    };
  }
  const listedBefore = before.proxyProfiles.filter((profile) => profile.source === "remote" && !profile.isStale).length;
  if (received === 0 && listedBefore > 0) {
    return {
      tone: "warning",
      title: "The public list came back empty",
      message: `None of its lines were usable links, so ${plural(gone, "public profile")} ${gone === 1 ? "is" : "are"} now gone from source. They stay until you remove them.${moved}`
    };
  }
  if (result.imported === 0 && gone === 0) {
    return {
      tone: "success",
      title: "Public list refreshed",
      message: `No changes: ${formatCount(result.updated)} updated, nothing new, nothing gone from source.${moved}`
    };
  }
  const message = `${gone > 0 ? "Gone profiles stay until you remove them." : ""}${moved}`.trim();
  return {
    tone: "success",
    title: `Public list refreshed: ${formatCount(result.imported)} new, ${formatCount(result.updated)} updated, ${formatCount(gone)} gone from source`,
    message: message || undefined
  };
}

// ---------- saving ----------

/**
 * Toast after Add profile. Saving a link that's already in the library
 * updates that profile instead, and the toast says so.
 */
export function savedProfileCopy(before: AppStore, after: AppStore): ToastCopy {
  const known = new Set(before.proxyProfiles.map((profile) => profile.id));
  const added = after.proxyProfiles.find((profile) => !known.has(profile.id));
  if (added) {
    const selectedNow = after.selectedProxyProfileId === added.id && before.selectedProxyProfileId !== added.id;
    return { title: "Profile saved", message: `${added.name} is in Xray profiles.${selectedNow ? " It’s selected for Connect." : ""}` };
  }
  const updated = after.proxyProfiles.reduce<ProxyProfile | undefined>(
    (latestSoFar, profile) => (!latestSoFar || Date.parse(profile.updatedAt) >= Date.parse(latestSoFar.updatedAt) ? profile : latestSoFar),
    undefined
  );
  return updated
    ? { title: "Profile updated", message: `${updated.name} was already in your library, so its details were updated.` }
    : { title: "Profile saved" };
}

/**
 * The selected insecure=1 profile that a pinned Hysteria 2 link fixes: same
 * host and ports. Profiles can't be edited, so the pinned link is saved as a
 * new profile, and selecting it keeps Connect off the tagged one. Links stay
 * in the main process, so the auth can't be compared here; only the selected
 * profile is ever stood in for.
 */
export function insecureProfileFixedBy(
  link: Pick<LinkPreview, "protocol" | "host" | "port" | "hopPorts" | "certificatePinned"> | undefined,
  store: Pick<AppStore, "proxyProfiles" | "selectedProxyProfileId">
): ProxyProfile | undefined {
  if (!link || link.protocol !== "hysteria2" || !link.certificatePinned) {
    return undefined;
  }
  const selected = store.proxyProfiles.find((profile) => profile.id === store.selectedProxyProfileId);
  if (!selected || selected.protocol !== "hysteria2" || !selected.insecureWithoutPin || selected.host !== link.host) {
    return undefined;
  }
  return (selected.hopPorts || String(selected.port)) === (link.hopPorts || String(link.port)) ? selected : undefined;
}

/** Hint under the previewed link, and the toast once the pinned profile took over the selection. */
export function fixedInsecureCopy(tagged: Pick<ProxyProfile, "name">, saved?: Pick<ProxyProfile, "name">): string {
  if (!saved) {
    return `Saving selects it for Connect in place of ${tagged.name}, which is tagged ${HYSTERIA2_INSECURE_TAG}.`;
  }
  return saved.name === tagged.name
    ? `The ${saved.name} with the pinSHA256 is selected for Connect in place of the one tagged ${HYSTERIA2_INSECURE_TAG}. You can remove that one now.`
    : `${saved.name} is selected for Connect in place of ${tagged.name}, which is tagged ${HYSTERIA2_INSECURE_TAG}. You can remove that one now.`;
}

// ---------- removal ----------

export interface BulkRemoveCopy {
  title: string;
  description: string;
  confirmLabel: string;
  removed: string;
  removedHint: string;
  kept: string;
  /** "Xray disconnects first" callout text, while a session runs. */
  xrayWarning?: string;
  /** "Nothing disconnects" callout text otherwise. */
  calmNote?: string;
  footnote: string;
}

export function bulkRemoveCopy(input: {
  counts: ProfileCounts;
  session?: XraySession;
  /** The profile the session runs on, if it's still saved. */
  sessionProfile?: ProxyProfile;
  /** SSH server name when an SSH session runs instead. */
  sshSessionName?: string;
}): BulkRemoveCopy {
  const { counts } = input;
  const unpinned = formatCount(counts.unpinned);
  const pinned = formatCount(counts.pinned);
  let xrayWarning: string | undefined;
  let calmNote: string | undefined;
  if (sessionWouldStop(input.session)) {
    const name = input.sessionProfile?.name ?? input.session?.name;
    const through = name ? `The tunnel through ${name}` : "The Xray tunnel";
    if (!input.sessionProfile) {
      xrayWarning = `${through} closes before anything is removed. Connect again when it’s done.`;
    } else if (input.sessionProfile.isPinned) {
      xrayWarning = `${through} closes before anything is removed, even though that profile is pinned. Connect again when it’s done.`;
    } else {
      xrayWarning = `${through} closes first, and ${name} is removed with the other unpinned profiles. Pick another profile on Connect when it’s done.`;
    }
  } else if (input.sshSessionName) {
    calmNote = `Xray isn’t running, so your SSH session to ${input.sshSessionName} stays up. When Xray is connected, it disconnects before profiles are removed.`;
  } else {
    calmNote = "Xray isn’t running right now. When it is, it disconnects before profiles are removed, even if its profile is pinned.";
  }
  return {
    title: `Remove ${unpinned} unpinned ${counts.unpinned === 1 ? "profile" : "profiles"}?`,
    description:
      counts.pinned === 0
        ? "Nothing is pinned, so every profile goes. This can’t be undone."
        : `Your ${pinned} pinned ${counts.pinned === 1 ? "profile stays" : "profiles stay"}. This can’t be undone.`,
    confirmLabel: `Remove ${unpinned} ${counts.unpinned === 1 ? "profile" : "profiles"}`,
    removed: unpinned,
    removedHint: counts.goneUnpinned > 0 ? `including ${formatCount(counts.goneUnpinned)} gone from source` : counts.unpinned === 1 ? "unpinned profile" : "unpinned profiles",
    kept: pinned,
    xrayWarning,
    calmNote,
    footnote: "Public profiles come back at the next refresh if they’re still listed. Imported and added ones need their links again."
  };
}

export function singleRemoveCopy(profile: ProxyProfile): { title: string; description: string; meta: string; footnote: string } {
  return {
    title: `Remove “${profile.name}”?`,
    description: "It disappears from your library and from the Connect picker. This can’t be undone.",
    meta: `${profileAddress(profile)} · ${sourceLabel(profile.source)}`,
    footnote:
      profile.source === "remote"
        ? "If it’s still in the public list, the next refresh brings it back."
        : "To get it back, add its link again. Links can’t be viewed or exported after saving."
  };
}

/** Success toast after removing one profile; says where Connect's selection went. */
export function removedOneCopy(profile: ProxyProfile, before: AppStore, after: AppStore): ToastCopy {
  let moved = "";
  if (before.selectedProxyProfileId !== after.selectedProxyProfileId) {
    const next = after.proxyProfiles.find((candidate) => candidate.id === after.selectedProxyProfileId);
    moved = next ? ` Connect now uses ${next.name}.` : "";
  }
  return { title: "Profile removed", message: `${profile.name} is no longer in your library.${moved}` };
}

export function removedUnpinnedCopy(removed: number, kept: number, xrayStopped: boolean): ToastCopy {
  return {
    title: `Removed ${formatCount(removed)} unpinned ${removed === 1 ? "profile" : "profiles"}`,
    message: `${kept === 0 ? "Nothing was pinned, so your library is empty now." : `${plural(kept, "pinned profile")} kept.`}${
      xrayStopped ? " Xray was disconnected first. Connect again when you are ready." : ""
    }`
  };
}

function latest(current: string | undefined, candidate: string | undefined): string | undefined {
  if (!candidate || Number.isNaN(Date.parse(candidate))) {
    return current;
  }
  return !current || Date.parse(candidate) > Date.parse(current) ? candidate : current;
}
