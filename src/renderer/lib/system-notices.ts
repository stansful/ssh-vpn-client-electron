import type { AppUpdateFormat, AutoConnectNotice, DesktopPlatform, TunnelCheckResult } from "../../shared/types.js";
import { formatLatency } from "./format.js";
import type { ReconnectReasonKind } from "./runtime-message.js";

/** How long after auto-connect started a newly opened window still announces it. */
export const AUTO_CONNECT_NOTICE_MS = 60_000;

export interface NoticeCopy {
  title: string;
  message: string;
}

/** "Connecting automatically" while the app-start connect is still running; undefined once it is old news. */
export function autoConnectCopy(notice: AutoConnectNotice | undefined, now = Date.now()): NoticeCopy | undefined {
  if (!notice) {
    return undefined;
  }
  const at = Date.parse(notice.at);
  if (!Number.isFinite(at) || now - at > AUTO_CONNECT_NOTICE_MS) {
    return undefined;
  }
  return {
    title: "Connecting automatically",
    message: `Auto-connect is on, so Shadow SSH is starting ${notice.targetName}.`
  };
}

const RECONNECTING_TITLE: Partial<Record<ReconnectReasonKind, string>> = {
  wake: "Reconnecting · woke from sleep",
  "network-change": "Reconnecting · network changed"
};

/**
 * Info toast when a live session drops for a routine reason the app handles
 * at once (wake, network change). Other reasons are explained on Connect.
 */
export function reconnectingCopy(kind: ReconnectReasonKind | undefined, targetName: string | undefined, platform: DesktopPlatform): NoticeCopy | undefined {
  const title = kind ? RECONNECTING_TITLE[kind] : undefined;
  if (!title) {
    return undefined;
  }
  // Only Windows keeps the system proxy pointed at the tunnel while it retries.
  const hold = platform === "windows" ? " Routing stays on for 30 s." : "";
  return {
    title,
    message: `Trying ${targetName ?? "the server"} now instead of waiting for the next attempt.${hold}`
  };
}

const RECONNECTED_SENTENCE: Partial<Record<ReconnectReasonKind, string>> = {
  "network-change": "Reconnected after the network change.",
  wake: "Reconnected after waking from sleep.",
  "clock-jump": "Reconnected after the pause.",
  watchdog: "Reconnected after the watchdog restarted the session."
};

/** "Back online · Frankfurt-01" toast; the check result is added once the automatic check passes. */
export function backOnlineCopy(input: { targetName?: string; reason?: ReconnectReasonKind; check?: TunnelCheckResult }): NoticeCopy {
  const sentence = (input.reason && RECONNECTED_SENTENCE[input.reason]) ?? "The tunnel reconnected on its own.";
  const check = input.check?.ok && input.check.latencyMs !== undefined ? ` Tunnel check: Passed · ${formatLatency(input.check.latencyMs)}.` : "";
  return {
    title: input.targetName ? `Back online · ${input.targetName}` : "Back online",
    message: `${sentence}${check}`
  };
}

/** "<file> is ready to run." (or "to install" for a DMG or .deb) for the Update downloaded toast. */
export function updateDownloadedCopy(filePath: string | undefined, assetName: string | undefined, format?: AppUpdateFormat): NoticeCopy {
  const fileName = filePath?.split(/[\\/]/u).pop() || assetName || "The new version";
  const step = format === "macos-dmg" || format === "linux-deb" ? "install" : "run";
  return { title: "Update downloaded", message: `${fileName} is ready to ${step}.` };
}
