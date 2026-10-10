import { useEffect, useRef } from "react";
import type { AttentionEvent, AttentionKind, AppSnapshot, TunnelCheckResult } from "../../shared/types.js";
import { activeTargetName } from "../components/shell/connection-target.js";
import { classifyReconnectReason, type ReconnectReasonKind } from "../lib/runtime-message.js";
import { autoConnectCopy, backOnlineCopy, reconnectingCopy, updateDownloadedCopy } from "../lib/system-notices.js";
import type { NavigateFn } from "./useNavigation.js";
import type { ToastApi, ToastInput } from "./useToasts.js";

const SHOWN_ATTENTION_KEY = "shadow-ssh.attention-toasted";
const MAX_REMEMBERED = 60;

function readShownIds(): Set<string> {
  try {
    const raw = window.localStorage.getItem(SHOWN_ATTENTION_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return new Set(Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === "string") : []);
  } catch {
    return new Set();
  }
}

function writeShownIds(ids: Set<string>): void {
  try {
    window.localStorage.setItem(SHOWN_ATTENTION_KEY, JSON.stringify([...ids].slice(-MAX_REMEMBERED)));
  } catch {
    // Storage can be unavailable; worst case a toast shows again after a reload.
  }
}

function attentionAction(kind: AttentionKind, navigate: NavigateFn, loggingEnabled: boolean): ToastInput["action"] {
  switch (kind) {
    case "split-tunnel-no-targets":
    case "auto-connect-skipped":
      return { label: "Open routing", onClick: () => navigate("routing") };
    case "tun-unavailable":
      return { label: "Open routing", onClick: () => navigate("routing", { type: "routing-tab", tab: "apps" }) };
    case "reconnect-stopped":
      return { label: "Open Connect", onClick: () => navigate("connect") };
    case "auto-connect-failed":
      return loggingEnabled ? { label: "Open activity", onClick: () => navigate("activity") } : undefined;
    default:
      return undefined;
  }
}

export function attentionToast(event: AttentionEvent, navigate: NavigateFn, loggingEnabled: boolean): ToastInput {
  return {
    id: `attention-${event.id}`,
    tone: event.level === "error" ? "error" : event.level === "warning" ? "warning" : "info",
    title: event.title,
    message: event.message,
    action: attentionAction(event.kind, navigate, loggingEnabled)
  };
}

/** How long "Back online" waits for the automatic tunnel check before it shows without it. */
const BACK_ONLINE_CHECK_WAIT_MS = 4000;

interface PendingBackOnline {
  since: number;
  targetName?: string;
  reason?: ReconnectReasonKind;
  timer: number;
}

/**
 * App-level toasts for things that happen without a click: new attention
 * events (each shown once, even across window reloads), auto-connect at app
 * start, a session that drops for a routine reason and comes back on its own,
 * and an update that finished downloading.
 */
export function useSystemToasts(snapshot: AppSnapshot | undefined, toasts: ToastApi, navigate: NavigateFn): void {
  const shownIds = useRef<Set<string>>();
  const toastedThisSession = useRef(new Set<string>());
  const previousRuntime = useRef<{ state: string; transport: string } | undefined>();
  const reconnectReason = useRef<ReconnectReasonKind | undefined>();
  const pendingBackOnline = useRef<PendingBackOnline | undefined>();
  const shownAutoConnect = useRef<string | undefined>();
  const previousDownload = useRef<string | undefined>();

  const attention = snapshot?.attention;
  const loggingEnabled = snapshot?.store.settings.loggingEnabled ?? true;
  useEffect(() => {
    if (!attention) {
      return;
    }
    shownIds.current ??= readShownIds();
    const current = new Set(attention.map((event) => event.id));
    let changed = false;
    for (const event of [...attention].reverse()) {
      if (event.kind === "storage-unreadable" || shownIds.current.has(event.id)) {
        continue;
      }
      shownIds.current.add(event.id);
      toastedThisSession.current.add(event.id);
      changed = true;
      toasts.toast(attentionToast(event, navigate, loggingEnabled));
    }
    for (const id of [...toastedThisSession.current]) {
      if (!current.has(id)) {
        toastedThisSession.current.delete(id);
        toasts.dismiss(`attention-${id}`);
      }
    }
    if (changed) {
      writeShownIds(shownIds.current);
    }
  }, [attention, loggingEnabled, navigate, toasts]);

  const autoConnect = snapshot?.autoConnect;
  useEffect(() => {
    if (!snapshot || !autoConnect || shownAutoConnect.current === autoConnect.at) {
      return;
    }
    shownAutoConnect.current = autoConnect.at;
    // A window that opens after the attempt settled has nothing to announce.
    if (snapshot.runtime.state === "Connected" || snapshot.runtime.state === "Error") {
      return;
    }
    const copy = autoConnectCopy(autoConnect);
    if (copy) {
      toasts.toast({ id: "auto-connect", tone: "info", ...copy });
    }
    // Once per auto-connect.
  }, [autoConnect?.at]);

  const showBackOnline = (check?: TunnelCheckResult): void => {
    const pending = pendingBackOnline.current;
    if (!pending) {
      return;
    }
    window.clearTimeout(pending.timer);
    pendingBackOnline.current = undefined;
    toasts.toast({ id: "connection-restored", tone: "success", ...backOnlineCopy({ targetName: pending.targetName, reason: pending.reason, check }) });
  };

  const cancelBackOnline = (): void => {
    if (pendingBackOnline.current) {
      window.clearTimeout(pendingBackOnline.current.timer);
      pendingBackOnline.current = undefined;
    }
  };

  useEffect(() => cancelBackOnline, []);

  const state = snapshot?.runtime.state;
  const transport = snapshot?.activeTransport;
  useEffect(() => {
    if (!snapshot || !state || !transport) {
      return;
    }
    const previous = previousRuntime.current;
    previousRuntime.current = { state, transport };
    const sameTransport = previous?.transport === transport;
    if (state === "Reconnecting" && previous?.state === "Connected" && sameTransport) {
      const name = activeTargetName(snapshot);
      const reason = classifyReconnectReason(snapshot.runtime.message, name);
      reconnectReason.current = reason?.kind;
      const copy = reconnectingCopy(reason?.kind, name, snapshot.environment.platform);
      if (copy) {
        toasts.toast({ id: "reconnecting", tone: "info", ...copy });
      }
      return;
    }
    if (previous?.state === "Reconnecting" && state !== "Reconnecting") {
      toasts.dismiss("reconnecting");
    }
    if (previous?.state === "Reconnecting" && state === "Connected" && sameTransport) {
      cancelBackOnline();
      pendingBackOnline.current = {
        since: Date.now(),
        targetName: activeTargetName(snapshot),
        reason: reconnectReason.current,
        timer: window.setTimeout(() => showBackOnline(), BACK_ONLINE_CHECK_WAIT_MS)
      };
    } else if (state !== "Connected") {
      cancelBackOnline();
    }
    if (state !== "Reconnecting") {
      reconnectReason.current = undefined;
    }
    // Only the state transition matters here, not every snapshot change.
  }, [state, transport]);

  // "Back online" waits briefly for the automatic check so it can say the tunnel works.
  const lastCheck = snapshot?.lastTunnelCheck;
  useEffect(() => {
    const pending = pendingBackOnline.current;
    if (!pending || !lastCheck) {
      return;
    }
    if (Date.parse(lastCheck.at) >= pending.since - 1000) {
      showBackOnline(lastCheck.ok ? lastCheck : undefined);
    }
  }, [lastCheck]);

  const downloadState = snapshot?.updateDownload?.state;
  useEffect(() => {
    const previous = previousDownload.current;
    previousDownload.current = downloadState;
    if (!snapshot || downloadState !== "downloaded" || previous === undefined || previous === "downloaded") {
      return;
    }
    toasts.toast({
      id: "update-downloaded",
      tone: "success",
      ...updateDownloadedCopy(snapshot.updateDownload?.filePath, snapshot.updateInfo?.asset?.name, snapshot.updateInfo?.asset?.format)
    });
    // Announced app-wide so a download that finishes on another page is still seen.
  }, [downloadState]);
}
