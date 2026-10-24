import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { describeError } from "../../../lib/errors.js";
import { isOpenPending, nextShellRecord, shellNeedsClose, type ShellRecordEvent } from "./shell-record.js";
import { terminalState, type ShellRecord, type TerminalState } from "./terminal-view.js";

export interface ServerShell {
  state: TerminalState;
  /** Why the shell didn't open (state "failed"). */
  error?: string;
  /** The panel is expanded (saved in settings). */
  expanded: boolean;
  /** A close request is in flight. */
  closing: boolean;
  setExpanded: (next: boolean) => void;
  /** Opens a shell again after the server closed it or it failed to open. */
  reopen: () => void;
  /** Ends the shell (never the tunnel) and collapses the panel. */
  closeAndCollapse: () => void;
  send: (line: string) => void;
}

/** Longest line the main process accepts in one send, newline included. */
const MAX_TERMINAL_INPUT = 64 * 1024;

/**
 * Owns the line-mode shell on the SSH session: opens it by itself while the
 * panel is expanded and SSH is connected (again after a reconnect), and keeps
 * open/close failures inside the terminal instead of in a stray notice.
 */
export function useServerShell(): ServerShell {
  const { snapshot, runtime, activeTransport, store, setSnapshot, updateSettings, toast } = useAppData();
  const live = activeTransport === "ssh" && runtime.state === "Connected";
  const session = live ? runtime.connectedAt ?? "connected" : "";
  const savedExpanded = store.settings.terminalExpanded;
  const [expanded, setExpandedState] = useState(savedExpanded);
  const [record, setRecord] = useState<ShellRecord>();
  const [closing, setClosing] = useState(false);
  // The record as of the last event, ahead of the re-render: a collapse and
  // re-expand can both land while an open is still on its way.
  const recordRef = useRef<ShellRecord>();
  const attempts = useRef(0);
  const historyRef = useRef(snapshot.terminal);
  historyRef.current = snapshot.terminal;

  useEffect(() => setExpandedState(savedExpanded), [savedExpanded]);

  const apply = useCallback((event: ShellRecordEvent): void => {
    recordRef.current = nextShellRecord(recordRef.current, event);
    setRecord(recordRef.current);
  }, []);

  const open = useCallback(async (): Promise<void> => {
    if (!session || isOpenPending(recordRef.current, session)) {
      return;
    }
    const attempt = ++attempts.current;
    apply({ type: "open", session, attempt, afterId: historyRef.current.at(-1)?.id });
    try {
      setSnapshot(await api.openTerminal());
      apply({ type: "opened", session, attempt });
    } catch (error) {
      apply({ type: "open-failed", session, attempt, error: describeError(error).message });
    }
  }, [apply, session, setSnapshot]);

  // Expanded while connected means a shell should exist for this session.
  const hasRecord = record?.session === session;
  useEffect(() => {
    if (expanded && live && !hasRecord) {
      void open();
    }
  }, [expanded, hasRecord, live, open]);

  const close = useCallback(async (): Promise<void> => {
    const hadShell = shellNeedsClose(recordRef.current, session);
    // Also drops an open still on its way: its answer no longer counts.
    apply({ type: "close" });
    if (!hadShell || !live) {
      return;
    }
    setClosing(true);
    try {
      setSnapshot(await api.closeTerminal());
    } catch (error) {
      const described = describeError(error, { title: "Couldn't close the shell" });
      toast({ tone: "error", title: described.title, message: described.message, details: described.technical });
    } finally {
      setClosing(false);
    }
  }, [apply, live, session, setSnapshot, toast]);

  const setExpanded = useCallback(
    (next: boolean): void => {
      setExpandedState(next);
      if (!next) {
        void close();
      }
      void updateSettings({ terminalExpanded: next });
    },
    [close, updateSettings]
  );

  const send = useCallback(
    (line: string): void => {
      if (!line.trim()) {
        return;
      }
      const payload = `${line}\n`;
      if (payload.length > MAX_TERMINAL_INPUT) {
        toast({ tone: "error", title: "Couldn't send the command", message: "A line can be up to 65,535 characters. Send a shorter one." });
        return;
      }
      void api.terminalInput(payload).catch((error: unknown) => {
        const described = describeError(error, { title: "Couldn't send the command" });
        toast({ tone: "error", title: described.title, message: described.message, details: described.technical });
      });
    },
    [toast]
  );

  return {
    state: terminalState({ live, expanded, session, record, history: snapshot.terminal }),
    error: record?.session === session ? record.error : undefined,
    expanded,
    closing,
    setExpanded,
    reopen: () => void open(),
    closeAndCollapse: () => setExpanded(false),
    send
  };
}
