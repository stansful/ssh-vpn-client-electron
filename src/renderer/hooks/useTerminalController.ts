import { useEffect, useMemo, useRef, useState, type Dispatch, type FormEvent, type SetStateAction } from "react";
import { api } from "../api.js";
import { toErrorMessage } from "../lib/labels.js";
import type { AppSnapshot, RuntimeStatus } from "../../shared/types.js";

export function useTerminalController({
  snapshot,
  runtime,
  setSnapshot,
  setNotice
}: {
  snapshot: AppSnapshot | undefined;
  runtime: RuntimeStatus | undefined;
  setSnapshot: Dispatch<SetStateAction<AppSnapshot | undefined>>;
  setNotice: Dispatch<SetStateAction<string>>;
}) {
  const [terminalInput, setTerminalInput] = useState("");
  const [terminalOpening, setTerminalOpening] = useState(false);
  const [terminalShellOpen, setTerminalShellOpen] = useState(false);
  const terminalStartupNormalized = useRef(false);
  const terminalText = useMemo(() => (snapshot?.terminal ?? []).map((line) => line.text).join(""), [snapshot?.terminal]);

  useEffect(() => {
    if (snapshot?.runtime.state !== "Connected") {
      setTerminalShellOpen(false);
    }
  }, [snapshot?.runtime.state]);

  useEffect(() => {
    if (!snapshot || terminalStartupNormalized.current) {
      return;
    }
    terminalStartupNormalized.current = true;
    if (snapshot.runtime.state !== "Connected" && snapshot.store.settings.terminalExpanded) {
      void api
        .updateSettings({ ...snapshot.store.settings, terminalExpanded: false })
        .then(setSnapshot)
        .catch((error: unknown) => setNotice(toErrorMessage(error)));
    }
  }, [snapshot, setNotice, setSnapshot]);

  useEffect(() => {
    if (snapshot?.runtime.state === "Connected" && snapshot.store.settings.terminalExpanded) {
      void ensureTerminalShellOpen();
    }
  }, [snapshot?.runtime.state, snapshot?.store.settings.terminalExpanded]);

  function sendTerminalInput(event: FormEvent): void {
    event.preventDefault();
    if (!terminalInput.trim()) {
      return;
    }
    void api.terminalInput(`${terminalInput}\n`);
    setTerminalInput("");
  }

  async function handleTerminalToggle(open: boolean): Promise<void> {
    if (!snapshot) {
      return;
    }
    try {
      const next = await api.updateSettings({ ...snapshot.store.settings, terminalExpanded: open });
      setSnapshot(next);
      if (open) {
        await ensureTerminalShellOpen();
      } else if (terminalShellOpen && runtime?.state === "Connected") {
        await closeTerminalShell(false);
      }
    } catch (error) {
      setNotice(toErrorMessage(error));
    }
  }

  async function ensureTerminalShellOpen(): Promise<void> {
    if (runtime?.state !== "Connected" || terminalShellOpen || terminalOpening) {
      return;
    }
    setTerminalOpening(true);
    try {
      const next = await api.openTerminal();
      setSnapshot(next);
      setTerminalShellOpen(true);
    } catch (error) {
      setNotice(toErrorMessage(error));
    } finally {
      setTerminalOpening(false);
    }
  }

  async function closeTerminalShell(collapse = true): Promise<void> {
    if (terminalOpening) {
      return;
    }
    setTerminalOpening(true);
    try {
      const next = await api.closeTerminal();
      setSnapshot(next);
      setTerminalShellOpen(false);
      if (collapse && snapshot) {
        const collapsed = await api.updateSettings({ ...snapshot.store.settings, terminalExpanded: false });
        setSnapshot(collapsed);
      }
    } catch (error) {
      setNotice(toErrorMessage(error));
    } finally {
      setTerminalOpening(false);
    }
  }

  return {
    terminalInput,
    setTerminalInput,
    terminalOpening,
    terminalText,
    sendTerminalInput,
    handleTerminalToggle,
    closeTerminalShell
  };
}
