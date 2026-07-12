import { useEffect, useMemo, useRef, useState, type Dispatch, type FormEvent, type SetStateAction } from "react";
import { api } from "../api.js";
import { toErrorMessage } from "../lib/labels.js";
import { TerminalDisplayBuffer } from "../lib/terminal-display-buffer.js";
import type { AppSnapshot, RuntimeStatus } from "../../shared/types.js";

export function useTerminalController({
  snapshot,
  runtime,
  terminalVisible,
  setSnapshot,
  setNotice
}: {
  snapshot: AppSnapshot | undefined;
  runtime: RuntimeStatus | undefined;
  terminalVisible: boolean;
  setSnapshot: Dispatch<SetStateAction<AppSnapshot | undefined>>;
  setNotice: Dispatch<SetStateAction<string>>;
}) {
  const [terminalInput, setTerminalInput] = useState("");
  const [terminalOpening, setTerminalOpening] = useState(false);
  const terminalStartupNormalized = useRef(false);
  const terminalShellOpenRef = useRef(false);
  const terminalMutationRef = useRef<Promise<void>>();
  const terminalDisplayBuffer = useRef<TerminalDisplayBuffer>();
  if (!terminalDisplayBuffer.current) {
    terminalDisplayBuffer.current = new TerminalDisplayBuffer();
  }
  const runtimeConnectedRef = useRef(runtime?.state === "Connected");
  runtimeConnectedRef.current = runtime?.state === "Connected";
  const terminalText = useMemo(
    () => terminalDisplayBuffer.current?.update(snapshot?.terminal ?? [], terminalVisible) ?? "",
    [snapshot?.terminal, terminalVisible]
  );

  useEffect(() => {
    if (snapshot?.runtime.state !== "Connected") {
      terminalShellOpenRef.current = false;
    }
  }, [snapshot?.runtime.state]);

  useEffect(() => {
    if (!snapshot || terminalStartupNormalized.current) {
      return;
    }
    terminalStartupNormalized.current = true;
    if (snapshot.runtime.state !== "Connected" && snapshot.store.settings.terminalExpanded) {
      void api
        .updateSettings({ terminalExpanded: false })
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
    void api.terminalInput(`${terminalInput}\n`).catch((error: unknown) => setNotice(toErrorMessage(error)));
    setTerminalInput("");
  }

  async function handleTerminalToggle(open: boolean): Promise<void> {
    if (!snapshot) {
      return;
    }
    try {
      const next = await api.updateSettings({ terminalExpanded: open });
      setSnapshot(next);
      if (open) {
        await ensureTerminalShellOpen();
      } else {
        await closeTerminalShell(false);
      }
    } catch (error) {
      setNotice(toErrorMessage(error));
    }
  }

  async function ensureTerminalShellOpen(): Promise<void> {
    try {
      await enqueueTerminalMutation(async () => {
        if (!runtimeConnectedRef.current || terminalShellOpenRef.current) {
          return;
        }
        const next = await api.openTerminal();
        setSnapshot(next);
        const opened = runtimeConnectedRef.current && next.runtime.state === "Connected";
        terminalShellOpenRef.current = opened;
      });
    } catch (error) {
      setNotice(toErrorMessage(error));
    }
  }

  async function closeTerminalShell(collapse = true): Promise<void> {
    try {
      await enqueueTerminalMutation(async () => {
        if (terminalShellOpenRef.current && runtimeConnectedRef.current) {
          const next = await api.closeTerminal();
          setSnapshot(next);
        }
        terminalShellOpenRef.current = false;
      });
      if (collapse && snapshot) {
        const collapsed = await api.updateSettings({ terminalExpanded: false });
        setSnapshot(collapsed);
      }
    } catch (error) {
      setNotice(toErrorMessage(error));
    }
  }

  function enqueueTerminalMutation(operation: () => Promise<void>): Promise<void> {
    const previous = terminalMutationRef.current ?? Promise.resolve();
    const next = previous.catch(() => undefined).then(operation);
    terminalMutationRef.current = next;
    setTerminalOpening(true);
    return next.finally(() => {
      if (terminalMutationRef.current === next) {
        terminalMutationRef.current = undefined;
        setTerminalOpening(false);
      }
    });
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
