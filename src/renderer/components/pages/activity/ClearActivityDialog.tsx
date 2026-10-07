import { Activity, Check, Copy, FileText, ShieldAlert, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { describeError } from "../../../lib/errors.js";
import { formatCount } from "../../../lib/format.js";
import { Button, Callout, Icon, Modal } from "../../ui/index.js";
import { clearDescription, type LogSizeInfo } from "./activity-log.js";

const COPIED_MS = 1600;

export interface ClearActivityDialogProps {
  open: boolean;
  onClose: () => void;
  liveCount: number;
  attentionCount: number;
  size: LogSizeInfo;
  /** main.log, then its archives. */
  fileNames: readonly string[];
  /** Deletes everything; a rejection keeps the dialog open with the error. */
  onClear: () => Promise<void>;
  /** Copies events, attention and the log; resolves true when copied. */
  onCopyEverything: () => Promise<boolean>;
}

/** "Clear all activity?" — lists exactly what gets deleted, with a copy-first escape hatch. */
export function ClearActivityDialog({ open, onClose, liveCount, attentionCount, size, fileNames, onClear, onCopyEverything }: ClearActivityDialogProps): JSX.Element {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const [busy, setBusy] = useState(false);
  const [copying, setCopying] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<unknown>();
  const copiedTimer = useRef<number>();

  useEffect(() => {
    if (open) {
      setBusy(false);
      setCopied(false);
      setError(undefined);
    }
  }, [open]);

  useEffect(() => () => window.clearTimeout(copiedTimer.current), []);

  const [current, ...archives] = fileNames;
  // Exact sizes list only the archives on disk; otherwise every possible one is named.
  const archiveRows = archives
    .map((name, index) => ({
      name,
      size: size.archiveSizes ? size.archiveSizes[index] : size.archives === "maybe" ? "Up to 5 MB" : "If present"
    }))
    .filter((row): row is { name: string; size: string } => row.size !== undefined);
  const described = error !== undefined ? describeError(error, { title: "Couldn’t clear activity" }) : undefined;

  const clear = (): void => {
    setBusy(true);
    setError(undefined);
    onClear().then(
      () => {
        setBusy(false);
        onClose();
      },
      (reason: unknown) => {
        setBusy(false);
        setError(reason);
      }
    );
  };

  const copyEverything = (): void => {
    setCopying(true);
    void onCopyEverything()
      .then((ok) => {
        if (ok) {
          setCopied(true);
          window.clearTimeout(copiedTimer.current);
          copiedTimer.current = window.setTimeout(() => setCopied(false), COPIED_MS);
        }
      })
      .finally(() => setCopying(false));
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      eyebrow="Activity"
      title="Clear all activity?"
      description={clearDescription({ liveCount, attentionCount, archives: size.archives, archiveCount: size.archiveCount })}
      icon={Trash2}
      iconTone="danger"
      size="confirm"
      role="alertdialog"
      busy={busy}
      closeButton={false}
      initialFocusRef={cancelRef}
      className="ac-clear"
      footer={
        <>
          <Button
            variant={copied ? "ok" : "ghost"}
            className="lead"
            icon={copied ? Check : Copy}
            busy={copying}
            disabled={busy}
            onClick={copyEverything}
          >
            <span className="btn-label-swap" key={copied ? "copied" : "copy"}>
              {copied ? "Copied" : "Copy everything first"}
            </span>
          </Button>
          <Button ref={cancelRef} disabled={busy} onClick={onClose}>
            Cancel
          </Button>
          <Button variant="danger-solid" busy={busy} busyLabel="Clearing…" onClick={clear}>
            Clear activity
          </Button>
        </>
      }
    >
      <ul className="ac-del" aria-label="What will be deleted">
        <li>
          <Icon icon={FileText} size="sm" />
          <span className="mono">{current}</span>
          <span className="ac-file-size">{size.mainSize ?? ""}</span>
        </li>
        {size.archives !== "none"
          ? archiveRows.map((row) => (
              <li key={row.name}>
                <Icon icon={FileText} size="sm" />
                <span className="mono">{row.name}</span>
                <span className="ac-file-size">{row.size}</span>
              </li>
            ))
          : null}
        <li>
          <Icon icon={Activity} size="sm" />
          <span>Live events from this connection</span>
          <span className="ac-file-size">{formatCount(liveCount)}</span>
        </li>
        {attentionCount > 0 ? (
          <li>
            <Icon icon={ShieldAlert} size="sm" />
            <span>Needs your attention</span>
            <span className="ac-file-size">{formatCount(attentionCount)}</span>
          </li>
        ) : null}
      </ul>
      <span className="hint">Recording keeps going, so new events start showing up right away. If you need these for a bug report, copy them first.</span>
      {described ? (
        <Callout tone="danger" title={described.title} role="alert">
          {described.message}
        </Callout>
      ) : null}
    </Modal>
  );
}
