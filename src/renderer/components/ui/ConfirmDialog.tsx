import { Trash2, TriangleAlert, type LucideIcon } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { describeError } from "../../lib/errors.js";
import type { ConfirmController, ConfirmOptions } from "../../hooks/useConfirm.js";
import { Button } from "./Button.js";
import { Callout } from "./Callout.js";
import { Modal } from "./Modal.js";

export interface ConfirmDialogProps extends ConfirmOptions {
  open: boolean;
  /** The confirmed action is running. */
  busy?: boolean;
  /** Failure of the last attempt, shown inside the dialog. */
  error?: unknown;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Confirmation: named, counted and honest about side effects. Focus opens on
 * Cancel; the action turns into progress and the dialog closes when done.
 */
export function ConfirmDialog({
  open,
  busy = false,
  error,
  onConfirm,
  onCancel,
  title,
  description,
  eyebrow,
  body,
  tone = "danger",
  icon,
  confirmLabel,
  busyLabel,
  confirmVariant = "danger-solid",
  confirmIcon,
  cancelLabel = "Cancel",
  lead,
  errorTitle
}: ConfirmDialogProps): JSX.Element {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const [leadBusy, setLeadBusy] = useState(false);
  const glyph: LucideIcon = icon ?? (tone === "danger" ? Trash2 : TriangleAlert);
  const described = error !== undefined ? describeError(error, { title: errorTitle ?? "That didn't work" }) : undefined;

  useEffect(() => {
    if (!open) {
      setLeadBusy(false);
    }
  }, [open]);

  let errorNode: ReactNode = null;
  if (described) {
    errorNode = (
      <Callout tone="danger" title={described.title} role="alert">
        {described.message}
      </Callout>
    );
  }

  return (
    <Modal
      open={open}
      onClose={onCancel}
      title={title}
      description={description}
      eyebrow={eyebrow}
      icon={glyph}
      iconTone={tone}
      size="confirm"
      role="alertdialog"
      busy={busy}
      closeButton={false}
      initialFocusRef={cancelRef}
      footer={
        <>
          {lead ? (
            <Button
              variant="ghost"
              icon={lead.icon}
              className="lead"
              busy={leadBusy}
              disabled={busy}
              onClick={() => {
                setLeadBusy(true);
                void Promise.resolve()
                  .then(lead.onClick)
                  .finally(() => setLeadBusy(false));
              }}
            >
              {lead.label}
            </Button>
          ) : null}
          <Button ref={cancelRef} disabled={busy} onClick={onCancel}>
            {cancelLabel}
          </Button>
          <Button variant={confirmVariant} icon={confirmIcon} busy={busy} busyLabel={busyLabel} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      {body || errorNode ? (
        <>
          {body}
          {errorNode}
        </>
      ) : null}
    </Modal>
  );
}

/** Renders the app-wide confirmation from the controller (mounted once by App). */
export function ConfirmHost({ controller }: { controller: ConfirmController }): JSX.Element {
  const { state, accept, cancel } = controller;
  const lastOptions = useRef<ConfirmOptions | undefined>(state?.options);
  if (state) {
    lastOptions.current = state.options;
  }
  // Keep the last options while the dialog plays its exit animation.
  const options = state?.options ?? lastOptions.current;
  if (!options) {
    return <></>;
  }
  return (
    <ConfirmDialog
      {...options}
      open={Boolean(state)}
      busy={state?.pending ?? false}
      error={state?.error}
      onConfirm={() => {
        void accept();
      }}
      onCancel={() => {
        cancel();
      }}
    />
  );
}
