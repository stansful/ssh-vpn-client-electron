import type { ConfirmationViewState } from "../../lib/confirmation-controller.js";
import { Modal } from "./Modal.js";

export function ConfirmationModal({
  state,
  onCancel,
  onConfirm
}: {
  state: ConfirmationViewState | undefined;
  onCancel: () => boolean;
  onConfirm: () => Promise<boolean>;
}): JSX.Element {
  const pending = state?.pending ?? false;
  return (
    <Modal open={Boolean(state)} title={state?.title ?? "Confirm action"} closeDisabled={pending} onClose={() => {
      if (!pending) {
        onCancel();
      }
    }}>
      <div className="modal-form" aria-busy={pending}>
        <p>{state?.message}</p>
        <div className="modal-actions">
          <button type="button" className="ghost-button" disabled={pending} autoFocus onClick={onCancel}>Cancel</button>
          <button
            type="button"
            className="danger-button"
            disabled={pending}
            onClick={() => void onConfirm().catch(() => undefined)}
          >
            {pending ? state?.pendingLabel : state?.confirmLabel}
          </button>
        </div>
      </div>
    </Modal>
  );
}
