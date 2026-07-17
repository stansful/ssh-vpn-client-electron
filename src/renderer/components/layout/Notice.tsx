import { CircleAlert, X } from "lucide-react";
import { memo } from "react";

export const Notice = memo(function Notice({ message, onDismiss }: { message: string; onDismiss: () => void }): JSX.Element | null {
  if (!message) {
    return null;
  }

  return (
    <div className="notice">
      <CircleAlert className="notice-icon" size={17} aria-hidden="true" />
      <span className="notice-copy" role="status" aria-live="polite">{message}</span>
      <button type="button" className="icon-button" onClick={onDismiss} aria-label="Dismiss notification">
        <X size={16} />
      </button>
    </div>
  );
});
