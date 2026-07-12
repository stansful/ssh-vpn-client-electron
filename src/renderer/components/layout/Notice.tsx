import { X } from "lucide-react";
import { memo } from "react";

export const Notice = memo(function Notice({ message, onDismiss }: { message: string; onDismiss: () => void }): JSX.Element | null {
  if (!message) {
    return null;
  }

  return (
    <div className="notice">
      <span>{message}</span>
      <button type="button" className="icon-button" onClick={onDismiss} aria-label="Dismiss">
        <X size={16} />
      </button>
    </div>
  );
});
