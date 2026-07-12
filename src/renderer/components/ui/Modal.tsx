import { X } from "lucide-react";
import { createPortal } from "react-dom";

export function Modal({
  open,
  title,
  children,
  onClose
}: {
  open: boolean;
  title: string;
  children: React.ReactNode;
  onClose: () => void;
}): JSX.Element | null {
  if (!open) {
    return null;
  }

  const portalRoot = document.querySelector<HTMLElement>(".app-shell") ?? document.body;

  return createPortal(
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section className="modal-card" role="dialog" aria-modal="true" aria-label={title} onMouseDown={(event) => event.stopPropagation()}>
        <header className="modal-header">
          <h2>{title}</h2>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close modal">
            <X size={16} />
          </button>
        </header>
        {children}
      </section>
    </div>,
    portalRoot
  );
}
