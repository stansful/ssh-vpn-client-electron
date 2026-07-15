import { X } from "lucide-react";
import { useEffect, useId, useRef } from "react";
import { createPortal } from "react-dom";
import { ModalFocusStack, nextModalFocusIndex } from "../../lib/modal-focus.js";

const modalFocusStack = new ModalFocusStack<symbol>();

const FOCUSABLE_SELECTOR = [
  "input:not([disabled]):not([type='hidden'])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "button:not([disabled])",
  "a[href]",
  "[contenteditable='true']",
  "[tabindex]:not([tabindex='-1'])"
].join(",");

function focusableElements(dialog: HTMLElement): HTMLElement[] {
  return Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter((element) => {
    if (element.hidden || element.getAttribute("aria-hidden") === "true") {
      return false;
    }
    const style = window.getComputedStyle(element);
    return style.display !== "none" && style.visibility !== "hidden";
  });
}

function initialFocusTarget(dialog: HTMLElement): HTMLElement {
  const focusable = focusableElements(dialog);
  return focusable.find((element) => element.hasAttribute("autofocus"))
    ?? focusable.find((element) => element.matches("input, select, textarea, [contenteditable='true']"))
    ?? focusable[0]
    ?? dialog;
}

function focusWithoutScrolling(element: HTMLElement): void {
  element.focus({ preventScroll: true });
}

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
  const dialogRef = useRef<HTMLElement>(null);
  const focusTokenRef = useRef(Symbol("modal-focus"));
  const onCloseRef = useRef(onClose);
  const titleId = useId();

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!open) {
      return undefined;
    }

    const previouslyFocused = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : undefined;
    const focusToken = focusTokenRef.current;
    modalFocusStack.activate(focusToken);
    let focusFrame = window.requestAnimationFrame(() => {
      focusFrame = 0;
      const dialog = dialogRef.current;
      if (dialog && modalFocusStack.isTopmost(focusToken)) {
        focusWithoutScrolling(initialFocusTarget(dialog));
      }
    });

    const handleKeyDown = (event: KeyboardEvent): void => {
      if (!modalFocusStack.isTopmost(focusToken)) {
        return;
      }
      const dialog = dialogRef.current;
      if (!dialog) {
        return;
      }
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab") {
        return;
      }

      const focusable = focusableElements(dialog);
      if (focusable.length === 0) {
        event.preventDefault();
        focusWithoutScrolling(dialog);
        return;
      }
      const currentIndex = document.activeElement instanceof HTMLElement
        ? focusable.indexOf(document.activeElement)
        : -1;
      const nextIndex = nextModalFocusIndex(currentIndex, focusable.length, event.shiftKey);
      event.preventDefault();
      focusWithoutScrolling(focusable[nextIndex]);
    };

    const keepFocusInside = (event: FocusEvent): void => {
      if (!modalFocusStack.isTopmost(focusToken)) {
        return;
      }
      const dialog = dialogRef.current;
      if (dialog && event.target instanceof Node && !dialog.contains(event.target)) {
        focusWithoutScrolling(initialFocusTarget(dialog));
      }
    };

    document.addEventListener("keydown", handleKeyDown, true);
    document.addEventListener("focusin", keepFocusInside, true);
    return () => {
      if (focusFrame !== 0) {
        window.cancelAnimationFrame(focusFrame);
      }
      document.removeEventListener("keydown", handleKeyDown, true);
      document.removeEventListener("focusin", keepFocusInside, true);
      const wasTopmost = modalFocusStack.deactivate(focusToken);
      if (wasTopmost && previouslyFocused?.isConnected) {
        focusWithoutScrolling(previouslyFocused);
      }
    };
  }, [open]);

  if (!open) {
    return null;
  }

  const portalRoot = document.querySelector<HTMLElement>(".app-shell") ?? document.body;

  return createPortal(
    <div
      className="modal-backdrop"
      role="presentation"
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <section
        ref={dialogRef}
        className="modal-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <header className="modal-header">
          <h2 id={titleId}>{title}</h2>
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
