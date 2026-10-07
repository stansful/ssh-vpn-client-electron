import { X, type LucideIcon } from "lucide-react";
import { useEffect, useId, useLayoutEffect, useRef, useState, type FormEvent, type ReactNode, type RefObject } from "react";
import { createPortal } from "react-dom";
import { ModalFocusStack, nextModalFocusIndex } from "../../lib/modal-focus.js";
import { IconButton } from "./Button.js";
import type { Tone } from "./Badge.js";
import { IconTile } from "./Card.js";
import { cx } from "./Icon.js";

const modalFocusStack = new ModalFocusStack<symbol>();
const EXIT_MS = 220;

const FOCUSABLE_SELECTOR = [
  "input:not([disabled]):not([type='hidden'])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "button:not([disabled])",
  "a[href]",
  "[contenteditable='true']",
  "[tabindex]:not([tabindex='-1'])"
].join(",");

function focusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter((element) => {
    if (element.hidden || element.closest("[aria-hidden='true'], [inert]")) {
      return false;
    }
    const style = window.getComputedStyle(element);
    return style.display !== "none" && style.visibility !== "hidden";
  });
}

function initialFocusTarget(dialog: HTMLElement): HTMLElement {
  const focusable = focusableElements(dialog);
  const body = dialog.querySelector<HTMLElement>(".modal-body");
  const inBody = body ? focusable.filter((element) => body.contains(element)) : focusable;
  return (
    focusable.find((element) => element.hasAttribute("autofocus") || element.hasAttribute("data-autofocus")) ??
    inBody.find((element) => element.matches("input, select, textarea, [contenteditable='true']")) ??
    inBody[0] ??
    focusable[0] ??
    dialog
  );
}

function focusWithoutScrolling(element: HTMLElement): void {
  element.focus({ preventScroll: true });
}

/** Overlays mount inside the `.app` container so its container queries apply. */
export function overlayRoot(): HTMLElement {
  return document.querySelector<HTMLElement>(".app") ?? document.body;
}

export interface ModalProps {
  open: boolean;
  /** Called on Esc, a scrim click or the close button — never while `busy`. */
  onClose: () => void;
  title: ReactNode;
  /** Sentence under the title. */
  description?: ReactNode;
  /** Small caps context above the title. */
  eyebrow?: string;
  /** Icon tile at the start of the header. */
  icon?: LucideIcon;
  iconTone?: Tone;
  /** Buttons for `.modal-foot` (put a `.lead` element first for a left-aligned helper). */
  footer?: ReactNode;
  children?: ReactNode;
  /** narrow 420, default 560, confirm 500, wide 720. */
  size?: "narrow" | "default" | "confirm" | "wide";
  /** Something is saving: Esc, the scrim and the close button wait. */
  busy?: boolean;
  /** Show the × button. Default true (confirmations omit it). */
  closeButton?: boolean;
  /** Element to focus first; defaults to the first field, then the first control. */
  initialFocusRef?: RefObject<HTMLElement>;
  /** "alertdialog" for confirmations. */
  role?: "dialog" | "alertdialog";
  /** Render the panel as a form; Enter in a field submits it. */
  onSubmit?: (event: FormEvent<HTMLFormElement>) => void;
  className?: string;
  bodyClassName?: string;
  /** Accessible name when the title is not plain text. */
  ariaLabel?: string;
}

/**
 * Dialog in a portal: scrim fades in, the panel lifts in; on close both fade
 * and drop for 220 ms. Traps focus (the topmost dialog owns it), closes on Esc
 * or a scrim click unless busy, and returns focus to whatever opened it.
 */
export function Modal({
  open,
  onClose,
  title,
  description,
  eyebrow,
  icon,
  iconTone = "neutral",
  footer,
  children,
  size = "default",
  busy = false,
  closeButton = true,
  initialFocusRef,
  role = "dialog",
  onSubmit,
  className,
  bodyClassName,
  ariaLabel
}: ModalProps): JSX.Element | null {
  const [rendered, setRendered] = useState(open);
  const [closing, setClosing] = useState(false);
  const panelRef = useRef<HTMLElement | null>(null);
  const focusTokenRef = useRef(Symbol("modal-focus"));
  const onCloseRef = useRef(onClose);
  const busyRef = useRef(busy);
  const initialFocusRefRef = useRef(initialFocusRef);
  const scrimPointerDown = useRef(false);
  const titleId = useId();
  const descriptionId = useId();

  onCloseRef.current = onClose;
  busyRef.current = busy;
  initialFocusRefRef.current = initialFocusRef;

  useLayoutEffect(() => {
    if (open) {
      setRendered(true);
      setClosing(false);
      return undefined;
    }
    if (!rendered) {
      return undefined;
    }
    setClosing(true);
    const timer = window.setTimeout(() => {
      setRendered(false);
      setClosing(false);
    }, EXIT_MS);
    return () => window.clearTimeout(timer);
    // `rendered` is read only to skip the exit when the dialog never opened.
  }, [open]);

  useEffect(() => {
    if (!open) {
      return undefined;
    }
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : undefined;
    const focusToken = focusTokenRef.current;
    modalFocusStack.activate(focusToken);
    let focusFrame = window.requestAnimationFrame(() => {
      focusFrame = 0;
      const panel = panelRef.current;
      if (panel && modalFocusStack.isTopmost(focusToken)) {
        // Show the ring on the initial target (Cancel in confirmations) even after a mouse click.
        const target = initialFocusRefRef.current?.current ?? initialFocusTarget(panel);
        target.focus({ preventScroll: true, focusVisible: true } as FocusOptions);
      }
    });

    const handleKeyDown = (event: KeyboardEvent): void => {
      if (!modalFocusStack.isTopmost(focusToken)) {
        return;
      }
      const panel = panelRef.current;
      if (!panel) {
        return;
      }
      if (event.key === "Escape") {
        if (event.defaultPrevented) {
          return;
        }
        event.preventDefault();
        event.stopPropagation();
        if (!busyRef.current) {
          onCloseRef.current();
        }
        return;
      }
      if (event.key !== "Tab") {
        return;
      }
      const focusable = focusableElements(panel);
      if (focusable.length === 0) {
        event.preventDefault();
        focusWithoutScrolling(panel);
        return;
      }
      const currentIndex = document.activeElement instanceof HTMLElement ? focusable.indexOf(document.activeElement) : -1;
      const nextIndex = nextModalFocusIndex(currentIndex, focusable.length, event.shiftKey);
      event.preventDefault();
      focusWithoutScrolling(focusable[nextIndex]);
    };

    const keepFocusInside = (event: FocusEvent): void => {
      if (!modalFocusStack.isTopmost(focusToken)) {
        return;
      }
      const panel = panelRef.current;
      const target = event.target;
      // Popovers (listboxes) render outside the panel but belong to it.
      if (panel && target instanceof Node && !panel.contains(target) && !(target instanceof Element && target.closest("[data-popover]"))) {
        focusWithoutScrolling(initialFocusTarget(panel));
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    document.addEventListener("focusin", keepFocusInside, true);
    return () => {
      if (focusFrame !== 0) {
        window.cancelAnimationFrame(focusFrame);
      }
      document.removeEventListener("keydown", handleKeyDown);
      document.removeEventListener("focusin", keepFocusInside, true);
      const wasTopmost = modalFocusStack.deactivate(focusToken);
      if (wasTopmost) {
        const fallback = document.querySelector<HTMLElement>(".page-title") ?? document.querySelector<HTMLElement>(".main");
        const target = previouslyFocused?.isConnected ? previouslyFocused : fallback;
        if (target) {
          focusWithoutScrolling(target);
        }
      }
    };
  }, [open]);

  if (!rendered) {
    return null;
  }

  const sizeClass = size === "wide" ? "modal-wide" : size === "confirm" ? "modal-confirm" : size === "narrow" ? "modal-narrow" : undefined;
  const header = (
    <div className="modal-head">
      {icon ? <IconTile icon={icon} tone={iconTone} /> : null}
      <div className="modal-head-main">
        {eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}
        <h2 className="modal-title" id={titleId}>
          {title}
        </h2>
        {description ? (
          <p className="modal-desc" id={descriptionId}>
            {description}
          </p>
        ) : null}
      </div>
      {closeButton ? <IconButton icon={X} label="Close" tooltip="Close (Esc)" disabled={busy} onClick={() => onCloseRef.current()} /> : null}
    </div>
  );
  const content = (
    <>
      {header}
      {children !== undefined && children !== null ? <div className={cx("modal-body", bodyClassName)}>{children}</div> : null}
      {footer ? <div className="modal-foot">{footer}</div> : null}
    </>
  );
  const panelProps = {
    className: cx("modal", sizeClass, className),
    role,
    "aria-modal": true,
    "aria-labelledby": ariaLabel ? undefined : titleId,
    "aria-label": ariaLabel,
    "aria-describedby": description ? descriptionId : undefined,
    "aria-busy": busy || undefined,
    tabIndex: -1
  } as const;

  return createPortal(
    <div
      className="overlay"
      data-closing={closing ? "true" : undefined}
      role="presentation"
      onMouseDown={(event) => {
        scrimPointerDown.current = event.target === event.currentTarget;
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget && scrimPointerDown.current && !busyRef.current && !closing) {
          onCloseRef.current();
        }
        scrimPointerDown.current = false;
      }}
    >
      {onSubmit ? (
        <form
          ref={(element) => {
            panelRef.current = element;
          }}
          {...panelProps}
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            if (!busyRef.current) {
              onSubmit(event);
            }
          }}
        >
          {content}
        </form>
      ) : (
        <section
          ref={(element) => {
            panelRef.current = element;
          }}
          {...panelProps}
        >
          {content}
        </section>
      )}
    </div>,
    overlayRoot()
  );
}
