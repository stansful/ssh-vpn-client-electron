import type { LucideIcon } from "lucide-react";
import { Fragment, useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type KeyboardEvent, type RefObject } from "react";
import { createPortal } from "react-dom";
import { nextModalFocusIndex } from "../../lib/modal-focus.js";
import { cx, Icon } from "./Icon.js";
import { MENU_GAP, VIEWPORT_MARGIN } from "./Listbox.js";
import { overlayRoot } from "./Modal.js";

export interface ActionMenuItem {
  id: string;
  label: string;
  icon: LucideIcon;
  tone?: "danger";
  /** Stays focusable (aria-disabled) so its note is still read out; picking it does nothing. */
  disabled?: boolean;
  /** Second line, e.g. why it is disabled (.lb-opt-note style); also aria-describedby. */
  note?: string;
  /** Visual key hint (aria-hidden kbd) + aria-keyshortcuts value. */
  shortcut?: { label: string; aria: string };
  separatorBefore?: boolean;
}

export interface ActionMenuProps {
  /** Id of the menu surface, for the opener's aria-controls. */
  id?: string;
  /** Names the menu: "Actions for Frankfurt-01". */
  label: string;
  items: ActionMenuItem[];
  open: boolean;
  /** Anchor (e.g. the ⋯ button). Used for placement unless point is set, and as the default focus-return target. */
  anchorRef: RefObject<HTMLElement | null>;
  /** Open at a viewport point (right-click) instead of under the anchor. */
  point?: { x: number; y: number } | null;
  /** Where focus goes on Esc/Tab/select; defaults to anchorRef. */
  returnFocusRef?: RefObject<HTMLElement | null>;
  /** Item focused on open: the first (default) or last enabled one. */
  initialFocus?: "first" | "last";
  /** Runs after the menu closed and focus went back, so the action may move focus itself. */
  onSelect: (id: string) => void;
  onClose: () => void;
}

export interface ActionMenuPlacement {
  left: number;
  top: number;
  side: "bottom" | "top";
}

/** Where the menu opens from: under an anchor's box or at a pointer. */
export type ActionMenuOrigin = { anchor: Pick<DOMRect, "top" | "right" | "bottom"> } | { point: { x: number; y: number } };

interface Size {
  width: number;
  height: number;
}

type MenuPosition = ActionMenuPlacement & { align: "start" | "end" };

/** var(--t-fast): how long the menu-out animation plays before unmounting. */
const EXIT_MS = 140;

/**
 * Under the anchor with right edges aligned, or with the top-left corner at
 * the pointer; flips above when it doesn't fit below and there is more room
 * above, and stays 12 px inside the viewport.
 */
export function placeActionMenu(menu: Size, viewport: Size, origin: ActionMenuOrigin): ActionMenuPlacement {
  // `down` is the top edge when opening down, `up` the bottom edge when opening up.
  const { left, down, up } =
    "anchor" in origin
      ? { left: origin.anchor.right - menu.width, down: origin.anchor.bottom + MENU_GAP, up: origin.anchor.top - MENU_GAP }
      : { left: origin.point.x, down: origin.point.y, up: origin.point.y };
  const roomBelow = viewport.height - VIEWPORT_MARGIN - down;
  const roomAbove = up - VIEWPORT_MARGIN;
  const side = menu.height <= roomBelow || roomBelow >= roomAbove ? "bottom" : "top";
  return {
    left: clamp(left, VIEWPORT_MARGIN, viewport.width - VIEWPORT_MARGIN - menu.width),
    top: clamp(side === "bottom" ? down : up - menu.height, VIEWPORT_MARGIN, viewport.height - VIEWPORT_MARGIN - menu.height),
    side
  };
}

/**
 * First-letter type-ahead: the next label after `from` that starts with `key`,
 * wrapping around, so pressing the same letter cycles through the matches.
 * -1 when nothing matches.
 */
export function typeaheadIndex(labels: readonly string[], from: number, key: string): number {
  const needle = key.toLocaleLowerCase();
  for (let step = 1; step <= labels.length; step += 1) {
    const index = (Math.max(from, -1) + step) % labels.length;
    if (labels[index].trim().toLocaleLowerCase().startsWith(needle)) {
      return index;
    }
  }
  return -1;
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(value, max));
}

/**
 * Action menu (`.menu` popover, role="menu") under a ⋯ button or at the
 * pointer. Keyboard: ↑/↓ wrap, Home/End, a first letter jumps to the next
 * match, Enter/Space pick, Esc and Tab close and return focus. Closes on
 * scroll, an outside pointer or window blur; on resize it follows its anchor,
 * or closes when opened at a pointer. Fades out for 140 ms.
 */
export function ActionMenu({
  id,
  label,
  items,
  open,
  anchorRef,
  point = null,
  returnFocusRef,
  initialFocus = "first",
  onSelect,
  onClose
}: ActionMenuProps): JSX.Element | null {
  const baseId = useId();
  const menuRef = useRef<HTMLDivElement>(null);
  const itemRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const onCloseRef = useRef(onClose);
  const [rendered, setRendered] = useState(open);
  const [position, setPosition] = useState<MenuPosition>();
  const focusTarget = returnFocusRef ?? anchorRef;
  const pointX = point?.x;
  const pointY = point?.y;
  const atPoint = pointX !== undefined && pointY !== undefined;

  onCloseRef.current = onClose;

  // Stay mounted (data-closing) while the exit animation plays.
  useLayoutEffect(() => {
    if (open) {
      setRendered(true);
      return undefined;
    }
    if (!rendered) {
      return undefined;
    }
    const timer = window.setTimeout(() => setRendered(false), EXIT_MS);
    return () => window.clearTimeout(timer);
    // `rendered` is read only to skip the exit when the menu never opened.
  }, [open]);

  const place = useCallback((): void => {
    const menu = menuRef.current;
    const anchor = anchorRef.current;
    const origin: ActionMenuOrigin | undefined =
      pointX !== undefined && pointY !== undefined ? { point: { x: pointX, y: pointY } } : anchor ? { anchor: anchor.getBoundingClientRect() } : undefined;
    if (!menu || !origin) {
      return;
    }
    // offset* sizes ignore the entrance animation's transform.
    const next: MenuPosition = {
      ...placeActionMenu({ width: menu.offsetWidth, height: menu.offsetHeight }, { width: window.innerWidth, height: window.innerHeight }, origin),
      align: "point" in origin ? "start" : "end"
    };
    setPosition((current) =>
      current && current.left === next.left && current.top === next.top && current.side === next.side && current.align === next.align ? current : next
    );
  }, [anchorRef, pointX, pointY]);

  // Placed before paint on every render while open: the size follows the items (a note adds a line).
  useLayoutEffect(() => {
    if (open) {
      place();
    }
  });

  // Close on scroll, an outside pointer or window blur; on resize follow the anchor (or close, when opened at a pointer).
  useLayoutEffect(() => {
    if (!open) {
      return undefined;
    }
    // Focus stays where it is, unless it would vanish with the menu.
    const dismiss = (): void => {
      if (menuRef.current?.contains(document.activeElement)) {
        focusTarget.current?.focus({ preventScroll: true });
      }
      onCloseRef.current();
    };
    const handlePointerDown = (event: PointerEvent): void => {
      const target = event.target as Node | null;
      // The anchor toggles the menu itself.
      if (target && !menuRef.current?.contains(target) && !anchorRef.current?.contains(target)) {
        onCloseRef.current();
      }
    };
    const handleViewportChange = (event: Event): void => {
      if (event.target instanceof Node && menuRef.current?.contains(event.target)) {
        return;
      }
      // Scrolling closes it: kept inside the window, it would cover other cards while acting on one out of view.
      if (atPoint || event.type === "scroll") {
        dismiss();
      } else {
        place();
      }
    };
    window.addEventListener("resize", handleViewportChange);
    window.addEventListener("scroll", handleViewportChange, true);
    window.addEventListener("blur", dismiss);
    document.addEventListener("pointerdown", handlePointerDown, true);
    return () => {
      window.removeEventListener("resize", handleViewportChange);
      window.removeEventListener("scroll", handleViewportChange, true);
      window.removeEventListener("blur", dismiss);
      document.removeEventListener("pointerdown", handlePointerDown, true);
    };
  }, [anchorRef, atPoint, focusTarget, open, place]);

  // Focus the first (or last) enabled item once the menu is in the DOM.
  useEffect(() => {
    if (!open) {
      return undefined;
    }
    const frame = window.requestAnimationFrame(() => {
      const enabled = items.flatMap((item, index) => (item.disabled ? [] : [index]));
      const index = (initialFocus === "last" ? enabled[enabled.length - 1] : enabled[0]) ?? 0;
      itemRefs.current[index]?.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
    // Items and initialFocus are read as they were when the menu opened.
  }, [open]);

  if (!open && !rendered) {
    return null;
  }

  const focusItem = (index: number): void => {
    itemRefs.current[index]?.focus({ preventScroll: true });
  };

  const closeAndReturnFocus = (): void => {
    onClose();
    focusTarget.current?.focus({ preventScroll: true });
  };

  const activate = (item: ActionMenuItem): void => {
    if (!open || item.disabled) {
      return;
    }
    // Focus is back on the opener before the action runs, so the action can move it
    // (into a rename field) or a dialog it opens knows where to return it.
    closeAndReturnFocus();
    onSelect(item.id);
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>): void => {
    // Portal events bubble through the consumer's React tree; keys pressed here belong to the menu.
    event.stopPropagation();
    if (!open) {
      return;
    }
    const current = itemRefs.current.findIndex((element) => element !== null && element === document.activeElement);
    switch (event.key) {
      case "ArrowDown":
      case "ArrowUp":
        event.preventDefault();
        focusItem(nextModalFocusIndex(current, items.length, event.key === "ArrowUp"));
        break;
      case "Home":
        event.preventDefault();
        focusItem(0);
        break;
      case "End":
        event.preventDefault();
        focusItem(items.length - 1);
        break;
      case "Enter":
      case " ":
        event.preventDefault();
        if (items[current]) {
          activate(items[current]);
        }
        break;
      case "Escape":
      case "Tab":
        event.preventDefault();
        closeAndReturnFocus();
        break;
      default:
        if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
          const next = typeaheadIndex(items.map((item) => item.label), current, event.key);
          if (next >= 0) {
            event.preventDefault();
            focusItem(next);
          }
        }
        break;
    }
  };

  return createPortal(
    <div
      ref={menuRef}
      id={id}
      className="menu"
      role="menu"
      aria-label={label}
      data-popover=""
      data-side={position?.side ?? "bottom"}
      data-align={position?.align ?? (atPoint ? "start" : "end")}
      data-closing={open ? undefined : "true"}
      style={position ? { left: position.left, top: position.top } : { visibility: "hidden" }}
      onKeyDown={handleKeyDown}
      onContextMenu={(event) => {
        // A right-click inside the menu must not open another one at the pointer.
        event.preventDefault();
        event.stopPropagation();
      }}
    >
      {items.map((item, index) => {
        const noteId = item.note ? `${baseId}-note-${index}` : undefined;
        return (
          <Fragment key={item.id}>
            {item.separatorBefore && index > 0 ? <div className="menu-sep" role="separator" /> : null}
            <button
              ref={(element) => {
                itemRefs.current[index] = element;
              }}
              type="button"
              role="menuitem"
              tabIndex={-1}
              className={cx("menu-item", item.tone === "danger" && "is-danger")}
              aria-disabled={item.disabled || undefined}
              aria-describedby={noteId}
              aria-keyshortcuts={item.shortcut?.aria}
              onMouseEnter={() => focusItem(index)}
              onClick={() => activate(item)}
            >
              <Icon icon={item.icon} size="sm" />
              <span className="menu-item-main">
                <span className="menu-item-label">{item.label}</span>
                {item.note ? (
                  <span className="lb-opt-note" id={noteId}>
                    {item.note}
                  </span>
                ) : null}
              </span>
              {item.shortcut ? (
                <span className="kbd menu-item-end" aria-hidden="true">
                  {item.shortcut.label}
                </span>
              ) : null}
            </button>
          </Fragment>
        );
      })}
    </div>,
    overlayRoot()
  );
}
