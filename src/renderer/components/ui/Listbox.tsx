import { Check, ChevronDown, ChevronsUpDown, Lock, type LucideIcon } from "lucide-react";
import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type ReactNode
} from "react";
import { createPortal } from "react-dom";
import { useFieldControl } from "./Field.js";
import { Icon } from "./Icon.js";
import { overlayRoot } from "./Modal.js";

export interface ListboxOption<T extends string> {
  value: T;
  /** Option title (also what search matches). */
  label: string;
  /** Mono second line: address, key type · Key ID. */
  sub?: string;
  /** Content of the leading square: initials ("FR") or an icon element. */
  lead?: ReactNode;
  /** Badge after the title (Unsupported, Pinned…). */
  badge?: ReactNode;
  disabled?: boolean;
  /** Why it can't be picked; shown under the title and read out. */
  disabledReason?: string;
  /** Options with the same group are listed under that label. */
  group?: string;
  /** Extra words for search (protocol, host…). */
  keywords?: string;
}

export interface SelectProps<T extends string> {
  value: T | undefined;
  options: ReadonlyArray<ListboxOption<T>>;
  onChange: (value: T) => void;
  /** Names the listbox: "Saved keys", "SSH servers". */
  ariaLabel: string;
  /** Accessible name of the trigger when it has no label element, e.g. "Choose SSH server, current: Frankfurt-01". */
  triggerAriaLabel?: string;
  /** Trigger text when nothing is selected. */
  placeholder?: string;
  /** Search box at the top of the menu. Default: on when there are more than 7 options. */
  searchable?: boolean;
  searchPlaceholder?: string;
  /** Shown when there are no options at all. */
  emptyText?: string;
  /** Shown when search matches nothing. */
  noMatchesText?: (query: string) => string;
  /** Extra actions under the list ("Add a new key"); receive a function that closes the menu. */
  footer?: (close: () => void) => ReactNode;
  disabled?: boolean;
  /** Locked: shows a lock glyph instead of the chevrons and does not open. */
  locked?: boolean;
  /** Trigger id; inside a Field it comes from the Field. */
  id?: string;
  /** "select-btn" (default, forms) or "picker" (Connect). */
  triggerClassName?: string;
  /** Custom trigger content; receives the selected option. */
  renderTrigger?: (selected: ListboxOption<T> | undefined, open: boolean) => ReactNode;
  /** Max menu height in px. Default 360. */
  maxHeight?: number;
  /** Opened/closed callback (e.g. to hide hints). */
  onOpenChange?: (open: boolean) => void;
  "aria-describedby"?: string;
}

interface MenuPosition {
  left: number;
  width: number;
  top?: number;
  bottom?: number;
  maxHeight: number;
  side: "bottom" | "top";
}

const MENU_GAP = 6;
const VIEWPORT_MARGIN = 12;
/**
 * Options rendered per step. A library can hold thousands of Xray profiles;
 * rendering them all would stall the menu on open, so the list grows as it is
 * scrolled or walked with the keyboard (search still covers every option).
 */
const RENDER_STEP = 150;

function computePosition(trigger: HTMLElement, preferredMax: number): MenuPosition {
  const rect = trigger.getBoundingClientRect();
  const width = Math.min(Math.max(rect.width, 240), window.innerWidth - VIEWPORT_MARGIN * 2);
  const left = Math.min(Math.max(VIEWPORT_MARGIN, rect.left), window.innerWidth - width - VIEWPORT_MARGIN);
  const below = window.innerHeight - rect.bottom - MENU_GAP - VIEWPORT_MARGIN;
  const above = rect.top - MENU_GAP - VIEWPORT_MARGIN;
  if (below >= Math.min(preferredMax, 240) || below >= above) {
    return { left, width, top: rect.bottom + MENU_GAP, maxHeight: Math.max(120, Math.min(preferredMax, below)), side: "bottom" };
  }
  return { left, width, bottom: window.innerHeight - rect.top + MENU_GAP, maxHeight: Math.max(120, Math.min(preferredMax, above)), side: "top" };
}

function matches<T extends string>(option: ListboxOption<T>, query: string): boolean {
  if (!query) {
    return true;
  }
  const haystack = `${option.label} ${option.sub ?? ""} ${option.keywords ?? ""} ${option.group ?? ""}`.toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/u)
    .filter(Boolean)
    .every((word) => haystack.includes(word));
}

/**
 * Button + popover listbox (`.select-btn` or `.picker` trigger, `.menu`
 * popover with optional search). Keyboard: Enter/Space/↓ open; ↑/↓, Home,
 * End move; Enter picks; Esc closes and returns focus to the trigger.
 */
export function Select<T extends string>({
  value,
  options,
  onChange,
  ariaLabel,
  triggerAriaLabel,
  placeholder = "Choose…",
  searchable,
  searchPlaceholder = "Search",
  emptyText = "Nothing to choose from yet.",
  noMatchesText = (query) => `Nothing matches “${query}”.`,
  footer,
  disabled,
  locked = false,
  id,
  triggerClassName = "select-btn",
  renderTrigger,
  maxHeight = 360,
  onOpenChange,
  "aria-describedby": describedBy
}: SelectProps<T>): JSX.Element {
  const field = useFieldControl();
  const baseId = useId();
  const listId = `${baseId}-listbox`;
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeValue, setActiveValue] = useState<T | undefined>(undefined);
  const [position, setPosition] = useState<MenuPosition>();
  const [renderLimit, setRenderLimit] = useState(RENDER_STEP);
  const isSearchable = searchable ?? options.length > 7;
  const isDisabled = Boolean(disabled ?? field?.disabled) || locked;
  const selected = options.find((option) => option.value === value);

  const visible = useMemo(() => options.filter((option) => matches(option, query.trim())), [options, query]);
  const optionId = useCallback((optionValue: string) => `${baseId}-opt-${optionValue.replace(/[^a-zA-Z0-9_-]/gu, "_")}`, [baseId]);

  const setOpenState = useCallback(
    (next: boolean): void => {
      setOpen(next);
      onOpenChange?.(next);
    },
    [onOpenChange]
  );

  const close = useCallback(
    (returnFocus = true): void => {
      setOpenState(false);
      setQuery("");
      if (returnFocus) {
        window.requestAnimationFrame(() => triggerRef.current?.focus({ preventScroll: true }));
      }
    },
    [setOpenState]
  );

  const openMenu = useCallback((): void => {
    if (isDisabled) {
      return;
    }
    const trigger = triggerRef.current;
    if (trigger) {
      setPosition(computePosition(trigger, maxHeight));
    }
    const initial = value ?? options.find((option) => !option.disabled)?.value;
    const initialIndex = initial === undefined ? -1 : options.findIndex((option) => option.value === initial);
    setRenderLimit(Math.max(RENDER_STEP, initialIndex + RENDER_STEP));
    setActiveValue(initial);
    setOpenState(true);
  }, [isDisabled, maxHeight, options, setOpenState, value]);

  // Focus the search box (or the list) once the menu is in the DOM.
  useEffect(() => {
    if (!open) {
      return undefined;
    }
    const frame = window.requestAnimationFrame(() => {
      (isSearchable ? searchRef.current : listRef.current)?.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [isSearchable, open]);

  // Follow the trigger while scrolling/resizing; close on outside pointer.
  useLayoutEffect(() => {
    if (!open) {
      return undefined;
    }
    const reposition = (): void => {
      if (triggerRef.current) {
        setPosition(computePosition(triggerRef.current, maxHeight));
      }
    };
    const handlePointerDown = (event: PointerEvent): void => {
      const target = event.target as Node | null;
      if (target && !menuRef.current?.contains(target) && !triggerRef.current?.contains(target)) {
        close(false);
      }
    };
    window.addEventListener("resize", reposition);
    window.addEventListener("scroll", reposition, true);
    document.addEventListener("pointerdown", handlePointerDown, true);
    return () => {
      window.removeEventListener("resize", reposition);
      window.removeEventListener("scroll", reposition, true);
      document.removeEventListener("pointerdown", handlePointerDown, true);
    };
  }, [close, maxHeight, open]);

  // A new search starts from the top of a fresh window.
  useEffect(() => {
    setRenderLimit(RENDER_STEP);
  }, [query]);

  // Grow the window so the active option is rendered.
  useEffect(() => {
    if (!open || activeValue === undefined) {
      return;
    }
    const index = visible.findIndex((option) => option.value === activeValue);
    if (index >= renderLimit) {
      setRenderLimit(index + RENDER_STEP);
    }
  }, [activeValue, open, renderLimit, visible]);

  // Keep the active option visible.
  useEffect(() => {
    if (!open || activeValue === undefined) {
      return;
    }
    document.getElementById(optionId(activeValue))?.scrollIntoView({ block: "nearest" });
  }, [activeValue, open, optionId]);

  // Keep the active option inside the filtered list.
  useEffect(() => {
    if (open && activeValue !== undefined && !visible.some((option) => option.value === activeValue)) {
      setActiveValue(visible.find((option) => !option.disabled)?.value ?? visible[0]?.value);
    }
  }, [activeValue, open, visible]);

  const pick = (option: ListboxOption<T>): void => {
    if (option.disabled) {
      return;
    }
    if (option.value !== value) {
      onChange(option.value);
    }
    close(true);
  };

  const moveActive = (delta: number | "first" | "last"): void => {
    if (visible.length === 0) {
      return;
    }
    const index = visible.findIndex((option) => option.value === activeValue);
    let next: number;
    if (delta === "first") {
      next = 0;
    } else if (delta === "last") {
      next = visible.length - 1;
    } else {
      next = index < 0 ? (delta > 0 ? 0 : visible.length - 1) : Math.min(visible.length - 1, Math.max(0, index + delta));
    }
    setActiveValue(visible[next].value);
  };

  const handleMenuKeyDown = (event: KeyboardEvent<HTMLElement>): void => {
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault();
        moveActive(1);
        break;
      case "ArrowUp":
        event.preventDefault();
        moveActive(-1);
        break;
      case "Home":
        if (!isSearchable) {
          event.preventDefault();
          moveActive("first");
        }
        break;
      case "End":
        if (!isSearchable) {
          event.preventDefault();
          moveActive("last");
        }
        break;
      case "PageDown":
        event.preventDefault();
        moveActive(8);
        break;
      case "PageUp":
        event.preventDefault();
        moveActive(-8);
        break;
      case "Enter": {
        event.preventDefault();
        const option = visible.find((candidate) => candidate.value === activeValue);
        if (option) {
          pick(option);
        }
        break;
      }
      case " ":
        if (!isSearchable) {
          event.preventDefault();
          const option = visible.find((candidate) => candidate.value === activeValue);
          if (option) {
            pick(option);
          }
        }
        break;
      case "Escape":
        event.preventDefault();
        event.stopPropagation();
        close(true);
        break;
      case "Tab":
        event.preventDefault();
        close(true);
        break;
      default:
        break;
    }
  };

  const handleTriggerKeyDown = (event: KeyboardEvent<HTMLButtonElement>): void => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      openMenu();
    }
  };

  let lastGroup: string | undefined;
  const items: ReactNode[] = [];
  const rendered = visible.length > renderLimit ? visible.slice(0, renderLimit) : visible;
  for (const option of rendered) {
    if (option.group && option.group !== lastGroup) {
      lastGroup = option.group;
      items.push(
        <div key={`group-${option.group}`} className="menu-group" role="presentation">
          {option.group}
        </div>
      );
    }
    const isSelected = option.value === value;
    const isActive = option.value === activeValue;
    items.push(
      <div
        key={option.value}
        id={optionId(option.value)}
        role="option"
        aria-selected={isSelected}
        aria-disabled={option.disabled || undefined}
        aria-description={option.disabledReason}
        className="lb-opt"
        data-active={isActive ? "true" : undefined}
        onMouseEnter={() => setActiveValue(option.value)}
        onMouseDown={(event) => event.preventDefault()}
        onClick={() => pick(option)}
      >
        {option.lead !== undefined ? <span className="lb-opt-lead">{option.lead}</span> : null}
        <span className="lb-opt-main">
          <span className="lb-opt-title">
            <span>{option.label}</span>
            {option.badge}
          </span>
          {option.sub ? <span className="lb-opt-sub">{option.sub}</span> : null}
          {option.disabled && option.disabledReason ? <span className="lb-opt-note">{option.disabledReason}</span> : null}
        </span>
        <Icon icon={Check} size="sm" className="lb-opt-check" />
      </div>
    );
  }

  const menuStyle: CSSProperties | undefined = position
    ? { left: position.left, width: position.width, top: position.top, bottom: position.bottom, maxHeight: position.maxHeight }
    : undefined;
  const activeId = activeValue !== undefined && visible.some((option) => option.value === activeValue) ? optionId(activeValue) : undefined;

  // Form selects use a chevron that flips while open; the Connect picker uses up/down chevrons.
  const pickerTrigger = triggerClassName.split(/\s+/u).includes("picker");
  const trailing: LucideIcon = locked ? Lock : pickerTrigger ? ChevronsUpDown : ChevronDown;
  const handleListScroll = (): void => {
    const list = listRef.current;
    if (list && rendered.length < visible.length && list.scrollTop + list.clientHeight >= list.scrollHeight - 240) {
      setRenderLimit((current) => current + RENDER_STEP);
    }
  };

  return (
    <>
      <button
        ref={triggerRef}
        id={id ?? field?.id}
        type="button"
        className={triggerClassName}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-label={triggerAriaLabel}
        aria-describedby={[describedBy, field?.describedBy].filter(Boolean).join(" ") || undefined}
        aria-invalid={field?.invalid || undefined}
        data-open={open ? "true" : undefined}
        disabled={isDisabled}
        onClick={() => (open ? close(true) : openMenu())}
        onKeyDown={handleTriggerKeyDown}
      >
        {renderTrigger ? (
          renderTrigger(selected, open)
        ) : (
          <span className="select-btn-main">
            {selected ? <span className="truncate">{selected.label}</span> : <span className="select-btn-placeholder">{placeholder}</span>}
          </span>
        )}
        <Icon icon={trailing} size="sm" className={locked || pickerTrigger ? "faint" : "faint chev"} />
      </button>
      {open && position
        ? createPortal(
            <div ref={menuRef} className="menu" data-popover="" data-side={position.side} style={menuStyle} onKeyDown={handleMenuKeyDown}>
              {isSearchable ? (
                <div className="menu-search">
                  <input
                    ref={searchRef}
                    className="input"
                    type="search"
                    role="combobox"
                    aria-expanded="true"
                    aria-controls={listId}
                    aria-activedescendant={activeId}
                    aria-autocomplete="list"
                    aria-label={`Search ${ariaLabel.toLowerCase()}`}
                    placeholder={searchPlaceholder}
                    value={query}
                    spellCheck={false}
                    onChange={(event) => setQuery(event.target.value)}
                  />
                </div>
              ) : null}
              <div
                ref={listRef}
                id={listId}
                className="menu-list"
                role="listbox"
                aria-label={ariaLabel}
                aria-activedescendant={isSearchable ? undefined : activeId}
                tabIndex={isSearchable ? -1 : 0}
                onScroll={handleListScroll}
              >
                {items.length > 0 ? items : <div className="menu-empty">{options.length === 0 ? emptyText : noMatchesText(query.trim())}</div>}
              </div>
              {footer ? <div className="menu-foot">{footer(() => close(true))}</div> : null}
            </div>,
            overlayRoot()
          )
        : null}
    </>
  );
}

export interface ListboxActionProps {
  icon?: LucideIcon;
  children: ReactNode;
  onClick: () => void;
}

/** Accent action row for a Select footer ("Add a new key"). */
export function ListboxAction({ icon, children, onClick }: ListboxActionProps): JSX.Element {
  return (
    <button type="button" className="lb-opt lb-opt-action" onClick={onClick}>
      {icon ? <Icon icon={icon} size="sm" /> : null}
      {children}
    </button>
  );
}
