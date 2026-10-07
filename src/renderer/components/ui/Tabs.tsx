import type { LucideIcon } from "lucide-react";
import { useLayoutEffect, useRef, useState, type CSSProperties, type KeyboardEvent, type ReactNode } from "react";
import { formatCount } from "../../lib/format.js";
import { cx, Icon } from "./Icon.js";

export interface TabOption<T extends string> {
  value: T;
  label: ReactNode;
  icon?: LucideIcon;
  /** Mono count chip after the label. */
  count?: number;
  disabled?: boolean;
}

export interface TabsProps<T extends string> {
  /** Base id; tabs get `${id}-tab-${value}`, the panel `${id}-panel`. */
  id: string;
  value: T;
  options: ReadonlyArray<TabOption<T>>;
  onChange: (value: T) => void;
  /** Names the tab list, e.g. "Rule type". */
  ariaLabel: string;
  className?: string;
}

export function tabId(id: string, value: string): string {
  return `${id}-tab-${value}`;
}

export function tabPanelId(id: string): string {
  return `${id}-panel`;
}

/**
 * Underline tabs. The ink slides to the selected tab in 240 ms; arrow keys,
 * Home and End move between tabs (automatic activation).
 */
export function Tabs<T extends string>({ id, value, options, onChange, ariaLabel, className }: TabsProps<T>): JSX.Element {
  const listRef = useRef<HTMLDivElement>(null);
  const buttons = useRef<Array<HTMLButtonElement | null>>([]);
  const [ink, setInk] = useState<{ x: number; width: number } | undefined>();
  const selectedIndex = options.findIndex((option) => option.value === value);

  useLayoutEffect(() => {
    const measure = (): void => {
      const button = buttons.current[selectedIndex];
      if (!button) {
        setInk(undefined);
        return;
      }
      setInk({ x: button.offsetLeft, width: button.offsetWidth });
    };
    measure();
    const list = listRef.current;
    if (!list || typeof ResizeObserver === "undefined") {
      return undefined;
    }
    const observer = new ResizeObserver(measure);
    observer.observe(list);
    return () => observer.disconnect();
  }, [selectedIndex, options]);

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number): void {
    const keys = ["ArrowLeft", "ArrowRight", "Home", "End"];
    if (!keys.includes(event.key)) {
      return;
    }
    event.preventDefault();
    const enabled = options.map((option, optionIndex) => (option.disabled ? -1 : optionIndex)).filter((optionIndex) => optionIndex >= 0);
    if (enabled.length === 0) {
      return;
    }
    const position = Math.max(0, enabled.indexOf(index));
    const next =
      event.key === "Home"
        ? enabled[0]
        : event.key === "End"
          ? enabled[enabled.length - 1]
          : enabled[(position + (event.key === "ArrowRight" ? 1 : -1) + enabled.length) % enabled.length];
    onChange(options[next].value);
    buttons.current[next]?.focus();
  }

  const inkStyle = ink ? ({ "--ink-x": `${ink.x}px`, "--ink-w": `${ink.width}px` } as CSSProperties) : undefined;

  return (
    <div ref={listRef} className={cx("tabs", className)} role="tablist" aria-label={ariaLabel} data-ink={ink ? "true" : undefined}>
      {options.map((option, index) => {
        const selected = option.value === value;
        return (
          <button
            ref={(element) => {
              buttons.current[index] = element;
            }}
            key={option.value}
            id={tabId(id, option.value)}
            type="button"
            role="tab"
            aria-selected={selected}
            aria-controls={tabPanelId(id)}
            tabIndex={selected ? 0 : -1}
            disabled={option.disabled}
            onKeyDown={(event) => handleKeyDown(event, index)}
            onClick={() => {
              if (!selected) {
                onChange(option.value);
              }
            }}
          >
            {option.icon ? <Icon icon={option.icon} size="sm" /> : null}
            {option.label}
            {option.count !== undefined ? <span className="count">{formatCount(option.count)}</span> : null}
          </button>
        );
      })}
      {ink ? <span className="tabs-ink" style={inkStyle} aria-hidden="true" /> : null}
    </div>
  );
}

export interface TabPanelProps {
  /** Same base id as the Tabs. */
  id: string;
  /** Current tab value; the panel swaps in with a short rise when it changes. */
  value: string;
  children: ReactNode;
  className?: string;
}

/** The panel for the selected tab (`role="tabpanel"`, labelled by its tab). */
export function TabPanel({ id, value, children, className }: TabPanelProps): JSX.Element {
  return (
    <div
      key={value}
      id={tabPanelId(id)}
      role="tabpanel"
      aria-labelledby={tabId(id, value)}
      className={cx("tab-panel anim-swap", className)}
      tabIndex={0}
    >
      {children}
    </div>
  );
}
