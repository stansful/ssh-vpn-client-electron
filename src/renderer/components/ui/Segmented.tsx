import type { LucideIcon } from "lucide-react";
import { useRef, type CSSProperties, type KeyboardEvent, type ReactNode } from "react";
import { formatCount } from "../../lib/format.js";
import { cx, Icon } from "./Icon.js";

export interface SegmentedOption<T extends string> {
  value: T;
  label: ReactNode;
  icon?: LucideIcon;
  /** Mono count chip after the label. */
  count?: number;
  disabled?: boolean;
  /** Accessible name when `label` is not plain text. */
  ariaLabel?: string;
  /** Second line for `tall` segments. */
  sub?: ReactNode;
}

export interface SegmentedProps<T extends string> {
  value: T;
  options: ReadonlyArray<SegmentedOption<T>>;
  onChange: (value: T) => void;
  /** Names the radio group: "Transport", "Traffic mode", "Theme". */
  ariaLabel: string;
  /** sm: 28 px segments. */
  size?: "sm" | "md";
  /** Stretch to the container width. */
  block?: boolean;
  /** Two-line segments (icon or thumbnail above the label). */
  tall?: boolean;
  disabled?: boolean;
  className?: string;
  id?: string;
}

const NAVIGATION_KEYS = ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"];

/**
 * Segmented control as a radio group: the thumb slides in 420 ms; arrow keys,
 * Home and End move the choice (disabled options are skipped).
 */
export function Segmented<T extends string>({
  value,
  options,
  onChange,
  ariaLabel,
  size = "md",
  block = false,
  tall = false,
  disabled = false,
  className,
  id
}: SegmentedProps<T>): JSX.Element {
  const buttons = useRef<Array<HTMLButtonElement | null>>([]);
  const selectedIndex = Math.max(0, options.findIndex((option) => option.value === value));

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number): void {
    if (!NAVIGATION_KEYS.includes(event.key)) {
      return;
    }
    event.preventDefault();
    const enabled = options.map((option, optionIndex) => (option.disabled || disabled ? -1 : optionIndex)).filter((optionIndex) => optionIndex >= 0);
    if (enabled.length === 0) {
      return;
    }
    let next: number;
    if (event.key === "Home") {
      next = enabled[0];
    } else if (event.key === "End") {
      next = enabled[enabled.length - 1];
    } else {
      const forward = event.key === "ArrowRight" || event.key === "ArrowDown";
      const position = enabled.indexOf(index);
      const from = position >= 0 ? position : enabled.indexOf(selectedIndex);
      next = enabled[(from + (forward ? 1 : -1) + enabled.length) % enabled.length];
    }
    if (options[next].value !== value) {
      onChange(options[next].value);
    }
    buttons.current[next]?.focus();
  }

  const style = { "--n": options.length, "--i": selectedIndex } as CSSProperties;

  return (
    <div
      id={id}
      className={cx("seg", size === "sm" && "seg-sm", block && "seg-block", tall && "seg-tall", className)}
      role="radiogroup"
      aria-label={ariaLabel}
      aria-disabled={disabled || undefined}
      style={style}
    >
      <span className="seg-thumb" aria-hidden="true" />
      {options.map((option, index) => {
        const checked = option.value === value;
        return (
          <button
            ref={(element) => {
              buttons.current[index] = element;
            }}
            key={option.value}
            type="button"
            role="radio"
            aria-checked={checked}
            aria-label={option.ariaLabel}
            tabIndex={checked ? 0 : -1}
            disabled={disabled || option.disabled}
            onKeyDown={(event) => handleKeyDown(event, index)}
            onClick={() => {
              if (!checked) {
                onChange(option.value);
              }
            }}
          >
            {option.icon ? <Icon icon={option.icon} size="sm" /> : null}
            {option.label}
            {option.count !== undefined ? <span className="count">{formatCount(option.count)}</span> : null}
            {tall && option.sub ? <span className="hint">{option.sub}</span> : null}
          </button>
        );
      })}
    </div>
  );
}
