import { Minus, Plus, Search, X, type LucideIcon } from "lucide-react";
import { forwardRef, useRef, type InputHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { IconButton } from "./Button.js";
import { useFieldControl } from "./Field.js";
import { cx, Icon } from "./Icon.js";

function mergeDescribedBy(...ids: Array<string | undefined>): string | undefined {
  const joined = ids.filter(Boolean).join(" ");
  return joined || undefined;
}

export interface TextInputProps extends InputHTMLAttributes<HTMLInputElement> {
  /** JetBrains Mono for hosts, ports, IPs, fingerprints, domains, paths. */
  mono?: boolean;
  /** Error styling; inside a Field it follows the Field's error automatically. */
  invalid?: boolean;
  /** Leading icon inside the input (search, filters). */
  icon?: LucideIcon;
}

/** Single-line input (`.input`). Inside a Field it is labelled and described automatically. */
export const TextInput = forwardRef<HTMLInputElement, TextInputProps>(function TextInput(
  { mono, invalid, icon, className, id, disabled, type = "text", spellCheck = false, "aria-describedby": describedBy, ...rest },
  ref
) {
  const field = useFieldControl();
  const isInvalid = invalid ?? field?.invalid ?? false;
  const input = (
    <input
      ref={ref}
      id={id ?? field?.id}
      type={type}
      className={cx("input", mono && "mono", isInvalid && "is-invalid", className)}
      aria-invalid={isInvalid || undefined}
      aria-describedby={mergeDescribedBy(describedBy, field?.describedBy)}
      disabled={disabled ?? field?.disabled}
      spellCheck={spellCheck}
      {...rest}
    />
  );
  if (!icon) {
    return input;
  }
  return (
    <div className="input-wrap">
      <Icon icon={icon} size="sm" />
      {input}
    </div>
  );
});

export interface SearchInputProps extends Omit<TextInputProps, "type" | "icon" | "onChange" | "value"> {
  value: string;
  onValueChange: (value: string) => void;
  /** Accessible name of the clear button. Default "Clear search". */
  clearLabel?: string;
}

/** Search field with a magnifier and a clear button; Esc clears it. */
export const SearchInput = forwardRef<HTMLInputElement, SearchInputProps>(function SearchInput(
  { value, onValueChange, clearLabel = "Clear search", className, onKeyDown, ...rest },
  ref
) {
  const localRef = useRef<HTMLInputElement | null>(null);
  return (
    <div className="input-wrap">
      <Icon icon={Search} size="sm" />
      <TextInput
        ref={(element) => {
          localRef.current = element;
          if (typeof ref === "function") {
            ref(element);
          } else if (ref) {
            ref.current = element;
          }
        }}
        type="search"
        value={value}
        onChange={(event) => onValueChange(event.target.value)}
        onKeyDown={(event) => {
          onKeyDown?.(event);
          if (!event.defaultPrevented && event.key === "Escape" && value) {
            event.preventDefault();
            event.stopPropagation();
            onValueChange("");
          }
        }}
        className={cx(value && "has-clear", className)}
        {...rest}
      />
      {value ? (
        <IconButton
          icon={X}
          label={clearLabel}
          className="input-clear"
          onClick={() => {
            onValueChange("");
            localRef.current?.focus();
          }}
        />
      ) : null}
    </div>
  );
});

export interface TextAreaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  mono?: boolean;
  invalid?: boolean;
  /** Hide characters (`-webkit-text-security: disc`) while keeping line structure. */
  masked?: boolean;
}

/** Multi-line input (`.textarea`). */
export const TextArea = forwardRef<HTMLTextAreaElement, TextAreaProps>(function TextArea(
  { mono, invalid, masked, className, id, disabled, spellCheck = false, "aria-describedby": describedBy, ...rest },
  ref
) {
  const field = useFieldControl();
  const isInvalid = invalid ?? field?.invalid ?? false;
  return (
    <textarea
      ref={ref}
      id={id ?? field?.id}
      className={cx("textarea", mono && "mono", masked && "masked", isInvalid && "is-invalid", className)}
      aria-invalid={isInvalid || undefined}
      aria-describedby={mergeDescribedBy(describedBy, field?.describedBy)}
      disabled={disabled ?? field?.disabled}
      spellCheck={spellCheck}
      {...rest}
    />
  );
});

export interface NumberStepperProps {
  value: number;
  onChange: (value: number) => void;
  min: number;
  max: number;
  step?: number;
  /** Unit after the number, e.g. "s". */
  unit?: string;
  /** Accessible names for − and +, e.g. "30 seconds less" / "30 seconds more". */
  decrementLabel: string;
  incrementLabel: string;
  id?: string;
  disabled?: boolean;
  invalid?: boolean;
  "aria-describedby"?: string;
}

function clampToRange(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/** Mono number field with − / + buttons (`.stepper`); typing is clamped on blur. */
export function NumberStepper({
  value,
  onChange,
  min,
  max,
  step = 1,
  unit,
  decrementLabel,
  incrementLabel,
  id,
  disabled,
  invalid,
  "aria-describedby": describedBy
}: NumberStepperProps): JSX.Element {
  const field = useFieldControl();
  const isInvalid = invalid ?? field?.invalid ?? false;
  const isDisabled = disabled ?? field?.disabled ?? false;
  return (
    <div className={cx("stepper", isInvalid && "is-invalid")}>
      <IconButton icon={Minus} label={decrementLabel} disabled={isDisabled || value <= min} onClick={() => onChange(clampToRange(value - step, min, max))} />
      <input
        id={id ?? field?.id}
        type="number"
        inputMode="numeric"
        min={min}
        max={max}
        step={step}
        value={Number.isFinite(value) ? value : ""}
        disabled={isDisabled}
        aria-invalid={isInvalid || undefined}
        aria-describedby={mergeDescribedBy(describedBy, field?.describedBy)}
        onChange={(event) => {
          const next = event.target.valueAsNumber;
          onChange(Number.isFinite(next) ? next : Number.NaN);
        }}
        onBlur={() => {
          if (!Number.isFinite(value)) {
            onChange(min);
          } else if (value < min || value > max) {
            onChange(clampToRange(value, min, max));
          }
        }}
      />
      {unit ? <span className="stepper-unit">{unit}</span> : null}
      <IconButton icon={Plus} label={incrementLabel} disabled={isDisabled || value >= max} onClick={() => onChange(clampToRange(value + step, min, max))} />
    </div>
  );
}
