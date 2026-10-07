import { forwardRef, useId, type ButtonHTMLAttributes, type ReactNode } from "react";
import { cx } from "./Icon.js";

export interface SwitchProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "onChange" | "children" | "role"> {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  /** Accessible name; required unless `aria-labelledby` points at a visible title. */
  "aria-label"?: string;
}

/** On/off switch (`button role="switch"`); the knob springs in 240 ms. */
export const Switch = forwardRef<HTMLButtonElement, SwitchProps>(function Switch(
  { checked, onCheckedChange, className, disabled, type = "button", onClick, ...rest },
  ref
) {
  return (
    <button
      ref={ref}
      type={type}
      role="switch"
      aria-checked={checked}
      className={cx("switch", className)}
      disabled={disabled}
      onClick={(event) => {
        onClick?.(event);
        if (!event.defaultPrevented) {
          onCheckedChange(!checked);
        }
      }}
      {...rest}
    />
  );
});

export interface ToggleRowProps {
  title: ReactNode;
  /** Short explanation under the title. A disabled switch always says why here. */
  description?: ReactNode;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
  /** Accessible name of the switch; defaults to the title when it is a string. */
  label?: string;
  /** Extra content after the copy (badges). */
  aside?: ReactNode;
  className?: string;
}

/** Settings row: title + description on the left, switch on the right (`.toggle-row`). */
export function ToggleRow({ title, description, checked, onCheckedChange, disabled, label, aside, className }: ToggleRowProps): JSX.Element {
  const titleId = useId();
  const descriptionId = useId();
  return (
    <div className={cx("toggle-row", className)}>
      <div className="toggle-copy">
        <span className="toggle-title" id={titleId}>{title}</span>
        {description ? <span className="toggle-desc" id={descriptionId}>{description}</span> : null}
      </div>
      {aside}
      <Switch
        checked={checked}
        onCheckedChange={onCheckedChange}
        disabled={disabled}
        aria-label={label ?? (typeof title === "string" ? title : undefined)}
        aria-labelledby={label || typeof title === "string" ? undefined : titleId}
        aria-describedby={description ? descriptionId : undefined}
      />
    </div>
  );
}
