import { ArrowRight, Check, ChevronDown, type LucideIcon } from "lucide-react";
import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { cx, Icon, Spinner } from "./Icon.js";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "danger-solid" | "danger-ghost" | "ok";
export type ButtonSize = "sm" | "md" | "lg";

const VARIANT_CLASS: Record<ButtonVariant, string | undefined> = {
  primary: "btn-primary",
  secondary: undefined,
  ghost: "btn-ghost",
  danger: "btn-danger",
  "danger-solid": "btn-danger-solid",
  "danger-ghost": "btn-danger-ghost",
  ok: "btn-ok"
};

const SIZE_CLASS: Record<ButtonSize, string | undefined> = { sm: "btn-sm", md: undefined, lg: "btn-lg" };

export function buttonClass(variant: ButtonVariant = "secondary", size: ButtonSize = "md", extra?: string): string {
  return cx("btn", VARIANT_CLASS[variant], SIZE_CLASS[size], extra);
}

export interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children"> {
  /** One primary per view; danger for stop/remove; solid danger only inside confirmations. Default secondary. */
  variant?: ButtonVariant;
  /** sm 32 px, md 38 px (default), lg 46 px. */
  size?: ButtonSize;
  /** Leading icon. Replaced by a spinner while `busy`. */
  icon?: LucideIcon;
  /** Trailing icon (e.g. a chevron). */
  iconAfter?: LucideIcon;
  /** Shows a spinner, sets aria-busy and disables the button. */
  busy?: boolean;
  /** Label while busy, ending in an ellipsis ("Checking…"). Defaults to the children. */
  busyLabel?: ReactNode;
  /** Success flash (mint), e.g. after Copy. */
  done?: boolean;
  /** Full width. */
  block?: boolean;
  children?: ReactNode;
}

/** The design system button (`.btn`). Labels are verbs. */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", icon, iconAfter, busy = false, busyLabel, done, block, className, disabled, type = "button", children, ...rest },
  ref
) {
  const iconSize = size === "lg" ? "md" : "sm";
  return (
    <button
      ref={ref}
      type={type}
      className={buttonClass(variant, size, cx(block && "btn-block", className))}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      data-done={done ? "true" : undefined}
      {...rest}
    >
      {busy ? <Spinner size={iconSize} /> : icon ? <Icon icon={icon} size={iconSize} /> : null}
      {busy && busyLabel !== undefined ? busyLabel : children}
      {iconAfter ? <Icon icon={iconAfter} size={iconSize} className="chev" /> : null}
    </button>
  );
});

export interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children" | "aria-label" | "title"> {
  icon: LucideIcon;
  /** Required accessible name that names the object ("Edit server Frankfurt-01"); also the tooltip. */
  label: string;
  /** Tooltip text when it should differ from the accessible name (e.g. "Copy"). */
  tooltip?: string;
  /** Default ghost. */
  variant?: ButtonVariant;
  /** Default sm (32 px). */
  size?: ButtonSize;
  busy?: boolean;
  /** Swap the icon for a mint check (copied, saved). */
  done?: boolean;
  /** For toggle-style icon buttons. */
  pressed?: boolean;
}

/** Icon-only button with a required aria-label and matching title. */
export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { icon, label, tooltip, variant = "ghost", size = "sm", busy = false, done = false, pressed, className, disabled, type = "button", ...rest },
  ref
) {
  return (
    <button
      ref={ref}
      type={type}
      className={buttonClass(variant, size, cx("btn-icon", className))}
      aria-label={label}
      title={tooltip ?? label}
      aria-pressed={pressed}
      aria-busy={busy || undefined}
      disabled={disabled || busy}
      {...rest}
    >
      {busy ? (
        <Spinner size={size === "lg" ? "md" : "sm"} />
      ) : (
        <Icon icon={done ? Check : icon} size={size === "lg" ? "md" : "sm"} style={done ? { color: "var(--ok-text)" } : undefined} />
      )}
    </button>
  );
});

export interface LinkButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children"> {
  children: ReactNode;
  /** Trailing icon; defaults to an arrow. Pass null for none. */
  icon?: LucideIcon | null;
}

/** Accent text action, e.g. "Manage routing →", "Open activity →". */
export const LinkButton = forwardRef<HTMLButtonElement, LinkButtonProps>(function LinkButton(
  { children, icon = ArrowRight, className, type = "button", ...rest },
  ref
) {
  return (
    <button ref={ref} type={type} className={cx("link-btn", className)} {...rest}>
      {children}
      {icon ? <Icon icon={icon} /> : null}
    </button>
  );
});

export interface DisclosureButtonProps extends Omit<ButtonProps, "iconAfter" | "aria-expanded"> {
  open: boolean;
  /** id of the region it shows/hides. */
  controls?: string;
}

/** Ghost button with a turning chevron for "Show details" / "What couldn't be read". */
export const DisclosureButton = forwardRef<HTMLButtonElement, DisclosureButtonProps>(function DisclosureButton(
  { open, controls, variant = "ghost", size = "sm", className, ...rest },
  ref
) {
  return (
    <Button
      ref={ref}
      variant={variant}
      size={size}
      iconAfter={ChevronDown}
      aria-expanded={open}
      aria-controls={controls}
      data-open={open ? "true" : "false"}
      className={cx("disclosure", className)}
      {...rest}
    />
  );
});
