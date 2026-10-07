import type { LucideIcon } from "lucide-react";
import { useEffect, useRef, type CSSProperties, type ReactNode } from "react";
import { initials as initialsOf } from "../../lib/format.js";
import { toneClass, type Tone } from "./Badge.js";
import { cx, Icon } from "./Icon.js";

export interface EmptyStateProps {
  icon: LucideIcon;
  /** What belongs here: "No SSH keys yet". */
  title: ReactNode;
  /** What you need to add it, in a sentence or two. */
  children?: ReactNode;
  /** The one action (usually a primary sm button). */
  action?: ReactNode;
  className?: string;
}

/** Dashed empty state: says what belongs here and offers the one action. */
export function EmptyState({ icon, title, children, action, className }: EmptyStateProps): JSX.Element {
  return (
    <div className={cx("empty", className)}>
      <span className="empty-icon">
        <Icon icon={icon} size="lg" />
      </span>
      <span className="empty-title">{title}</span>
      {children ? <p>{children}</p> : null}
      {action ? <div className="empty-actions">{action}</div> : null}
    </div>
  );
}

/** Keyboard key hint, e.g. ↵ or Esc. */
export function Kbd({ children }: { children: ReactNode }): JSX.Element {
  return <kbd className="kbd">{children}</kbd>;
}

export interface ProgressProps {
  /** 0–100. Omit for an indeterminate bar. */
  value?: number;
  /** Accessible name, e.g. "Portable update download". */
  label: string;
  className?: string;
}

/** 6 px progress bar; indeterminate holds still (faded) under reduced motion. */
export function Progress({ value, label, className }: ProgressProps): JSX.Element {
  const determinate = value !== undefined && Number.isFinite(value);
  const clamped = determinate ? Math.max(0, Math.min(100, value)) : undefined;
  return (
    <div
      className={cx("progress", !determinate && "indeterminate", className)}
      role="progressbar"
      aria-label={label}
      aria-valuemin={determinate ? 0 : undefined}
      aria-valuemax={determinate ? 100 : undefined}
      aria-valuenow={clamped !== undefined ? Math.round(clamped) : undefined}
    >
      <span style={determinate ? { width: `${clamped}%` } : undefined} />
    </div>
  );
}

/** Loading placeholder with a shimmer. */
export function Skeleton({ width, height = 14, className, style }: { width?: number | string; height?: number | string; className?: string; style?: CSSProperties }): JSX.Element {
  return <span className={cx("skeleton", className)} style={{ width, height, ...style }} aria-hidden="true" />;
}

export interface FactItem {
  label: ReactNode;
  value: ReactNode;
  key?: string;
}

/** Grid of small labelled facts (`.facts`), e.g. Local proxy / Protocols / Host key. */
export function Facts({ items, className }: { items: FactItem[]; className?: string }): JSX.Element {
  return (
    <div className={cx("facts", className)}>
      {items.map((item, index) => (
        <Fact key={item.key ?? index} label={item.label}>
          {item.value}
        </Fact>
      ))}
    </div>
  );
}

/** One cell of `.facts`; use inside Facts or a custom `.facts` grid. */
export function Fact({ label, children }: { label: ReactNode; children: ReactNode }): JSX.Element {
  return (
    <div className="fact">
      <span className="fact-label">{label}</span>
      <span className="fact-value">{children}</span>
    </div>
  );
}

export interface KeyValueItem {
  term: ReactNode;
  value: ReactNode;
  /** Render the value in JetBrains Mono. */
  mono?: boolean;
  key?: string;
}

/** Two-column definition list (`.kv`). */
export function KeyValue({ items, className }: { items: KeyValueItem[]; className?: string }): JSX.Element {
  return (
    <dl className={cx("kv", className)}>
      {items.map((item, index) => (
        <div key={item.key ?? index} style={{ display: "contents" }}>
          <dt>{item.term}</dt>
          <dd className={item.mono ? "mono" : undefined}>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export interface ChipProps {
  children: ReactNode;
  icon?: LucideIcon;
  /** Interactive chip; without it the chip is static text. */
  onClick?: () => void;
  /** For toggle chips (filters, "already added"). */
  pressed?: boolean;
  disabled?: boolean;
  /** Onest instead of mono (filters, labels). */
  ui?: boolean;
  /** Accessible name when the text alone is ambiguous. */
  ariaLabel?: string;
  title?: string;
  className?: string;
}

/** Pill chip: mono by default (domains, process names). */
export function Chip({ children, icon, onClick, pressed, disabled, ui, ariaLabel, title, className }: ChipProps): JSX.Element {
  const content = (
    <>
      {icon ? <Icon icon={icon} /> : null}
      {children}
    </>
  );
  if (!onClick) {
    return (
      <span className={cx("chip chip-static", ui && "chip-ui", className)} title={title} aria-label={ariaLabel}>
        {content}
      </span>
    );
  }
  return (
    <button
      type="button"
      className={cx("chip", ui && "chip-ui", className)}
      aria-pressed={pressed}
      aria-label={ariaLabel}
      title={title}
      disabled={disabled}
      onClick={onClick}
    >
      {content}
    </button>
  );
}

/** JetBrains Mono span for anything people copy or compare (hosts, ports, IDs, paths). */
export function Mono({ children, className, title }: { children: ReactNode; className?: string; title?: string }): JSX.Element {
  return (
    <span className={cx("mono", className)} title={title}>
      {children}
    </span>
  );
}

export interface AvatarProps {
  /** Name to take initials from ("Frankfurt-01" → FR). */
  name?: string;
  /** Explicit text or an icon instead of initials. */
  children?: ReactNode;
  icon?: LucideIcon;
  tone?: Tone;
  size?: "sm" | "md";
  className?: string;
}

/** Rounded square with initials or an icon (list rows, pickers). */
export function Avatar({ name, children, icon, tone, size = "md", className }: AvatarProps): JSX.Element {
  return (
    <span className={cx("avatar", size === "sm" && "avatar-sm", toneClass(tone), className)} aria-hidden="true">
      {icon ? <Icon icon={icon} size="sm" /> : children ?? initialsOf(name ?? "")}
    </span>
  );
}

export interface CollapseProps {
  open: boolean;
  children: ReactNode;
  id?: string;
  className?: string;
}

/** Height animation through grid rows; closed content is inert (not focusable or announced). */
export function Collapse({ open, children, id, className }: CollapseProps): JSX.Element {
  const innerRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (innerRef.current) {
      innerRef.current.inert = !open;
    }
  }, [open]);
  return (
    <div id={id} className={cx("collapse", className)} data-open={open ? "true" : "false"}>
      <div ref={innerRef} aria-hidden={open ? undefined : true}>
        {children}
      </div>
    </div>
  );
}
