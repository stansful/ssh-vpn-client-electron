import { CircleAlert, Info, ShieldAlert, ShieldCheck, TriangleAlert, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { cx, Icon } from "./Icon.js";

export type CalloutTone = "neutral" | "info" | "warn" | "danger" | "ok" | "accent";

const DEFAULT_ICON: Record<CalloutTone, LucideIcon> = {
  neutral: Info,
  info: Info,
  warn: ShieldAlert,
  danger: TriangleAlert,
  ok: ShieldCheck,
  accent: CircleAlert
};

export interface CalloutProps {
  /** Default neutral. info = calm note, warn = needs a decision, danger = failed, ok = it worked. */
  tone?: CalloutTone;
  /** Overrides the tone's icon. Pass null for no icon. */
  icon?: LucideIcon | null;
  /** Says what; the body says what to do. */
  title?: ReactNode;
  children?: ReactNode;
  /** Buttons on the right (they wrap below on narrow widths). */
  actions?: ReactNode;
  /** "alert" for failures that must interrupt, "status" for live updates. */
  role?: "alert" | "status";
  className?: string;
  id?: string;
}

/** In-page note that stays until the situation changes (`.callout`). */
export function Callout({ tone = "neutral", icon, title, children, actions, role, className, id }: CalloutProps): JSX.Element {
  const glyph = icon === null ? undefined : icon ?? DEFAULT_ICON[tone];
  return (
    <div id={id} className={cx("callout", tone !== "neutral" && `t-${tone}`, className)} role={role}>
      {glyph ? <Icon icon={glyph} /> : null}
      <div className="callout-body">
        {title ? <span className="callout-title">{title}</span> : null}
        {children ? <span>{children}</span> : null}
      </div>
      {actions ? <div className="callout-actions">{actions}</div> : null}
    </div>
  );
}

export interface StateLineProps {
  tone?: "neutral" | "ok" | "warn" | "accent" | "danger" | "info";
  icon: LucideIcon;
  children: ReactNode;
  /** Trailing link action, e.g. Undo. */
  action?: ReactNode;
  id?: string;
  className?: string;
}

/** Compact state line under a field ("A key is saved · paste a new one to replace it"). */
export function StateLine({ tone = "neutral", icon, children, action, id, className }: StateLineProps): JSX.Element {
  return (
    <div id={id} className={cx("state-line", tone !== "neutral" && `t-${tone}`, "anim-swap", className)}>
      <Icon icon={icon} />
      <span>{children}</span>
      {action}
    </div>
  );
}
