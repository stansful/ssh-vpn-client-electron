import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { cx, Icon, Spinner } from "./Icon.js";

/** Status tones; one meaning each (neutral = at rest). */
export type Tone = "neutral" | "ok" | "busy" | "accent" | "danger" | "warn" | "info";

export function toneClass(tone: Tone | undefined): string | undefined {
  return tone && tone !== "neutral" ? `t-${tone}` : undefined;
}

export interface BadgeProps {
  /** Default neutral. "outline" is a quiet bordered pill (counts, facts). */
  tone?: Tone | "outline";
  /** Leading status dot in the badge tone (steady states). */
  dot?: boolean;
  /** Leading spinner for working states; end the text with an ellipsis. */
  spinner?: boolean;
  /** Leading icon (check, cross, pin…). */
  icon?: LucideIcon;
  /** Square mono tag (`.badge-sq`) for facts like protocol, key type, version. */
  square?: boolean;
  className?: string;
  title?: string;
  children: ReactNode;
}

/** Status pill or mono tag. Status is never colour-only: always a word, plus a dot, spinner or icon. */
export function Badge({ tone = "neutral", dot, spinner, icon, square, className, title, children }: BadgeProps): JSX.Element {
  const toneCls = tone === "outline" ? "t-outline" : toneClass(tone);
  return (
    <span className={cx("badge", square && "badge-sq", toneCls, className)} title={title}>
      {spinner ? <Spinner size="md" /> : icon ? <Icon icon={icon} /> : dot ? <StatusDot tone={tone === "outline" ? "neutral" : tone} /> : null}
      {children}
    </span>
  );
}

export interface StatusDotProps {
  tone?: Tone;
  className?: string;
}

/** 8 px status dot; "busy" pulses. Never use it without a word next to it. */
export function StatusDot({ tone = "neutral", className }: StatusDotProps): JSX.Element {
  return <span className={cx("dot", toneClass(tone), className)} aria-hidden="true" />;
}

/** Dot followed by its word, e.g. "● Protected". */
export function DotLabel({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }): JSX.Element {
  return (
    <span className="dot-label">
      <StatusDot tone={tone} />
      {children}
    </span>
  );
}

/** Activity level pill: INFO / WARN / ERROR, coloured and worded. */
export function LevelPill({ level }: { level: "info" | "warning" | "error" }): JSX.Element {
  const label = level === "warning" ? "WARN" : level === "error" ? "ERROR" : "INFO";
  const cls = level === "warning" ? "lvl-warn" : level === "error" ? "lvl-error" : "lvl-info";
  return <span className={cx("lvl", cls)}>{label}</span>;
}
