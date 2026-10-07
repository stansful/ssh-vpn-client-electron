import type { LucideIcon } from "lucide-react";
import { forwardRef, type CSSProperties, type HTMLAttributes, type ReactNode } from "react";
import { toneClass, type Tone } from "./Badge.js";
import { cx, Icon } from "./Icon.js";

export interface CardProps extends HTMLAttributes<HTMLElement> {
  /** Element to render. Default section. */
  as?: "section" | "article" | "div" | "aside";
  /** No shadow. */
  flat?: boolean;
  /** Recessed panel (surface-2, no shadow). */
  inset?: boolean;
  /** Entrance stagger step (adds `.rise` with `--d`). */
  rise?: number;
  children?: ReactNode;
}

/** Surface for one topic (`.card`). Give it an aria-label or a CardHeader title. */
export const Card = forwardRef<HTMLElement, CardProps>(function Card(
  { as: Element = "section", flat, inset, rise, className, style, children, ...rest },
  ref
) {
  const riseStyle = rise !== undefined ? ({ ...style, "--d": rise } as CSSProperties) : style;
  return (
    <Element
      ref={ref as never}
      className={cx("card", flat && "card-flat", inset && "card-inset", rise !== undefined && "rise", className)}
      style={riseStyle}
      {...rest}
    >
      {children}
    </Element>
  );
});

export interface CardHeaderProps {
  title: ReactNode;
  /** Short line under the title. */
  sub?: ReactNode;
  icon?: LucideIcon;
  /** Tints the icon box. */
  iconTone?: Tone;
  /** Buttons/badges on the right. */
  tools?: ReactNode;
  /** Heading level for the title. Default 3 (pages use h1 in the header, h2 for sections). */
  level?: 2 | 3;
  titleId?: string;
  className?: string;
}

/** Card heading row: icon box, title + sub, tools on the right. */
export function CardHeader({ title, sub, icon, iconTone, tools, level = 3, titleId, className }: CardHeaderProps): JSX.Element {
  const Heading = level === 2 ? "h2" : "h3";
  return (
    <div className={cx("card-head", className)}>
      <div className="card-title-wrap">
        {icon ? (
          <span className={cx("card-icon", toneClass(iconTone))}>
            <Icon icon={icon} />
          </span>
        ) : null}
        <div className="card-title-copy">
          <Heading className="card-title" id={titleId}>{title}</Heading>
          {sub ? <p className="card-sub">{sub}</p> : null}
        </div>
      </div>
      {tools ? <div className="card-tools">{tools}</div> : null}
    </div>
  );
}

export interface IconTileProps {
  icon: LucideIcon;
  tone?: Tone;
  /** sm 34 px, md 44 px (default), lg 56 px. */
  size?: "sm" | "md" | "lg";
  className?: string;
}

/** Tinted square holding a status icon (dialogs, toasts, system screens). */
export function IconTile({ icon, tone = "neutral", size = "md", className }: IconTileProps): JSX.Element {
  return (
    <span className={cx("icon-tile", size === "sm" && "icon-tile-sm", size === "lg" && "icon-tile-lg", toneClass(tone), className)} aria-hidden="true">
      <Icon icon={icon} size={size === "lg" ? "lg" : "md"} />
    </span>
  );
}
