import { CircleHelp } from "lucide-react";
import { cloneElement, isValidElement, useId, type ReactElement, type ReactNode } from "react";
import { cx, Icon } from "./Icon.js";

export interface TooltipProps {
  /** Bubble text. Keep it to a sentence or two. */
  content: ReactNode;
  /** A single focusable element; it gets aria-describedby pointing at the bubble. */
  children: ReactElement;
  /** Horizontal anchor of the bubble. Default center. */
  align?: "center" | "start" | "end";
  /** Default top. */
  side?: "top" | "bottom";
  className?: string;
}

/** Hover/focus tooltip (`.tip`). The trigger must be focusable so keyboard users get it too. */
export function Tooltip({ content, children, align = "center", side = "top", className }: TooltipProps): JSX.Element {
  const id = useId();
  const trigger = isValidElement<{ "aria-describedby"?: string }>(children)
    ? cloneElement(children, {
        "aria-describedby": [children.props["aria-describedby"], id].filter(Boolean).join(" ")
      })
    : children;
  return (
    <span className={cx("tip", className)} data-align={align === "center" ? undefined : align} data-side={side === "top" ? undefined : side}>
      {trigger}
      <span className="tip-bubble" role="tooltip" id={id}>
        {content}
      </span>
    </span>
  );
}

export interface HelpTipProps {
  /** Accessible name of the "?" button: "What is the Key ID?". */
  label: string;
  content: ReactNode;
  align?: "center" | "start" | "end";
}

/** Small "?" button that explains a term on hover or focus. */
export function HelpTip({ label, content, align = "end" }: HelpTipProps): JSX.Element {
  return (
    <Tooltip content={content} align={align}>
      <button type="button" className="help-tip-btn" aria-label={label}>
        <Icon icon={CircleHelp} />
      </button>
    </Tooltip>
  );
}
