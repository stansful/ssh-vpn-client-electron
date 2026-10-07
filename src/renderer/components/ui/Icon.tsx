import { LoaderCircle, type LucideIcon } from "lucide-react";

/** Joins class names, skipping falsy parts. */
export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

export type IconSize = "sm" | "md" | "lg" | "xl";

export interface IconProps {
  /** A Lucide icon component (the boards use Lucide names). */
  icon: LucideIcon;
  /** sm 15 px, md 18 px (default), lg 22 px, xl 30 px. */
  size?: IconSize;
  /** Rotate continuously (spinners). */
  spin?: boolean;
  className?: string;
  /** Inline style, e.g. a colour override. */
  style?: React.CSSProperties;
}

const SIZE_CLASS: Record<IconSize, string | undefined> = {
  sm: "ic-sm",
  md: undefined,
  lg: "ic-lg",
  xl: "ic-xl"
};

/** Decorative stroke icon in the design system's `.ic` style; hidden from assistive tech. */
export function Icon({ icon: Glyph, size = "md", spin = false, className, style }: IconProps): JSX.Element {
  return (
    <Glyph
      className={cx("ic", SIZE_CLASS[size], spin && "ic-spin", className)}
      style={style}
      aria-hidden="true"
      focusable="false"
    />
  );
}

/** The working spinner (open arc). Pair it with a word that ends in an ellipsis. */
export function Spinner({ size = "sm", className }: { size?: IconSize; className?: string }): JSX.Element {
  return <Icon icon={LoaderCircle} size={size} spin className={className} />;
}

/** Stop glyph used by the orb and "Stop" actions (rounded square, smaller than Lucide's Square). */
export function StopIcon({ className }: { className?: string }): JSX.Element {
  return (
    <svg className={cx("ic", className)} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <rect width="12" height="12" x="6" y="6" rx="2.5" />
    </svg>
  );
}
