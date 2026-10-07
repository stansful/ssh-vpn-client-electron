import { Power, RotateCcw, ShieldAlert, ShieldCheck, type LucideIcon } from "lucide-react";
import { forwardRef } from "react";
import type { OrbState } from "../../lib/connection.js";
import { cx, Icon, StopIcon } from "./Icon.js";

export type { OrbState } from "../../lib/connection.js";

export interface OrbProps {
  state: OrbState;
  /** Accessible name of the button ("Connect", "Disconnect", "Stop reconnecting"). */
  ariaLabel: string;
  /** Small caps label under the orb ("Tap to connect"). */
  label?: string;
  onClick?: () => void;
  disabled?: boolean;
  /** md 196 px (hero), sm 76 px (compact rows). */
  size?: "md" | "sm";
  /** Override the state's glyph. */
  icon?: LucideIcon;
  /** Render as a static picture instead of a button (galleries, previews). */
  decorative?: boolean;
  className?: string;
}

function glyphFor(state: OrbState): LucideIcon | "stop" {
  switch (state) {
    case "connected":
      return ShieldCheck;
    case "reconnecting":
    case "disconnecting":
      return "stop";
    case "preview":
      return ShieldAlert;
    case "error":
      return RotateCcw;
    default:
      return Power;
  }
}

/**
 * The signal orb — the main power control. Rings, arc and glow animate per
 * state (spinning arc while working, breathing while protected, one shake on
 * error); reduced motion stops all of it.
 */
export const Orb = forwardRef<HTMLButtonElement, OrbProps>(function Orb(
  { state, ariaLabel, label, onClick, disabled, size = "md", icon, decorative = false, className },
  ref
) {
  const glyph = icon ?? glyphFor(state);
  const glyphNode = glyph === "stop" ? <StopIcon /> : <Icon icon={glyph} />;
  const orb = (
    <div className={cx("orb", size === "sm" && "orb-sm", !label && className)} data-state={state}>
      <span className="orb-ring r3" />
      <span className="orb-ring" />
      <span className="orb-ring r2" />
      <span className="orb-glow" />
      <span className="orb-arc" />
      {decorative ? (
        <span className="orb-btn" role="img" aria-label={ariaLabel}>
          {glyphNode}
        </span>
      ) : (
        <button ref={ref} type="button" className="orb-btn" aria-label={ariaLabel} disabled={disabled} onClick={onClick}>
          {glyphNode}
        </button>
      )}
    </div>
  );
  if (!label) {
    return orb;
  }
  return (
    <div className={cx("orb-col", className)}>
      {orb}
      <span className="orb-label" aria-hidden="true">
        {label}
      </span>
    </div>
  );
});
