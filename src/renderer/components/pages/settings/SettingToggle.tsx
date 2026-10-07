import { Lock } from "lucide-react";
import { useId, type ReactNode } from "react";
import { Collapse, cx, Icon, Switch } from "../../ui/index.js";

export interface SettingToggleProps {
  /** Visible title; clicking it flips the switch like a checkbox label. */
  title: ReactNode;
  description?: ReactNode;
  /** Accessible name of the switch (names the setting in full). */
  label: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
  /** Indented under the setting it depends on, with a connector line. */
  sub?: boolean;
  /** Says why the switch is unavailable (shown with a lock while it is). */
  why?: ReactNode;
  /** Badge next to the title ("Windows"). */
  badge?: ReactNode;
}

/** One settings row (`.toggle-row`): title and description on the left, switch on the right. */
export function SettingToggle({ title, description, label, checked, onCheckedChange, disabled = false, sub = false, why, badge }: SettingToggleProps): JSX.Element {
  const switchId = useId();
  const descriptionId = useId();
  const whyId = useId();
  const describedBy = [description ? descriptionId : undefined, why && disabled ? whyId : undefined].filter(Boolean).join(" ") || undefined;
  return (
    <div className={cx("toggle-row", sub && "st-sub")} data-off={disabled ? "true" : "false"}>
      <div className="toggle-copy">
        <label className="toggle-title st-tt" htmlFor={switchId}>
          {title}
          {badge}
        </label>
        {description ? (
          <span className="toggle-desc" id={descriptionId}>
            {description}
          </span>
        ) : null}
        {why ? (
          <Collapse open={disabled}>
            <span className="st-why" id={whyId}>
              <Icon icon={Lock} />
              {why}
            </span>
          </Collapse>
        ) : null}
      </div>
      <Switch id={switchId} checked={checked} onCheckedChange={onCheckedChange} disabled={disabled} aria-label={label} aria-describedby={describedBy} />
    </div>
  );
}
