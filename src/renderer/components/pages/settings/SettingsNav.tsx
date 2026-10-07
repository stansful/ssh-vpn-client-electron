import { Activity, Bell, Info, Monitor, Package, Palette, type LucideIcon } from "lucide-react";
import type { CSSProperties } from "react";
import type { SettingsSection } from "../../../types.js";
import { Icon } from "../../ui/index.js";
import { SECTION_LABELS, SETTINGS_SECTIONS, sectionElementId } from "./settings-model.js";

const SECTION_ICONS: Record<SettingsSection, LucideIcon> = {
  general: Monitor,
  notifications: Bell,
  appearance: Palette,
  diagnostics: Activity,
  updates: Package,
  about: Info
};

export interface SettingsNavProps {
  current: SettingsSection;
  onSelect: (section: SettingsSection) => void;
  /** "Off" next to Diagnostics while history is off. */
  historyOff: boolean;
  /** Accent dot next to Updates while a newer version waits. */
  updateWaiting: boolean;
}

/**
 * Local section navigation: a sticky column with a sliding highlight, which
 * turns into a wrapping row of chips on narrow windows (CSS).
 */
export function SettingsNav({ current, onSelect, historyOff, updateWaiting }: SettingsNavProps): JSX.Element {
  const index = Math.max(0, SETTINGS_SECTIONS.indexOf(current));
  return (
    <aside className="st-aside rise" style={{ "--d": 1 } as CSSProperties}>
      <nav className="st-nav" aria-label="Settings sections" style={{ "--i": index } as CSSProperties}>
        <span className="st-nav-ind" aria-hidden="true" />
        {SETTINGS_SECTIONS.map((section) => (
          <a
            key={section}
            className="st-nav-link"
            href={`#${sectionElementId(section)}`}
            aria-current={section === current ? "location" : undefined}
            onClick={(event) => {
              event.preventDefault();
              onSelect(section);
            }}
          >
            <Icon icon={SECTION_ICONS[section]} />
            <span>{SECTION_LABELS[section]}</span>
            {section === "diagnostics" && historyOff ? <span className="st-nav-meta">Off</span> : null}
            {section === "updates" && updateWaiting ? (
              <span className="st-nav-dot" title="Update available">
                <span className="sr-only">Update available</span>
              </span>
            ) : null}
          </a>
        ))}
      </nav>
    </aside>
  );
}
