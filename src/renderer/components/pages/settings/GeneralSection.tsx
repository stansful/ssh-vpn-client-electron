import { ArrowRight, Monitor, Route } from "lucide-react";
import { useAppData } from "../../../hooks/useAppData.js";
import type { AppSettings } from "../../../../shared/types.js";
import { Badge, Card, CardHeader, Icon } from "../../ui/index.js";
import { autoConnectTarget, platformCopy, routingModeLabel, sectionElementId } from "./settings-model.js";
import { SettingToggle } from "./SettingToggle.js";
import type { SettingsSaver } from "./useSettingsSaver.js";

export function GeneralSection({ settings, save }: { settings: AppSettings; save: SettingsSaver["save"] }): JSX.Element {
  const { store, environment, navigate } = useAppData();
  const copy = platformCopy(environment.platform);
  const target = autoConnectTarget(store);
  const tray = settings.closeToTrayEnabled;

  return (
    <Card id={sectionElementId("general")} className="st-section" rise={2} aria-labelledby="st-general-h" tabIndex={-1}>
      <CardHeader
        level={2}
        titleId="st-general-h"
        icon={Monitor}
        title="General"
        sub="Startup & window: how Shadow SSH starts, closes and keeps running in the background."
      />

      <div className="st-toggles">
        <SettingToggle
          title="Connect automatically when the app starts"
          label="Connect automatically when the app starts"
          description={
            <>
              Reconnects with the transport and server you used last, currently <span className="mono">{target.label}</span>
              {target.selected ? "" : ` with nothing selected`}. If Split tunnel has nothing to route or no server is selected, it skips and a toast says why.
            </>
          }
          checked={settings.autoConnectOnStartup}
          onCheckedChange={(checked) => save({ autoConnectOnStartup: checked })}
        />

        <SettingToggle
          title={copy.trayTitle}
          label={copy.trayTitle}
          description={copy.trayDescription}
          checked={tray}
          onCheckedChange={(checked) => save({ closeToTrayEnabled: checked })}
        />

        <SettingToggle
          sub
          title="Free memory while hidden"
          label="Free memory while hidden"
          description={copy.freeMemoryDescription}
          why={copy.freeMemoryWhy}
          checked={tray && settings.releaseRendererInTrayEnabled}
          disabled={!tray}
          onCheckedChange={(checked) => save({ releaseRendererInTrayEnabled: checked })}
        />

        <SettingToggle
          title="Launch at sign-in, hidden in tray"
          label="Launch at sign-in, hidden in tray"
          badge={
            <Badge square tone="outline">
              Windows
            </Badge>
          }
          description={copy.signInDescription}
          checked={copy.signInAvailable && settings.startWithWindowsInTray}
          disabled={!copy.signInAvailable}
          onCheckedChange={(checked) => save({ startWithWindowsInTray: checked })}
        />
      </div>

      <a
        className="st-moved"
        href="#routing"
        onClick={(event) => {
          event.preventDefault();
          navigate("routing");
        }}
      >
        <span className="card-icon">
          <Icon icon={Route} size="sm" />
        </span>
        <span className="st-moved-copy">
          <span className="toggle-title">Routing mode now lives in Routing</span>
          <span className="toggle-desc">
            Full tunnel or Split tunnel is chosen at the top of Routing, next to the rules it depends on. Now: {routingModeLabel(store.routingMode)}.
          </span>
        </span>
        <Icon icon={ArrowRight} className="st-moved-arrow" />
      </a>
    </Card>
  );
}
