import { Bell } from "lucide-react";
import { useAppData } from "../../../hooks/useAppData.js";
import type { AppSettings } from "../../../../shared/types.js";
import { Card, CardHeader } from "../../ui/index.js";
import { platformCopy, sectionElementId } from "./settings-model.js";
import { SettingToggle } from "./SettingToggle.js";
import type { SettingsSaver } from "./useSettingsSaver.js";

/** Desktop (OS) notifications, copy from System.dc.html section 05. */
export function NotificationsSection({ settings, save }: { settings: AppSettings; save: SettingsSaver["save"] }): JSX.Element {
  const { environment } = useAppData();
  const copy = platformCopy(environment.platform);
  const tray = settings.closeToTrayEnabled;

  return (
    <Card id={sectionElementId("notifications")} className="st-section" rise={3} aria-labelledby="st-notifications-h" tabIndex={-1}>
      <CardHeader level={2} titleId="st-notifications-h" icon={Bell} title="Notifications" sub={copy.notificationsSub} />

      <div className="st-toggles">
        <SettingToggle
          title="Tunnel drops or comes back"
          label="Notify when the tunnel drops or comes back"
          description="When the connection is lost, reconnects, or gives up."
          checked={settings.notifyTunnelChanges}
          onCheckedChange={(checked) => save({ notifyTunnelChanges: checked })}
        />
        <SettingToggle
          title="Update downloaded"
          label="Notify when an update is downloaded"
          description={copy.updateNotificationDescription}
          checked={copy.updatesInApp && settings.notifyUpdateDownloaded}
          disabled={!copy.updatesInApp}
          onCheckedChange={(checked) => save({ notifyUpdateDownloaded: checked })}
        />
        <SettingToggle
          title={copy.stillRunningTitle}
          label={copy.stillRunningLabel}
          description="Once, the first time you close the window while the tunnel is on."
          why={copy.stillRunningWhy}
          checked={tray && settings.notifyStillRunningInTray}
          disabled={!tray}
          onCheckedChange={(checked) => save({ notifyStillRunningInTray: checked })}
        />
        <SettingToggle
          title="Only while the window is hidden"
          label="Show desktop notifications only while the window is hidden"
          description="With the window open you get in-app toasts instead, never both."
          checked={settings.notifyOnlyWhenHidden}
          onCheckedChange={(checked) => save({ notifyOnlyWhenHidden: checked })}
        />
      </div>

      <p className="hint st-note">{copy.notificationsHint}</p>
    </Card>
  );
}
