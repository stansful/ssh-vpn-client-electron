import { Check } from "lucide-react";
import { useEffect, useRef } from "react";
import { useAppData } from "../../../hooks/useAppData.js";
import { useNavigation } from "../../../hooks/useNavigation.js";
import type { PageProps } from "../../../types.js";
import { PageHeader } from "../../shell/index.js";
import { Badge } from "../../ui/index.js";
import { AboutSection } from "./AboutSection.js";
import { AppearanceSection } from "./AppearanceSection.js";
import { DiagnosticsSection } from "./DiagnosticsSection.js";
import { GeneralSection } from "./GeneralSection.js";
import { NotificationsSection } from "./NotificationsSection.js";
import { presentUpdates } from "./settings-model.js";
import { SettingsNav } from "./SettingsNav.js";
import { UpdatesSection } from "./UpdatesSection.js";
import { useSectionSpy } from "./useSectionSpy.js";
import { useSettingsSaver } from "./useSettingsSaver.js";

/**
 * Settings (Settings.dc.html): every change applies and saves at once. A local
 * section nav follows the scroll; intents can open a given section.
 */
export function SettingsPage({ intent }: PageProps): JSX.Element {
  const { snapshot, store, environment } = useAppData();
  const { clearIntent } = useNavigation();
  const { save, status, savedKey } = useSettingsSaver();
  const layoutRef = useRef<HTMLDivElement>(null);
  const { current, goTo } = useSectionSpy(layoutRef);
  const settings = store.settings;

  useEffect(() => {
    if (intent?.type !== "settings-section") {
      return undefined;
    }
    const section = intent.section;
    // Wait for the page's own scroll reset and first layout before jumping.
    const frame = window.requestAnimationFrame(() => {
      goTo(section, { focus: true, instant: true });
      clearIntent();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [clearIntent, goTo, intent]);

  const updateWaiting = presentUpdates({
    platform: environment.platform,
    arch: environment.arch,
    currentVersion: environment.version,
    info: snapshot.updateInfo,
    download: snapshot.updateDownload,
    checking: false
  }).navDot;
  const saved = status === "saved";

  return (
    <>
      <PageHeader
        eyebrow="App"
        title="Settings"
        sub="Every change applies and saves the moment you make it. There is no Save button to forget."
        actions={
          <span className="st-save-live" role="status">
            <Badge key={saved ? `saved-${savedKey}` : `idle-${savedKey}`} className="st-save anim-swap" tone={saved ? "ok" : "outline"} icon={saved ? Check : undefined}>
              {saved ? "Saved" : "Changes save automatically"}
            </Badge>
          </span>
        }
      />

      <div className="st-layout" ref={layoutRef}>
        <SettingsNav current={current} onSelect={(section) => goTo(section, { focus: true })} historyOff={!settings.loggingEnabled} updateWaiting={updateWaiting} />

        <div className="st-sections">
          <GeneralSection settings={settings} save={save} />
          <NotificationsSection settings={settings} save={save} />
          <AppearanceSection settings={settings} save={save} />
          <DiagnosticsSection settings={settings} save={save} />
          <UpdatesSection />
          <AboutSection />
        </div>
      </div>
    </>
  );
}
