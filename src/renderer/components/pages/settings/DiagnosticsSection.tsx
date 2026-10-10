import { Activity, FileText, Info, TriangleAlert } from "lucide-react";
import { useAppData } from "../../../hooks/useAppData.js";
import type { AppSettings } from "../../../../shared/types.js";
import { Badge, Callout, Card, CardHeader, Collapse, Icon, LinkButton } from "../../ui/index.js";
import { historyPatch, logFilePath, presentDiagnostics, sectionElementId } from "./settings-model.js";
import { SettingToggle } from "./SettingToggle.js";
import type { SettingsSaver } from "./useSettingsSaver.js";

export function DiagnosticsSection({ settings, save }: { settings: AppSettings; save: SettingsSaver["save"] }): JSX.Element {
  const { snapshot, navigate } = useAppData();
  const state = presentDiagnostics(settings);

  return (
    <Card id={sectionElementId("diagnostics")} className="st-section" rise={5} aria-labelledby="st-diagnostics-h" tabIndex={-1}>
      <CardHeader
        level={2}
        titleId="st-diagnostics-h"
        icon={Activity}
        title="Diagnostics"
        sub="What Shadow records for Activity and for bug reports."
        tools={
          <Badge tone={state.badge.tone} dot>
            {state.badge.text}
          </Badge>
        }
      />

      <div>
        <div className="st-toggles">
          <SettingToggle
            title="Keep activity history"
            label="Keep activity history"
            description="Lets Shadow record what the tunnel does, so you can look back in Activity when something goes wrong."
            checked={state.historyOn}
            onCheckedChange={(checked) => save(historyPatch(checked))}
          />
          <SettingToggle
            sub
            title="Record live events"
            label="Record live events"
            description="Connection events, tunnel checks and errors appear in Activity as they happen."
            checked={state.liveOn}
            disabled={!state.historyOn}
            onCheckedChange={(checked) => save({ diagnosticsLoggingEnabled: checked })}
          />
          <SettingToggle
            sub
            title={
              <>
                Write log file <span className="mono faint">main.log</span>
              </>
            }
            label="Write log file (main.log)"
            description="Saves the same events to a file you can attach to a bug report."
            checked={state.fileOn}
            disabled={!state.historyOn}
            onCheckedChange={(checked) => save({ fileLoggingEnabled: checked })}
          />
        </div>

        <Collapse open={!state.historyOn}>
          <Callout tone="warn" icon={TriangleAlert} title="History is off" className="st-callout">
            Activity disappears from the sidebar and nothing new is recorded, not even startup errors. What was recorded before stays and comes back when you
            turn history on again.
          </Callout>
        </Collapse>

        <Collapse open={state.nothingRecorded}>
          <Callout tone="info" icon={Info} title="Nothing is being recorded" className="st-callout">
            Live events and the log file are both off, so Activity stays empty. Turn one back on, or turn history off altogether.
          </Callout>
        </Collapse>
      </div>

      <div className="st-path">
        <span className="card-icon">
          <Icon icon={FileText} size="sm" />
        </span>
        <span className="st-path-copy">
          <span className="st-cap">Log file</span>
          <span className="mono break">{logFilePath(snapshot)}</span>
        </span>
        {state.historyOn ? <LinkButton onClick={() => navigate("activity")}>Open Activity</LinkButton> : null}
      </div>
    </Card>
  );
}
