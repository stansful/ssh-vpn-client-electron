import { CircleDot, FileText, Folder, Info } from "lucide-react";
import { Badge, Card, CardHeader, Icon, LinkButton, ToggleRow } from "../../ui/index.js";
import type { LogSizeInfo } from "./activity-log.js";

export interface RecordingCardProps {
  liveOn: boolean;
  fileOn: boolean;
  onLiveChange: (on: boolean) => void;
  onFileChange: (on: boolean) => void;
  onOpenDiagnostics: () => void;
}

/** What Shadow SSH keeps while it runs: live events and the log file. */
export function RecordingCard({ liveOn, fileOn, onLiveChange, onFileChange, onOpenDiagnostics }: RecordingCardProps): JSX.Element {
  const both = liveOn && fileOn;
  const none = !liveOn && !fileOn;
  return (
    <Card rise={3} aria-labelledby="ac-rec-title">
      <CardHeader
        icon={CircleDot}
        title="Recording"
        titleId="ac-rec-title"
        sub="Choose what Shadow SSH keeps while it runs."
        tools={
          <Badge tone={both ? "ok" : none ? "neutral" : "warn"} dot>
            {both ? "Recording" : none ? "Off" : "Partly off"}
          </Badge>
        }
      />
      <div>
        <ToggleRow
          title="Record live events"
          description="Keeps up to 500 events in memory for the Events tab. They’re cleared each time you connect and when you quit."
          checked={liveOn}
          onCheckedChange={onLiveChange}
        />
        <ToggleRow
          title="Write log file"
          description="Saves events to main.log so they survive a restart. Useful when you report a problem."
          checked={fileOn}
          onCheckedChange={onFileChange}
        />
      </div>
      <div className="ac-note">
        <Icon icon={Info} size="sm" />
        <span>
          Turning these off only stops new entries. What’s already kept stays until you clear it. To switch activity off entirely and hide this page, use{" "}
          <LinkButton icon={null} onClick={onOpenDiagnostics}>
            Settings → Diagnostics
          </LinkButton>
          .
        </span>
      </div>
    </Card>
  );
}

export interface LogFilesCardProps {
  directory: string;
  /** main.log, then its archives, newest first. */
  fileNames: readonly string[];
  size: LogSizeInfo;
  /** Activity was cleared on this visit: archives read "Deleted". */
  cleared: boolean;
}

/** main.log and its two rotation archives. */
export function LogFilesCard({ directory, fileNames, size, cleared }: LogFilesCardProps): JSX.Element {
  const [current, ...archives] = fileNames;
  const missing = cleared ? "Deleted" : "None yet";
  const archiveRow = (index: number): { size: string; gone: boolean } => {
    if (size.archiveSizes) {
      const known = size.archiveSizes[index];
      return known === undefined ? { size: missing, gone: true } : { size: known, gone: false };
    }
    if (size.archives === "none") {
      return { size: missing, gone: true };
    }
    return { size: size.archives === "maybe" ? "Up to 5 MB" : "Unknown", gone: false };
  };
  return (
    <Card rise={4} aria-labelledby="ac-files-title">
      <CardHeader
        icon={Folder}
        title="Log files"
        titleId="ac-files-title"
        sub="When main.log reaches 5 MB it becomes an archive. Two archives are kept, so logs stay under about 15 MB."
      />
      <span className="mono ac-path faint">{directory}</span>
      <div className="ac-files">
        <div className="ac-file-row">
          <Icon icon={FileText} size="sm" />
          <span className="mono">{current}</span>
          <Badge tone="accent" square>
            current
          </Badge>
          <span className="ac-file-size">{size.mainSize ?? "Unknown"}</span>
        </div>
        {archives.map((name, index) => {
          const row = archiveRow(index);
          return (
            <div className="ac-file-row" data-gone={row.gone ? "true" : "false"} key={name}>
              <Icon icon={FileText} size="sm" />
              <span className="mono">{name}</span>
              <Badge tone="outline" square>
                {index === archives.length - 1 ? "oldest" : "archive"}
              </Badge>
              <span className="ac-file-size">{row.size}</span>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
