import { FileText, RefreshCw } from "lucide-react";
import { memo, useId, useLayoutEffect, useRef, useState } from "react";
import { Button, buttonClass, Callout, Collapse, DisclosureButton, EmptyState, Icon } from "../../ui/index.js";
import { utcOffsetNote, type LogLine, type LogRead, type LogSizeInfo } from "./activity-log.js";

export interface LogFilePanelProps {
  read?: LogRead;
  reading: boolean;
  readNo: number;
  newFrom: number;
  /** main.log path shown above the lines. */
  path: string;
  size: LogSizeInfo;
  fileOn: boolean;
  onTurnOnFile: () => void;
  onRefresh: () => void;
}

/** Log file tab: the tail of main.log, read on open and on Refresh (it isn't live). */
export function LogFilePanel({ read, reading, readNo, newFrom, path, size, fileOn, onTurnOnFile, onRefresh }: LogFilePanelProps): JSX.Element {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const detailsId = useId();

  return (
    <>
      <div className="ac-file">
        <span className="card-icon" aria-hidden="true">
          <Icon icon={FileText} />
        </span>
        <div className="ac-file-copy">
          <span className="mono ac-path">{read?.path ?? path}</span>
          {size.meta ? (
            <div className="ac-file-meta">
              <span>{size.meta}</span>
              {size.capPercent !== undefined ? (
                <div className="progress ac-cap" role="img" aria-label={`${size.mainSize ?? ""} of the 5 MB limit before main.log becomes an archive`}>
                  <span style={{ width: `${size.capPercent}%` }} />
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
        <button type="button" className={buttonClass("secondary", "sm")} disabled={reading} aria-busy={reading || undefined} onClick={onRefresh}>
          <Icon icon={RefreshCw} size="sm" spin={reading} />
          {reading ? "Reading…" : "Refresh"}
        </button>
      </div>

      {!fileOn ? (
        <Callout
          tone="info"
          title="Writing to main.log is off"
          actions={
            <Button size="sm" onClick={onTurnOnFile}>
              Turn on
            </Button>
          }
        >
          This file stopped updating. New events still show in the Events tab while live events are on.
        </Callout>
      ) : null}

      {read?.state === "error" ? (
        <div className="stack">
          <Callout
            tone="danger"
            title="Couldn’t read main.log"
            role="alert"
            actions={
              <>
                <DisclosureButton open={detailsOpen} controls={detailsId} onClick={() => setDetailsOpen((open) => !open)}>
                  {detailsOpen ? "Hide details" : "Details"}
                </DisclosureButton>
                <Button size="sm" disabled={reading} onClick={onRefresh}>
                  Try again
                </Button>
              </>
            }
          >
            Another program may be holding the file open. Close it, then try again. Live events are still in the Events tab.
          </Callout>
          <Collapse open={detailsOpen} id={detailsId}>
            <div className="term term-lines ac-term" role="log" aria-label="Error details">
              {read.path ? <span className="term-line t-dim">### {read.path}</span> : null}
              {read.details.map((line, index) => (
                <span className={index === 0 ? "term-line t-err" : "term-line t-dim"} key={index}>
                  {line}
                </span>
              ))}
            </div>
          </Collapse>
        </div>
      ) : null}

      {read?.state === "lines" ? <LogLines lines={read.lines} newFrom={newFrom} readNo={readNo} /> : null}

      {read?.state === "empty" ? (
        <EmptyState icon={FileText} title="main.log is empty" className="fade">
          New lines are written as things happen. Press Refresh to read the file again.
        </EmptyState>
      ) : null}

      <p className="hint ac-loghint">
        Shows the last 1 MB across main.log and its archives, oldest at the top. {utcOffsetNote()} Per-connection proxy chatter isn’t written to the file,
        and the file doesn’t update live: it’s read when you open this tab or press Refresh.
      </p>
    </>
  );
}

interface LogLinesProps {
  lines: LogLine[];
  newFrom: number;
  readNo: number;
}

/** Up to 1 MB of lines: memoized so live feed updates don't re-render it. Scrolls to the newest line after each read. */
const LogLines = memo(function LogLines({ lines, newFrom, readNo }: LogLinesProps): JSX.Element {
  const termRef = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const term = termRef.current;
    if (term) {
      term.scrollTop = term.scrollHeight;
    }
  }, [readNo]);

  return (
    <div ref={termRef} className="term term-lines ac-term" role="log" aria-label="main.log, last 1 MB, oldest first" tabIndex={0}>
      {lines.map((line, index) => (
        <span className={index >= newFrom ? "term-line ac-flash" : "term-line"} key={`${index >= newFrom ? readNo : 0}-${index}`}>
          {line.timestamp ? (
            <>
              <span className="t-dim">[{line.timestamp}]</span>{" "}
            </>
          ) : null}
          {line.levelText ? (
            <>
              <span className={`ac-lv ac-lv-${line.tone ?? "info"}`}>{line.levelText}</span>{" "}
            </>
          ) : null}
          {line.xray ? <span className="t-prompt">Xray: </span> : null}
          <span className={line.tone === "error" ? "t-err" : undefined}>{line.message}</span>
        </span>
      ))}
    </div>
  );
});
