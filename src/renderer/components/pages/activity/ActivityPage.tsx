import { Activity, Check, Clock, Copy, FileText, Folder, Pause, Play, Trash2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import type { DiagnosticsEntry } from "../../../../shared/types.js";
import { formatClock, formatCount } from "../../../lib/format.js";
import { PageHeader } from "../../shell/index.js";
import { Button, Card, Icon, TabPanel, Tabs, useCopyFeedback, type TabOption } from "../../ui/index.js";
import { RecordingCard, LogFilesCard } from "./ActivityCards.js";
import { AttentionCard } from "./AttentionCard.js";
import { ClearActivityDialog } from "./ClearActivityDialog.js";
import { EventsPanel } from "./EventsPanel.js";
import { LogFilePanel } from "./LogFilePanel.js";
import { sessionStartedAt } from "./activity-attention.js";
import {
  buildFeed,
  copyEventsTitle,
  countEvents,
  countNewerThan,
  EMPTY_FILTERS,
  formatActivityReport,
  formatEventLine,
  formatEventsForCopy,
  hasActiveFilters,
  matchesFilters,
  toActivityEvents,
  type ActivityEvent,
  type ActivityFilters
} from "./activity-feed.js";
import { baseName, clearedToastText, describeLogSize, fileManagerName, withTrailingSeparator } from "./activity-log.js";
import { useLogFile } from "./useLogFile.js";

type ActivityTab = "events" | "log";

const VIEWER_ID = "ac-viewer";

/** main.log and its two archives (the main process rotates into `.1` and `.2`). */
function logFileNamesOf(paths: readonly string[]): string[] {
  if (paths.length >= 3) {
    return paths.slice(0, 3).map(baseName);
  }
  const main = paths[0] ? baseName(paths[0]) : "main.log";
  return [main, `${main}.1`, `${main}.2`];
}

/**
 * Activity: what the tunnel did and why. Live events from this connection
 * (with routine entries folded), the main.log tail, and the attention events
 * that outlive both until dismissed.
 */
export function ActivityPage(): JSX.Element {
  const { snapshot, store, runtime, environment, run, toast, navigate, setSnapshot, updateSettings, copyText } = useAppData();
  const settings = store.settings;
  const liveOn = settings.diagnosticsLoggingEnabled;
  const fileOn = settings.fileLoggingEnabled;

  const [tab, setTab] = useState<ActivityTab>("events");
  const [filters, setFilters] = useState<ActivityFilters>(EMPTY_FILTERS);
  const [frozen, setFrozen] = useState<DiagnosticsEntry[] | null>(null);
  const [openGroups, setOpenGroups] = useState<ReadonlySet<string>>(() => new Set());
  const [clearOpen, setClearOpen] = useState(false);
  const [cleared, setCleared] = useState(false);
  const log = useLogFile();
  const { refresh: refreshLog } = log;
  const { copied: mainCopied, copy: copyMain } = useCopyFeedback();

  // Read main.log once for the sizes on this page; the Log file tab reads again when opened.
  useEffect(() => {
    void refreshLog();
  }, [refreshLog]);

  // Pausing only makes sense while events are recorded.
  useEffect(() => {
    if (!liveOn) {
      setFrozen(null);
    }
  }, [liveOn]);

  const paused = liveOn && frozen !== null;
  const diagnostics = paused && frozen ? frozen : snapshot.diagnostics;
  const events = useMemo(() => toActivityEvents(diagnostics), [diagnostics]);
  const counts = useMemo(() => countEvents(events), [events]);
  const shownEvents = useMemo(() => events.filter((event) => matchesFilters(event, filters)), [events, filters]);
  const feed = useMemo(() => buildFeed(shownEvents), [shownEvents]);
  const pending = paused && frozen ? countNewerThan(frozen, snapshot.diagnostics) : 0;
  const filtersActive = hasActiveFilters(filters);

  const logSize = describeLogSize(log.read, log.files);
  const logFileNames = logFileNamesOf(snapshot.logFilePaths);
  const mainLogPath = snapshot.logFilePaths[0] ?? `${withTrailingSeparator(environment.logDirectory)}main.log`;
  const fileManager = fileManagerName(environment.platform);
  const sessionStart = sessionStartedAt(runtime.state, runtime.connectedAt, snapshot.diagnostics);

  const isEvents = tab === "events";
  const copyDisabled = isEvents ? shownEvents.length === 0 : log.read?.state !== "lines";
  const copyTitle = isEvents ? copyEventsTitle(shownEvents.length, counts.total, filtersActive) : "Copy the last 1 MB of main.log";
  const logKnownEmpty = log.read?.state === "empty";
  const clearDisabled = snapshot.diagnostics.length === 0 && snapshot.attention.length === 0 && logKnownEmpty;

  const changeTab = (next: ActivityTab): void => {
    setTab(next);
    if (next === "log") {
      void refreshLog();
    }
  };

  const copyCurrent = (): void => {
    if (isEvents) {
      void copyMain(formatEventsForCopy(shownEvents));
    } else if (log.read?.state === "lines") {
      void copyMain(log.read.text);
    }
  };

  const openLogFolder = async (): Promise<void> => {
    const opened = await run(() => api.openLogFolder(), { errorTitle: "Couldn’t open the log folder" });
    if (opened === true) {
      const who = fileManager.charAt(0).toUpperCase() + fileManager.slice(1);
      toast({
        tone: "info",
        title: "Log folder opened",
        message: `${who} is showing main.log${logSize.archives === "none" ? "" : " and its archives"}.`
      });
    } else if (opened === false) {
      toast({
        tone: "error",
        title: "Couldn’t open the log folder",
        message: `It may have been moved or deleted. The logs are kept in ${environment.logDirectory}.`
      });
    }
  };

  const setLive = (on: boolean): void => {
    if (!on) {
      setFrozen(null);
    }
    void updateSettings({ diagnosticsLoggingEnabled: on });
  };
  const setFile = (on: boolean): void => {
    void updateSettings({ fileLoggingEnabled: on });
  };

  const togglePause = (): void => {
    setFrozen((current) => (current ? null : snapshot.diagnostics));
  };

  const toggleGroup = useCallback((id: string): void => {
    setOpenGroups((current) => {
      const next = new Set(current);
      if (!next.delete(id)) {
        next.add(id);
      }
      return next;
    });
  }, []);

  const copyEvent = useCallback((event: ActivityEvent) => copyText(formatEventLine(event)), [copyText]);

  const dismissAttention = useCallback(
    async (id?: string): Promise<boolean> => {
      const result = await run(() => api.dismissAttention(id), { errorTitle: "Couldn’t dismiss that event" });
      return result !== undefined;
    },
    [run]
  );

  const copyEverything = async (): Promise<boolean> => {
    const fresh = await refreshLog();
    const logText = fresh?.state === "lines" ? fresh.text : fresh?.state === "empty" ? "" : undefined;
    return copyText(
      formatActivityReport({ events: toActivityEvents(snapshot.diagnostics), attention: snapshot.attention, logText })
    );
  };

  const clearActivity = async (): Promise<void> => {
    const summary = {
      liveCount: snapshot.diagnostics.length,
      attentionCount: snapshot.attention.length,
      archives: logSize.archives,
      archiveCount: logSize.archiveCount
    };
    log.replace(await api.clearLogFile());
    let next = await api.clearDiagnostics();
    // Clearing also clears what Activity was asked to keep (the main process does it too).
    if (next.attention.length > 0) {
      next = await api.dismissAttention();
    }
    setSnapshot(next);
    setFrozen(null);
    setFilters(EMPTY_FILTERS);
    setOpenGroups(new Set());
    setCleared(true);
    toast({ tone: "success", title: "Activity cleared", message: clearedToastText(summary) });
  };

  const liveState = !liveOn ? "off" : paused ? "paused" : "live";
  const logTabCount = logSize.tabCount;
  // Stable while the counts hold, so the tab ink isn't re-measured on every live event.
  const tabOptions = useMemo<ReadonlyArray<TabOption<ActivityTab>>>(
    () => [
      { value: "events", label: "Events", icon: Activity, count: counts.total },
      {
        value: "log",
        label: (
          <>
            Log file
            {logTabCount ? <span className="count">{logTabCount}</span> : null}
          </>
        ),
        icon: FileText
      }
    ],
    [counts.total, logTabCount]
  );

  let readText = "Not read yet";
  if (log.reading) {
    readText = "Reading main.log…";
  } else if (log.read?.state === "error" && log.readAt) {
    readText = `Last read failed at ${formatClock(log.readAt)}`;
  } else if (log.readAt) {
    readText = `Read at ${formatClock(log.readAt)} · updates on Refresh`;
  }

  return (
    <>
      <PageHeader
        eyebrow="App"
        title="Activity"
        sub="What the tunnel did and why: live events from this connection, plus the log file Shadow SSH keeps on disk."
        className="ac-topbar"
        actions={
          <>
            <Button
              variant={mainCopied ? "ok" : "secondary"}
              icon={mainCopied ? Check : Copy}
              title={copyTitle}
              aria-label={mainCopied ? "Copied" : copyTitle}
              disabled={copyDisabled}
              onClick={copyCurrent}
            >
              <span className="btn-label-swap" key={mainCopied ? "copied" : "copy"}>
                {mainCopied ? "Copied" : "Copy"}
              </span>
            </Button>
            <Button icon={Folder} title={`Show the logs folder in ${fileManager}`} onClick={() => void openLogFolder()}>
              Open log folder
            </Button>
            <Button variant="danger-ghost" icon={Trash2} disabled={clearDisabled} onClick={() => setClearOpen(true)}>
              Clear…
            </Button>
          </>
        }
      />

      {snapshot.attention.length > 0 ? (
        <AttentionCard events={snapshot.attention} sessionStart={sessionStart} onDismiss={dismissAttention} navigate={navigate} />
      ) : null}

      <Card rise={2} className="ac-viewer" aria-label="Activity">
        <div className="ac-vhead">
          <Tabs id={VIEWER_ID} value={tab} options={tabOptions} onChange={changeTab} ariaLabel="Activity views" />
          {isEvents ? (
            <div className="ac-live">
              <span className="ac-livedot" data-state={liveState} aria-hidden="true" />
              <span className="ac-live-label">{liveState === "off" ? "Not recording" : liveState === "paused" ? "Paused" : "Live"}</span>
              <span>
                {formatCount(counts.total)} {counts.total === 1 ? "event" : "events"} this session · {liveOn ? "cleared on each connect" : "recording is off"}
              </span>
              <Button variant="ghost" size="sm" icon={paused ? Play : Pause} aria-pressed={paused} disabled={!liveOn} onClick={togglePause}>
                {paused ? (pending > 0 ? `Resume · ${formatCount(pending)} new` : "Resume") : "Pause"}
              </Button>
            </div>
          ) : (
            <div className="ac-live">
              <Icon icon={Clock} size="sm" />
              <span>{readText}</span>
            </div>
          )}
        </div>

        <TabPanel id={VIEWER_ID} value={tab} className="ac-panel">
          {isEvents ? (
            <EventsPanel
              liveOn={liveOn}
              onTurnOnLive={() => setLive(true)}
              filters={filters}
              onFiltersChange={setFilters}
              filtersActive={filtersActive}
              counts={counts}
              feed={feed}
              shownCount={shownEvents.length}
              openGroups={openGroups}
              onToggleGroup={toggleGroup}
              onCopyEvent={copyEvent}
            />
          ) : (
            <LogFilePanel
              read={log.read}
              reading={log.reading}
              readNo={log.readNo}
              newFrom={log.newFrom}
              path={mainLogPath}
              size={logSize}
              fileOn={fileOn}
              onTurnOnFile={() => setFile(true)}
              onRefresh={() => void refreshLog()}
            />
          )}
        </TabPanel>
      </Card>

      <div className="split-even">
        <RecordingCard
          liveOn={liveOn}
          fileOn={fileOn}
          onLiveChange={setLive}
          onFileChange={setFile}
          onOpenDiagnostics={() => navigate("settings", { type: "settings-section", section: "diagnostics" })}
        />
        <LogFilesCard directory={withTrailingSeparator(environment.logDirectory)} fileNames={logFileNames} size={logSize} cleared={cleared} />
      </div>

      <ClearActivityDialog
        open={clearOpen}
        onClose={() => setClearOpen(false)}
        liveCount={snapshot.diagnostics.length}
        attentionCount={snapshot.attention.length}
        size={logSize}
        fileNames={logFileNames}
        onClear={clearActivity}
        onCopyEverything={copyEverything}
      />
    </>
  );
}
