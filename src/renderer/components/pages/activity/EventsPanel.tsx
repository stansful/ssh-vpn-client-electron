import { Activity, Check, ChevronDown, Copy, List, Search, TriangleAlert } from "lucide-react";
import { memo, useCallback, useEffect, useId, useRef, useState, type CSSProperties } from "react";
import type { DiagnosticsSource } from "../../../../shared/types.js";
import { formatClock, formatCount } from "../../../lib/format.js";
import { Button, Callout, Collapse, EmptyState, Icon, IconButton, LevelPill, LinkButton, SearchInput, Segmented, type SegmentedOption } from "../../ui/index.js";
import {
  ACTIVITY_SOURCES,
  EMPTY_FILTERS,
  feedFooterText,
  messageParts,
  sourceChipTitle,
  sourceLabel,
  summarizeGroup,
  type ActivityCounts,
  type ActivityEvent,
  type ActivityFilters,
  type FeedItem,
  type LevelFilter
} from "./activity-feed.js";

const ROW_COPIED_MS = 1400;
/** Entrance stagger stops after this many rows. */
const MAX_STAGGER = 16;

export interface EventsPanelProps {
  liveOn: boolean;
  onTurnOnLive: () => void;
  filters: ActivityFilters;
  onFiltersChange: (filters: ActivityFilters) => void;
  filtersActive: boolean;
  /** Counts over every event in the feed (before filters). */
  counts: ActivityCounts;
  feed: FeedItem[];
  shownCount: number;
  openGroups: ReadonlySet<string>;
  onToggleGroup: (id: string) => void;
  onCopyEvent: (event: ActivityEvent) => Promise<boolean>;
}

/** Events tab: level, search and source filters over the live feed, newest first. */
export function EventsPanel({
  liveOn,
  onTurnOnLive,
  filters,
  onFiltersChange,
  filtersActive,
  counts,
  feed,
  shownCount,
  openGroups,
  onToggleGroup,
  onCopyEvent
}: EventsPanelProps): JSX.Element {
  const searchId = useId();
  const [copiedId, setCopiedId] = useState<string>();
  const copiedTimer = useRef<number>();

  useEffect(() => () => window.clearTimeout(copiedTimer.current), []);

  const copyEvent = useCallback(
    (event: ActivityEvent): void => {
      void onCopyEvent(event).then((ok) => {
        if (!ok) {
          return;
        }
        setCopiedId(event.entry.id);
        window.clearTimeout(copiedTimer.current);
        copiedTimer.current = window.setTimeout(() => setCopiedId(undefined), ROW_COPIED_MS);
      });
    },
    [onCopyEvent]
  );

  const resetFilters = (): void => onFiltersChange(EMPTY_FILTERS);

  const toggleSource = (source: DiagnosticsSource): void => {
    const on = filters.sources.includes(source);
    onFiltersChange({ ...filters, sources: on ? filters.sources.filter((candidate) => candidate !== source) : [...filters.sources, source] });
  };

  const levelOptions: ReadonlyArray<SegmentedOption<LevelFilter>> = [
    { value: "all", label: "All" },
    { value: "info", label: "Info" },
    {
      value: "warning",
      label: (
        <>
          Warnings <span className="ac-segn t-warn">{formatCount(counts.levels.warning)}</span>
        </>
      ),
      ariaLabel: `Warnings, ${counts.levels.warning}`
    },
    {
      value: "error",
      label: (
        <>
          Errors <span className="ac-segn t-danger">{formatCount(counts.levels.error)}</span>
        </>
      ),
      ariaLabel: `Errors, ${counts.levels.error}`
    }
  ];

  return (
    <>
      {!liveOn ? (
        <Callout
          tone="warn"
          icon={TriangleAlert}
          title="Live events are off"
          actions={
            <Button size="sm" onClick={onTurnOnLive}>
              Turn on
            </Button>
          }
        >
          New events aren’t kept, including ones that never reach the log file, like why a tunnel was closed. What’s below stays until you clear it.
        </Callout>
      ) : null}

      <div className="ac-filters">
        <Segmented
          size="sm"
          className="ac-levels"
          ariaLabel="Level"
          value={filters.level}
          options={levelOptions}
          onChange={(level) => onFiltersChange({ ...filters, level })}
        />
        <div className="ac-search">
          <label className="sr-only" htmlFor={searchId}>
            Search events
          </label>
          <SearchInput
            id={searchId}
            value={filters.query}
            onValueChange={(query) => onFiltersChange({ ...filters, query })}
            placeholder="Search messages, hosts, ports"
            autoComplete="off"
          />
        </div>
        <div className="ac-chips" role="group" aria-label="Source">
          <span className="ac-chips-label" aria-hidden="true">
            Source
          </span>
          {ACTIVITY_SOURCES.map((source) => {
            const count = counts.sources[source];
            const pressed = filters.sources.includes(source);
            return (
              <button
                key={source}
                type="button"
                className="ac-chip"
                aria-pressed={pressed}
                disabled={count === 0 && !pressed}
                title={sourceChipTitle(source, count, pressed)}
                onClick={() => toggleSource(source)}
              >
                <Icon icon={Check} className="ac-tick" />
                {sourceLabel(source)} <span className="ac-n">{formatCount(count)}</span>
              </button>
            );
          })}
        </div>
      </div>

      {feed.length > 0 ? (
        <div className="ac-feed" role="log" aria-label="Events, newest first" aria-live="polite">
          {feed.map((item, index) =>
            item.kind === "event" ? (
              <EventRow
                key={item.id}
                event={item.event}
                delay={Math.min(index, MAX_STAGGER)}
                copied={copiedId === item.event.entry.id}
                onCopy={copyEvent}
              />
            ) : (
              <GroupRow key={item.id} id={item.id} events={item.events} delay={Math.min(index, MAX_STAGGER)} open={openGroups.has(item.id)} onToggle={onToggleGroup} />
            )
          )}
        </div>
      ) : null}

      {counts.total === 0 ? (
        <EmptyState icon={Activity} title="No events yet" className="fade">
          New events show up here as Shadow connects, checks the tunnel and changes routing.
        </EmptyState>
      ) : feed.length === 0 ? (
        <EmptyState
          icon={Search}
          title="Nothing matches"
          className="fade"
          action={
            <Button size="sm" onClick={resetFilters}>
              Reset filters
            </Button>
          }
        >
          No events from this connection match these filters. Try another level or source, or clear the search.
        </EmptyState>
      ) : null}

      <div className="ac-foot">
        <span>{feedFooterText(shownCount, counts.total, filtersActive)}</span>
        {filtersActive ? (
          <LinkButton icon={null} onClick={resetFilters}>
            Reset filters
          </LinkButton>
        ) : null}
        <span className="spacer" />
        <span>Your local time · hover a row to copy it</span>
      </div>
    </>
  );
}

interface EventRowProps {
  event: ActivityEvent;
  delay: number;
  copied: boolean;
  onCopy: (event: ActivityEvent) => void;
}

const EventRow = memo(function EventRow({ event, delay, copied, onCopy }: EventRowProps): JSX.Element {
  const time = formatClock(event.entry.at);
  return (
    <div className="ac-row" data-lvl={event.entry.level} style={{ "--d": delay } as CSSProperties}>
      <span className="ac-time">{time}</span>
      <LevelPill level={event.entry.level} />
      <span className="ac-src">{sourceLabel(event.source)}</span>
      <span className="ac-msg">
        {messageParts(event.entry.message).map((part, index) =>
          part.mono ? (
            <span className="mono" key={index}>
              {part.text}
            </span>
          ) : (
            <span key={index}>{part.text}</span>
          )
        )}
      </span>
      <IconButton
        icon={Copy}
        label={`Copy event from ${time}`}
        tooltip={copied ? "Copied" : "Copy line"}
        done={copied}
        className="ac-copy"
        data-done={copied ? "true" : "false"}
        onClick={() => onCopy(event)}
      />
    </div>
  );
});

interface GroupRowProps {
  id: string;
  events: ActivityEvent[];
  delay: number;
  open: boolean;
  onToggle: (id: string) => void;
}

const GroupRow = memo(function GroupRow({ id, events, delay, open, onToggle }: GroupRowProps): JSX.Element {
  const samplesId = useId();
  const summary = summarizeGroup(events);
  return (
    <div className="ac-group" data-open={open ? "true" : "false"} style={{ "--d": delay } as CSSProperties}>
      <button type="button" className="ac-group-btn" aria-expanded={open} aria-controls={samplesId} onClick={() => onToggle(id)}>
        <span className="ac-time">{summary.time}</span>
        <span className="ac-group-label">
          <Icon icon={List} size="sm" />
          <span className="ac-group-count">{summary.countText}</span>
          <span>{summary.note}</span>
        </span>
        <span className="ac-group-more">
          {open ? "Hide" : "Show"}
          <Icon icon={ChevronDown} size="sm" className="chev" />
        </span>
      </button>
      <Collapse open={open} id={samplesId}>
        <div className="ac-samples">
          {summary.samples.map((sample) => (
            <div className="ac-sample" key={sample.id}>
              <span>{sample.time}</span>
              <span>{sample.text}</span>
            </div>
          ))}
          {summary.more ? <span className="ac-sample-more">{summary.more}</span> : null}
        </div>
      </Collapse>
    </div>
  );
});
