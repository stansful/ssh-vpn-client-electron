import type { AttentionEvent, DiagnosticsEntry, DiagnosticsSource } from "../../../../shared/types.js";
import { diagnosticSource } from "../../../lib/diagnostics.js";
import { formatClock, formatCount } from "../../../lib/format.js";

export type ActivityLevel = DiagnosticsEntry["level"];
export type LevelFilter = "all" | ActivityLevel;

/** Source chips, in the order the board shows them. */
export const ACTIVITY_SOURCES: readonly DiagnosticsSource[] = ["ssh", "xray", "routing", "update", "app"];

const SOURCE_LABELS: Record<DiagnosticsSource, string> = {
  ssh: "SSH",
  xray: "Xray",
  routing: "Routing",
  update: "Updates",
  app: "App"
};

export function sourceLabel(source: DiagnosticsSource): string {
  return SOURCE_LABELS[source] ?? "App";
}

/**
 * Routine entries a busy session produces by the hundred: per-connection
 * proxy notes, the 30-second traffic summaries and Xray connection notices.
 * Runs of them fold into one row so the events that matter stay visible.
 */
export type RoutineKind = "connection" | "traffic" | "xray";

const CONNECTION_PATTERNS = [
  /^(?:HTTP CONNECT|HTTP proxy|HTTP|SOCKS[45](?: CONNECT)?) .+ from 127\.0\.0\.1:\d+\.$/u,
  /^(?:HTTP CONNECT|HTTP proxy|HTTP|SOCKS[45](?: CONNECT)?) tunnel opened for .+\.$/u,
  /^(?:SOCKS[45]|HTTP) connection from 127\.0\.0\.1:\d+\.$/u,
  /^Accepted local TCP connection from .+\.$/u
];

export function routineKind(entry: Pick<DiagnosticsEntry, "level" | "message">): RoutineKind | undefined {
  if (entry.level !== "info") {
    return undefined;
  }
  const message = entry.message;
  if (message.startsWith("Local proxy activity:")) {
    return "traffic";
  }
  if (/^Xray: \[(?:Info|Debug)\]/u.test(message)) {
    return "xray";
  }
  return CONNECTION_PATTERNS.some((pattern) => pattern.test(message)) ? "connection" : undefined;
}

export interface ActivityEvent {
  entry: DiagnosticsEntry;
  source: DiagnosticsSource;
  routine?: RoutineKind;
}

// Entries keep their identity across snapshot updates, so their events do too (memoized rows stay put).
const eventCache = new WeakMap<DiagnosticsEntry, ActivityEvent>();

/** Diagnostics (oldest first, as the snapshot keeps them) as feed events, newest first. */
export function toActivityEvents(diagnostics: readonly DiagnosticsEntry[]): ActivityEvent[] {
  const events: ActivityEvent[] = [];
  for (let index = diagnostics.length - 1; index >= 0; index -= 1) {
    const entry = diagnostics[index];
    let event = eventCache.get(entry);
    if (!event) {
      event = { entry, source: diagnosticSource(entry), routine: routineKind(entry) };
      eventCache.set(entry, event);
    }
    events.push(event);
  }
  return events;
}

export interface ActivityFilters {
  level: LevelFilter;
  /** Empty means every source. */
  sources: readonly DiagnosticsSource[];
  query: string;
}

export const EMPTY_FILTERS: ActivityFilters = { level: "all", sources: [], query: "" };

export function hasActiveFilters(filters: ActivityFilters): boolean {
  return filters.level !== "all" || filters.sources.length > 0 || filters.query.trim().length > 0;
}

/** Level, source and a case-insensitive search over the message and the source name. */
export function matchesFilters(event: ActivityEvent, filters: ActivityFilters): boolean {
  if (filters.level !== "all" && event.entry.level !== filters.level) {
    return false;
  }
  if (filters.sources.length > 0 && !filters.sources.includes(event.source)) {
    return false;
  }
  const query = filters.query.trim().toLowerCase();
  if (query) {
    const haystack = `${event.entry.message} ${sourceLabel(event.source)}`.toLowerCase();
    if (!haystack.includes(query)) {
      return false;
    }
  }
  return true;
}

export interface ActivityCounts {
  total: number;
  levels: Record<ActivityLevel, number>;
  sources: Record<DiagnosticsSource, number>;
}

export function countEvents(events: readonly ActivityEvent[]): ActivityCounts {
  const counts: ActivityCounts = {
    total: events.length,
    levels: { info: 0, warning: 0, error: 0 },
    sources: { ssh: 0, xray: 0, routing: 0, update: 0, app: 0 }
  };
  for (const event of events) {
    counts.levels[event.entry.level] += 1;
    counts.sources[event.source] += 1;
  }
  return counts;
}

export type FeedItem =
  | { kind: "event"; id: string; event: ActivityEvent }
  /** `events` newest first; the id follows the oldest member so it survives new entries joining at the top. */
  | { kind: "group"; id: string; events: ActivityEvent[] };

/** Shorter runs of routine entries stay as plain rows. */
export const MIN_GROUP_SIZE = 3;

/**
 * Folds runs of routine entries (newest first) into groups. The newest entry
 * of the feed always stays a row, so the latest traffic summary is visible.
 */
export function buildFeed(events: readonly ActivityEvent[], minGroupSize = MIN_GROUP_SIZE): FeedItem[] {
  const items: FeedItem[] = [];
  let run: ActivityEvent[] = [];
  const flush = (): void => {
    if (run.length >= minGroupSize) {
      items.push({ kind: "group", id: `group-${run[run.length - 1].entry.id}`, events: run });
    } else {
      for (const event of run) {
        items.push({ kind: "event", id: event.entry.id, event });
      }
    }
    run = [];
  };
  events.forEach((event, index) => {
    if (index > 0 && event.routine) {
      run.push(event);
      return;
    }
    flush();
    items.push({ kind: "event", id: event.entry.id, event });
  });
  flush();
  return items;
}

const ROUTINE_NOTES: Record<RoutineKind, string> = {
  connection: "proxy connections",
  traffic: "30-second traffic summaries",
  xray: "Xray connection notices"
};

/** "proxy connections and 30-second traffic summaries". */
export function routineNote(events: readonly ActivityEvent[]): string {
  const kinds = (["connection", "traffic", "xray"] as const).filter((kind) => events.some((event) => event.routine === kind));
  const notes = kinds.map((kind) => ROUTINE_NOTES[kind]);
  if (notes.length <= 1) {
    return notes[0] ?? "routine entries";
  }
  return `${notes.slice(0, -1).join(", ")} and ${notes[notes.length - 1]}`;
}

export const GROUP_SAMPLE_COUNT = 4;

export interface GroupSummary {
  /** Local time of the newest entry. */
  time: string;
  countText: string;
  /** "proxy connections and 30-second traffic summaries · 12:12:12 – 12:14:20" */
  note: string;
  samples: Array<{ id: string; time: string; text: string }>;
  /** "and 112 more like these. …" when the samples don't show everything. */
  more?: string;
}

export function summarizeGroup(events: readonly ActivityEvent[]): GroupSummary {
  const newest = events[0];
  const oldest = events[events.length - 1];
  const samples = events.slice(0, GROUP_SAMPLE_COUNT).map((event) => ({
    id: event.entry.id,
    time: formatClock(event.entry.at),
    text: event.entry.message
  }));
  const hidden = events.length - samples.length;
  return {
    time: newest ? formatClock(newest.entry.at) : "",
    countText: `${formatCount(events.length)} routine ${events.length === 1 ? "entry" : "entries"}`,
    note: newest && oldest ? `${routineNote(events)} · ${formatClock(oldest.entry.at)} – ${formatClock(newest.entry.at)}` : routineNote(events),
    samples,
    more: hidden > 0 ? `and ${formatCount(hidden)} more like these. Copy the events to get all of them.` : undefined
  };
}

export interface MessagePart {
  text: string;
  /** Hosts, addresses and ports, set in JetBrains Mono. */
  mono: boolean;
}

const LABEL = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?";
const MONO_PATTERN = new RegExp(
  [
    "\\[[0-9A-Fa-f:.]+\\](?::\\d{1,5})?",
    "\\b(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d{1,5})?\\b",
    `\\b${LABEL}(?:\\.${LABEL})+:\\d{1,5}\\b`
  ].join("|"),
  "gu"
);

/** Splits a message so hosts, IPs and host:port pairs render in mono. */
export function messageParts(message: string): MessagePart[] {
  const parts: MessagePart[] = [];
  let last = 0;
  for (const match of message.matchAll(MONO_PATTERN)) {
    const start = match.index ?? 0;
    if (start > last) {
      parts.push({ text: message.slice(last, start), mono: false });
    }
    parts.push({ text: match[0], mono: true });
    last = start + match[0].length;
  }
  if (last < message.length) {
    parts.push({ text: message.slice(last), mono: false });
  }
  return parts;
}

/** One event as a copied line: "[2026-10-06T12:14:21.000Z] INFO SSH: message". */
export function formatEventLine(event: ActivityEvent): string {
  return `[${event.entry.at}] ${event.entry.level.toUpperCase()} ${sourceLabel(event.source)}: ${event.entry.message}`;
}

/** Events (newest first, as shown) copied oldest first, like a log. */
export function formatEventsForCopy(events: readonly ActivityEvent[]): string {
  return events
    .slice()
    .reverse()
    .map(formatEventLine)
    .join("\n");
}

/**
 * New entries since the feed was paused. Both lists are oldest first; the
 * frozen list's newest entry is looked up in the live one.
 */
export function countNewerThan(frozen: readonly DiagnosticsEntry[], current: readonly DiagnosticsEntry[]): number {
  const lastId = frozen[frozen.length - 1]?.id;
  if (lastId === undefined) {
    return current.length;
  }
  for (let index = current.length - 1; index >= 0; index -= 1) {
    if (current[index].id === lastId) {
      return current.length - 1 - index;
    }
  }
  // Cleared by a new connect (or trimmed): everything there now is new.
  return current.length;
}

export function copyEventsTitle(shown: number, total: number, filtersActive: boolean): string {
  if (filtersActive) {
    return shown === 1 ? "Copy the 1 event that matches" : `Copy the ${formatCount(shown)} events that match`;
  }
  return total === 1 ? "Copy the 1 event" : `Copy all ${formatCount(total)} events`;
}

export function feedFooterText(shown: number, total: number, filtersActive: boolean): string {
  return filtersActive ? `Showing ${formatCount(shown)} of ${formatCount(total)}` : `Showing all ${formatCount(total)}, newest first`;
}

export function sourceChipTitle(source: DiagnosticsSource, count: number, pressed: boolean): string {
  const label = sourceLabel(source);
  if (count === 0 && !pressed) {
    return `No ${label} events in this connection`;
  }
  return pressed ? `Stop filtering by ${label}` : `Show ${label} events`;
}

export interface ActivityReportInput {
  /** Live events, newest first. */
  events: readonly ActivityEvent[];
  attention: readonly Pick<AttentionEvent, "at" | "level" | "title" | "message">[];
  /** main.log tail as read, or undefined when it couldn't be read. */
  logText?: string;
  now?: Date;
}

/** Everything Clear deletes, as one text for a bug report. */
export function formatActivityReport({ events, attention, logText, now = new Date() }: ActivityReportInput): string {
  const sections = [`Shadow SSH activity, copied ${now.toISOString()}`];
  if (attention.length > 0) {
    sections.push(
      [`Needs your attention (${attention.length})`, ...attention.map((event) => `[${event.at}] ${event.level.toUpperCase()} ${event.title}. ${event.message}`)].join("\n")
    );
  }
  sections.push([`Live events (${events.length})`, formatEventsForCopy(events) || "None"].join("\n"));
  sections.push(["main.log (last 1 MB)", logText === undefined ? "Couldn't be read." : logText || "Empty"].join("\n"));
  return sections.join("\n\n");
}
