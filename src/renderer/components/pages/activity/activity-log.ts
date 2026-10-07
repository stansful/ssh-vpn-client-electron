import type { DesktopPlatform, LogFileInfo } from "../../../../shared/types.js";

/** main.log becomes an archive at this size (see the main process logger). */
export const LOG_FILE_LIMIT_BYTES = 5 * 1024 * 1024;
/** readLogFile returns at most this much, across main.log and its archives. */
export const LOG_READ_LIMIT_BYTES = 1024 * 1024;
/** The logger caps one message at 64 K characters; a read this close to the limit was cut. */
const TRUNCATION_MARGIN_BYTES = 64 * 1024;

const READ_ERROR_PREFIX = "Unable to read log file:";

export type LogTone = "info" | "warn" | "error";

export interface LogLine {
  raw: string;
  /** ISO timestamp as written, without the brackets. */
  timestamp?: string;
  /** INFO, WARNING, ERROR or ATTENTION as written. */
  levelText?: string;
  tone?: LogTone;
  /** The line came from the Xray process ("Xray: " prefix). */
  xray: boolean;
  /** Message after the level and the Xray prefix. */
  message: string;
}

export type LogRead =
  | { state: "empty"; path?: string }
  | { state: "lines"; path?: string; text: string; lines: LogLine[]; bytes: number; truncated: boolean }
  | { state: "error"; path?: string; message: string; details: string[] };

const LINE_PATTERN = /^\[(\d{4}-\d{2}-\d{2}T[^\]\s]+)\]\s+(?:(INFO|WARNING|WARN|ERROR|ATTENTION)\s+)?(.*)$/u;

export function parseLogLine(raw: string): LogLine {
  const match = LINE_PATTERN.exec(raw);
  if (!match) {
    return { raw, xray: false, message: raw };
  }
  const [, timestamp, levelText, rest] = match;
  const xray = rest.startsWith("Xray: ");
  return {
    raw,
    timestamp,
    levelText,
    tone: levelText ? toneOf(levelText) : undefined,
    xray,
    message: xray ? rest.slice("Xray: ".length) : rest
  };
}

function toneOf(levelText: string): LogTone {
  if (levelText === "ERROR") {
    return "error";
  }
  return levelText === "WARNING" || levelText === "WARN" || levelText === "ATTENTION" ? "warn" : "info";
}

function utf8Length(text: string): number {
  return new TextEncoder().encode(text).length;
}

/**
 * Parses what `readLogFile()` returns: an optional "### <path>" header, then
 * the tail of main.log and its archives, or "Unable to read log file: …".
 */
export function parseLogContent(content: string): LogRead {
  let body = content.replace(/\r\n/gu, "\n");
  let path: string | undefined;
  if (body.startsWith("### ")) {
    const end = body.indexOf("\n");
    path = (end === -1 ? body.slice(4) : body.slice(4, end)).trim() || undefined;
    body = end === -1 ? "" : body.slice(end + 1);
  }
  body = body.replace(/\s+$/u, "");
  if (body.startsWith(READ_ERROR_PREFIX)) {
    const message = body.slice(READ_ERROR_PREFIX.length).trim();
    return { state: "error", path, message, details: body.split("\n") };
  }
  if (!body.trim()) {
    return { state: "empty", path };
  }
  const lines = body.split("\n").filter((line) => line.length > 0).map(parseLogLine);
  const bytes = utf8Length(body);
  return { state: "lines", path, text: body, lines, bytes, truncated: bytes >= LOG_READ_LIMIT_BYTES - TRUNCATION_MARGIN_BYTES };
}

/** A failed IPC call (not a failed file read) in the same shape. */
export function logReadFailure(message: string, technical?: string, path?: string): LogRead {
  return { state: "error", path, message, details: [technical ?? message] };
}

/**
 * Index of the first line that wasn't there in the previous read (the lines
 * after the previous last line). Nothing is new on the first read.
 */
export function firstNewLine(previous: LogRead | undefined, next: LogRead): number {
  if (next.state !== "lines") {
    return 0;
  }
  if (!previous || previous.state === "error") {
    return next.lines.length;
  }
  if (previous.state === "empty") {
    return 0;
  }
  const last = previous.lines[previous.lines.length - 1]?.raw;
  for (let index = next.lines.length - 1; index >= 0; index -= 1) {
    if (next.lines[index].raw === last) {
      return index + 1;
    }
  }
  // The previous tail is gone (cleared or rotated out of the last 1 MB).
  return 0;
}

/** Binary sizes to match the 1 MB read and 5 MB rotation limits: "0 KB", "12.4 KB", "1.2 MB". */
export function formatLogSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 KB";
  }
  if (bytes < 1000 * 1024) {
    const kb = bytes / 1024;
    return `${kb < 10 ? Math.max(0.1, Math.round(kb * 10) / 10).toFixed(1) : Math.round(kb)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export interface LogSizeInfo {
  /** Size of main.log, when the read could tell. */
  mainSize?: string;
  /**
   * "none": no archives exist; "present": `archiveCount` archives exist (sizes known);
   * "maybe": main.log is past the read limit, archives may exist; "unknown": not read.
   */
  archives: "none" | "present" | "maybe" | "unknown";
  /** Archives on disk, when the file sizes are known. */
  archiveCount?: number;
  /** Size of main.log.1, main.log.2… in order; undefined for one that doesn't exist. */
  archiveSizes?: Array<string | undefined>;
  /** "1.2 MB of 5 MB · no archives". */
  meta?: string;
  /** Fill of the 5 MB rotation limit, when known. */
  capPercent?: number;
  /** Text for the Log file tab count. */
  tabCount?: string;
}

function archivesText(count: number): string {
  return count === 0 ? "no archives" : count === 1 ? "1 archive" : `${count} archives`;
}

/**
 * Sizes for the Log file tab, the Log files card and the Clear dialog. With
 * the files' sizes from disk (`getLogFileInfo`) they are exact. Without them,
 * the read is all there is: it returns the last 1 MB across main.log and its
 * archives. Below that, it is the whole log, and archives (made at 5 MB)
 * can't exist; at the limit only "1 MB or more" is known.
 */
export function describeLogSize(read: LogRead | undefined, files?: readonly LogFileInfo[]): LogSizeInfo {
  if (files && files.length > 0) {
    const [main, ...archives] = files;
    const count = archives.filter((file) => file.exists).length;
    const mainSize = formatLogSize(main.size);
    return {
      mainSize,
      archives: count > 0 ? "present" : "none",
      archiveCount: count,
      archiveSizes: archives.map((file) => (file.exists ? formatLogSize(file.size) : undefined)),
      meta: `${mainSize} of 5 MB · ${archivesText(count)}`,
      capPercent: Math.min(100, (main.size / LOG_FILE_LIMIT_BYTES) * 100),
      tabCount: main.size === 0 && count === 0 ? "Empty" : mainSize
    };
  }
  if (!read || read.state === "error") {
    return { archives: "unknown" };
  }
  if (read.state === "empty") {
    return { mainSize: "0 KB", archives: "none", meta: "0 KB of 5 MB · no archives", capPercent: 0, tabCount: "Empty" };
  }
  if (read.truncated) {
    return { mainSize: "1 MB or more", archives: "maybe", meta: "1 MB or more · only the last 1 MB is shown", tabCount: "1 MB+" };
  }
  const size = formatLogSize(read.bytes);
  return {
    mainSize: size,
    archives: "none",
    meta: `${size} of 5 MB · no archives`,
    capPercent: Math.min(100, (read.bytes / LOG_FILE_LIMIT_BYTES) * 100),
    tabCount: size
  };
}

function hoursText(totalMinutes: number): string {
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  const hourPart = hours > 0 ? `${hours} ${hours === 1 ? "hour" : "hours"}` : "";
  const minutePart = minutes > 0 ? `${minutes} ${minutes === 1 ? "minute" : "minutes"}` : "";
  return [hourPart, minutePart].filter(Boolean).join(" ");
}

/** "Times are UTC, 3 hours behind your clock." for the local time zone of `date`. */
export function utcOffsetNote(date: Date = new Date()): string {
  const ahead = -date.getTimezoneOffset();
  if (ahead === 0) {
    return "Times are UTC, the same as your clock.";
  }
  return `Times are UTC, ${hoursText(Math.abs(ahead))} ${ahead > 0 ? "behind" : "ahead of"} your clock.`;
}

/** Where "Open log folder" shows the files. */
export function fileManagerName(platform: DesktopPlatform): string {
  if (platform === "windows") {
    return "File Explorer";
  }
  return platform === "macos" ? "Finder" : "your file manager";
}

/** Last path segment for either separator. */
export function baseName(path: string): string {
  const parts = path.split(/[\\/]/u).filter(Boolean);
  return parts[parts.length - 1] ?? path;
}

/** Directory with a trailing separator, as the board shows it. */
export function withTrailingSeparator(directory: string): string {
  if (!directory || /[\\/]$/u.test(directory)) {
    return directory;
  }
  return `${directory}${directory.includes("\\") ? "\\" : "/"}`;
}

export interface ClearSummaryInput {
  liveCount: number;
  attentionCount: number;
  archives: LogSizeInfo["archives"];
  archiveCount?: number;
}

/** "main.log", "main.log, its 2 archives" or "main.log, its archives" when the count isn't known. */
function deletedFilesText(archives: LogSizeInfo["archives"], archiveCount: number | undefined, joiner: ", " | " and "): string {
  if (archives === "none") {
    return "main.log";
  }
  const its = archives === "present" && archiveCount ? (archiveCount === 1 ? "its archive" : `its ${archiveCount} archives`) : "its archives";
  return `main.log${joiner}${its}`;
}

function eventsText(count: number): string {
  return count === 1 ? "1 live event" : `${count.toLocaleString("en-US")} live events`;
}

/** Description of the Clear confirmation. */
export function clearDescription({ liveCount, archives, archiveCount }: ClearSummaryInput): string {
  if (liveCount === 0) {
    return archives === "none"
      ? "This empties main.log. It can’t be undone."
      : `This deletes ${deletedFilesText(archives, archiveCount, " and ")}. It can’t be undone.`;
  }
  return `This deletes ${deletedFilesText(archives, archiveCount, ", ")} and the ${eventsText(liveCount)} from this session. It can’t be undone.`;
}

/** Text of the "Activity cleared" toast. */
export function clearedToastText({ liveCount, archives, archiveCount }: ClearSummaryInput): string {
  const events = liveCount === 1 ? "1 event" : `${liveCount.toLocaleString("en-US")} events`;
  if (archives === "none") {
    return liveCount > 0 ? `main.log and ${events} were deleted.` : "main.log was emptied.";
  }
  return liveCount > 0
    ? `${deletedFilesText(archives, archiveCount, ", ")} and ${events} were deleted.`
    : `${deletedFilesText(archives, archiveCount, " and ")} were deleted.`;
}
