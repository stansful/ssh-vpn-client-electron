import type { ImportProxyProfilesResult, ProxyProfile } from "../../../../shared/types.js";
import { formatCount, plural } from "../../../lib/format.js";
import {
  applySchemeFix,
  importFailureHint,
  importFailureMessage,
  linkFingerprint,
  MAX_IMPORT_LINES,
  MAX_IMPORT_TEXT_LENGTH,
  MAX_STORED_PROFILES,
  parseShareLink
} from "./link-preview.js";

/**
 * The Links box: its text and, after a partial import, the original line
 * number of each line it still holds (so "Line 4" keeps meaning line 4 of
 * what the person pasted). `lineNumbers` is null for plain 1..n numbering.
 */
export interface ImportBox {
  text: string;
  lineNumbers: number[] | null;
}

export const EMPTY_IMPORT_BOX: ImportBox = { text: "", lineNumbers: null };

export function splitLines(text: string): string[] {
  return text.split(/\r?\n/u);
}

/** Rows the textarea shows (a trailing newline adds an empty row for the caret). */
export function visualLineCount(text: string): number {
  return splitLines(text).length;
}

/** Blank lines at the end only inflate the skipped count and can trip the line limit. */
export function trimTrailingBlankLines(text: string): string {
  return text.replace(/(?:\r?\n[ \t]*)+$/u, "");
}

/** Lines that hold something, not counting blank lines at the end. */
export function contentLineCount(text: string): number {
  const trimmed = trimTrailingBlankLines(text);
  return trimmed.trim() === "" ? 0 : splitLines(trimmed).length;
}

/** Number shown in the gutter for row `index` (0-based). */
export function gutterNumber(box: ImportBox, index: number): number {
  return box.lineNumbers?.[index] ?? index + 1;
}

/** Typing keeps the original numbering as long as the number of rows stays the same. */
export function editImportBox(box: ImportBox, text: string): ImportBox {
  if (box.lineNumbers && visualLineCount(text) === box.lineNumbers.length) {
    return { text, lineNumbers: box.lineNumbers };
  }
  return { text, lineNumbers: null };
}

/** "line 4", "lines 4 and 9", "lines 4, 9 and 12", "lines 4, 9, 12 and 3 more". */
export function describeLineNumbers(numbers: readonly number[]): string {
  const shown = numbers.slice(0, 3).map((value) => formatCount(value));
  if (numbers.length === 0) {
    return "";
  }
  if (numbers.length === 1) {
    return `line ${shown[0]}`;
  }
  if (numbers.length <= 3) {
    return `lines ${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}`;
  }
  return `lines ${shown.join(", ")} and ${formatCount(numbers.length - 3)} more`;
}

export interface LinesHint {
  text: string;
  /** The box can't be imported as it is. */
  blocked?: boolean;
  /** Over a limit the import will enforce. */
  tone?: "danger";
}

/** Hint next to the Links label: "6 lines · up to 10,000", "1 line kept · line 4", "Empty". */
export function linesHint(box: ImportBox): LinesHint {
  if (box.text.length > MAX_IMPORT_TEXT_LENGTH) {
    return { text: "Over 2 MB of text · split it into smaller batches", tone: "danger", blocked: true };
  }
  const count = contentLineCount(box.text);
  if (count === 0) {
    return { text: "Empty", blocked: true };
  }
  if (box.lineNumbers) {
    return { text: `${plural(count, "line")} kept · ${describeLineNumbers(box.lineNumbers.slice(0, count))}` };
  }
  if (count > MAX_IMPORT_LINES) {
    return { text: `${formatCount(count)} lines · only the first 10,000 are read`, tone: "danger" };
  }
  return { text: `${plural(count, "line")} · up to 10,000` };
}

export interface ImportFailureItem {
  /** Line number in what the person pasted. */
  line: number;
  message: string;
  /** The failed line as it was sent. */
  text: string;
  hint?: string;
  fix?: { from: string; to: string };
}

export type ImportOutcome = "clean" | "nothing" | "partial" | "failed";

export interface ImportReport {
  imported: number;
  updated: number;
  skipped: number;
  failed: number;
  outcome: ImportOutcome;
  title: string;
  /** "Imported 3 · Updated 1 · Skipped 1 · Failed 1". */
  countsLine: string;
  /** Failed lines the main process named ("Line N: …"), in line order. */
  failures: ImportFailureItem[];
  /** Problems that aren't about one line (line or size limits). */
  general: string[];
  /** Failed lines beyond the ones listed (the main process names up to 500). */
  unlisted: number;
  /** Failed and ignored lines, for "Keep failed lines in the box". */
  kept: ImportBox;
}

const LINE_ERROR = /^Line (\d+): ([\s\S]*)$/u;

/** Turns the main process's import result into what the dialog lists and keeps. */
export function buildImportReport(sent: ImportBox, result: ImportProxyProfilesResult): ImportReport {
  const lines = splitLines(sent.text);
  const failures: ImportFailureItem[] = [];
  const general: string[] = [];
  const keptRows = new Set<number>();

  for (const error of result.errors) {
    const match = LINE_ERROR.exec(error);
    const row = match ? Number(match[1]) : Number.NaN;
    if (!match || !Number.isInteger(row) || row < 1 || row > lines.length) {
      general.push(generalImportMessage(error));
      continue;
    }
    const text = lines[row - 1] ?? "";
    const hint = importFailureHint(text.trim());
    failures.push({ line: gutterNumber(sent, row - 1), message: importFailureMessage(match[2]), text, hint: hint?.hint, fix: hint?.fix });
    keptRows.add(row);
  }

  const unlisted = Math.max(0, result.failed - result.errors.length);
  if (unlisted > 0) {
    // The list stops at 500; find the rest the same way the parser does.
    const lastListed = failures.reduce((max, item) => Math.max(max, rowOfLine(sent, item.line)), 0);
    for (let row = lastListed + 1; row <= Math.min(lines.length, MAX_IMPORT_LINES); row += 1) {
      if (isLinkLine(lines[row - 1]) && !parses(lines[row - 1].trim())) {
        keptRows.add(row);
      }
    }
  }
  for (let row = MAX_IMPORT_LINES + 1; row <= lines.length; row += 1) {
    if (isLinkLine(lines[row - 1])) {
      keptRows.add(row);
    }
  }

  const rows = [...keptRows].sort((left, right) => left - right);
  const kept: ImportBox = {
    text: rows.map((row) => lines[row - 1]).join("\n"),
    lineNumbers: rows.map((row) => gutterNumber(sent, row - 1))
  };
  failures.sort((left, right) => left.line - right.line);

  const total = result.imported + result.updated;
  let outcome: ImportOutcome;
  let title: string;
  if (result.failed === 0) {
    outcome = total > 0 ? "clean" : "nothing";
    title = total > 0 ? "All lines imported" : "Nothing to import";
  } else if (total > 0) {
    outcome = "partial";
    title = `Imported with ${plural(result.failed, "problem")}`;
  } else {
    outcome = "failed";
    title = "Nothing was imported";
  }

  return {
    imported: result.imported,
    updated: result.updated,
    skipped: result.skipped,
    failed: result.failed,
    outcome,
    title,
    countsLine: `Imported ${formatCount(result.imported)} · Updated ${formatCount(result.updated)} · Skipped ${formatCount(result.skipped)} · Failed ${formatCount(result.failed)}`,
    failures,
    general,
    unlisted,
    kept: rows.length > 0 ? kept : EMPTY_IMPORT_BOX
  };
}

/** Plain words for the import errors that aren't about a single line. */
export function generalImportMessage(error: string): string {
  const lineLimit = /^Import contains (\d+) lines; maximum is (\d+)\./u.exec(error);
  if (lineLimit) {
    return `Only the first ${formatCount(Number(lineLimit[2]))} of ${formatCount(Number(lineLimit[1]))} lines were read. Import the rest in another batch.`;
  }
  if (/^Import text is longer than \d+ characters\.$/u.test(error)) {
    return "The text is over 2 MB, so nothing was read. Split it into smaller batches.";
  }
  return error;
}

/** Replaces the mistyped scheme on one original line, wherever the box holds it. */
export function fixBoxLine(box: ImportBox, line: number, scheme: string): ImportBox {
  const rows = splitLines(box.text);
  const index = box.lineNumbers ? box.lineNumbers.indexOf(line) : line - 1;
  if (index < 0 || index >= rows.length) {
    return box;
  }
  rows[index] = applySchemeFix(rows[index], scheme);
  return { text: rows.join("\n"), lineNumbers: box.lineNumbers };
}

/** Whether the box still holds that original line (so a quick fix can land). */
export function boxHoldsLine(box: ImportBox, line: number): boolean {
  return Boolean(box.lineNumbers?.includes(line));
}

/** The main process refused the whole import because of the 10,000-profile cap. */
export function isProfileLimitError(error: unknown): boolean {
  const text = error instanceof Error ? error.message : String(error);
  return /profile count exceeds the \d+ profile limit/iu.test(text);
}

export interface LibraryMatch {
  /** Lines (original numbers) that update a profile already saved, with its name. */
  existing: Array<{ line: number; name: string }>;
  /** Lines that repeat an earlier line of the same import. */
  repeats: Array<{ line: number; of: number }>;
  /** Distinct links that would become new profiles. */
  newCount: number;
}

/**
 * Matches each readable link against the library by fingerprint, like the
 * import does. Undefined when this window can't hash (no WebCrypto).
 */
export async function matchLinksToLibrary(
  box: ImportBox,
  library: ReadonlyArray<Pick<ProxyProfile, "fingerprint" | "name">>
): Promise<LibraryMatch | undefined> {
  const rows = splitLines(box.text).slice(0, MAX_IMPORT_LINES);
  const parsed: Array<{ line: number; canonical: string }> = [];
  rows.forEach((raw, index) => {
    const text = raw.trim();
    if (!text || text.startsWith("#")) {
      return;
    }
    try {
      parsed.push({ line: gutterNumber(box, index), canonical: parseShareLink(text).canonical });
    } catch {
      // Failed lines are reported by the import itself.
    }
  });
  const fingerprints = await Promise.all(parsed.map((item) => linkFingerprint(item)));
  if (fingerprints.some((value) => value === undefined)) {
    return undefined;
  }
  const known = new Map(library.map((profile) => [profile.fingerprint, profile.name]));
  const firstSeen = new Map<string, number>();
  const match: LibraryMatch = { existing: [], repeats: [], newCount: 0 };
  parsed.forEach((item, index) => {
    const fingerprint = fingerprints[index] as string;
    const earlier = firstSeen.get(fingerprint);
    if (earlier !== undefined) {
      match.repeats.push({ line: item.line, of: earlier });
      return;
    }
    firstSeen.set(fingerprint, item.line);
    const name = known.get(fingerprint);
    if (name !== undefined) {
      match.existing.push({ line: item.line, name });
    } else {
      match.newCount += 1;
    }
  });
  return match;
}

/**
 * The quiet line under the result: which lines were skipped and which
 * updated profiles you already had. Falls back to counts when the match
 * doesn't add up to what the import reported.
 */
export function describeImportNotes(sent: ImportBox, report: Pick<ImportReport, "updated">, match: LibraryMatch | undefined): string | undefined {
  const rows = splitLines(sent.text).slice(0, MAX_IMPORT_LINES);
  const comments: number[] = [];
  let blank = 0;
  rows.forEach((raw, index) => {
    const text = raw.trim();
    if (!text) {
      blank += 1;
    } else if (text.startsWith("#")) {
      comments.push(gutterNumber(sent, index));
    }
  });

  const sentences: string[] = [];
  if (comments.length === 1) {
    sentences.push(`Line ${formatCount(comments[0])} was skipped because it starts with #.`);
  } else if (comments.length > 1 && comments.length <= 3) {
    sentences.push(`${capitalize(describeLineNumbers(comments))} were skipped because they start with #.`);
  } else if (comments.length > 3) {
    sentences.push(`${formatCount(comments.length)} lines were skipped because they start with #.`);
  }
  if (blank > 0) {
    sentences.push(`${plural(blank, "empty line")} ${blank === 1 ? "was" : "were"} skipped${comments.length > 0 ? " too" : ""}.`);
  }

  if (report.updated > 0) {
    if (match && match.existing.length + match.repeats.length === report.updated) {
      const { existing, repeats } = match;
      if (existing.length === 1) {
        sentences.push(`Line ${formatCount(existing[0].line)} updated ${existing[0].name}, which you already had.`);
      } else if (existing.length === 2) {
        sentences.push(`Lines ${formatCount(existing[0].line)} and ${formatCount(existing[1].line)} updated ${existing[0].name} and ${existing[1].name}, which you already had.`);
      } else if (existing.length > 2) {
        sentences.push(`${formatCount(existing.length)} lines updated profiles you already had.`);
      }
      if (repeats.length === 1) {
        sentences.push(`Line ${formatCount(repeats[0].line)} repeats line ${formatCount(repeats[0].of)}, so it counted as an update.`);
      } else if (repeats.length > 1) {
        sentences.push(`${formatCount(repeats.length)} lines repeat earlier ones, so they counted as updates.`);
      }
    } else {
      sentences.push(report.updated === 1 ? "1 line updated a profile you already had." : `${formatCount(report.updated)} lines updated profiles you already had.`);
    }
  }
  const insecure = describeInsecureLines(sent);
  if (insecure) {
    sentences.push(insecure);
  }
  return sentences.length > 0 ? sentences.join(" ") : undefined;
}

/** Lines (original numbers) whose Hysteria 2 link asks for insecure=1 without a pinSHA256. */
export function insecureLinkLines(box: ImportBox): number[] {
  const numbers: number[] = [];
  splitLines(box.text)
    .slice(0, MAX_IMPORT_LINES)
    .forEach((raw, index) => {
      const text = raw.trim();
      if (!text || text.startsWith("#")) {
        return;
      }
      try {
        if (parseShareLink(text).insecureWithoutPin) {
          numbers.push(gutterNumber(box, index));
        }
      } catch {
        // Failed lines are listed on their own.
      }
    });
  return numbers;
}

/**
 * Sentences for the import result when some imported links ask to skip
 * certificate checks without a pin: the card tag is the only other sign.
 * Profiles can't be edited, so the fix is the pinned link as a new profile.
 */
export function describeInsecureLines(box: ImportBox): string | undefined {
  const lines = insecureLinkLines(box);
  if (lines.length === 0) {
    return undefined;
  }
  const one = lines.length === 1;
  return `${capitalize(describeLineNumbers(lines))} ${one ? "asks" : "ask"} to skip certificate checks (insecure=1) without a pinSHA256. The bundled Xray checks certificates anyway, so ${
    one ? "its card is" : "their cards are"
  } tagged insecure=1. ${
    one
      ? "If the server uses a self-signed certificate, add the link again with its pinSHA256 and remove the tagged profile."
      : "If a server uses a self-signed certificate, add its link again with the server’s pinSHA256 and remove the tagged profile."
  }`;
}

/** Callout text when the import would pass the 10,000-profile cap. */
export function describeProfileLimit(libraryCount: number, match: LibraryMatch | undefined): string {
  const tail = "so nothing was added or updated. Remove profiles you don’t use, then import again.";
  if (!match) {
    return `These links would take your library past the ${formatCount(MAX_STORED_PROFILES)}-profile limit, ${tail}`;
  }
  return `These links would add ${plural(match.newCount, "new profile")} to the ${formatCount(libraryCount)} you have, past the ${formatCount(MAX_STORED_PROFILES)}-profile limit, ${tail}`;
}

/** Last sentence of the success callout: "jp-osa-ws is in Xray profiles." */
export function importedSentence(before: readonly ProxyProfile[], after: readonly ProxyProfile[]): string {
  const previous = new Map(before.map((profile) => [profile.id, profile.updatedAt]));
  const touched = after.filter((profile) => !previous.has(profile.id) || previous.get(profile.id) !== profile.updatedAt);
  if (touched.length === 1) {
    return `${touched[0].name} is in Xray profiles.`;
  }
  return touched.length > 1 ? `All ${formatCount(touched.length)} are in Xray profiles.` : "";
}

function rowOfLine(box: ImportBox, line: number): number {
  return box.lineNumbers ? box.lineNumbers.indexOf(line) + 1 : line;
}

function isLinkLine(raw: string | undefined): boolean {
  const text = raw?.trim() ?? "";
  return text !== "" && !text.startsWith("#");
}

function parses(text: string): boolean {
  try {
    parseShareLink(text);
    return true;
  } catch {
    return false;
  }
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
