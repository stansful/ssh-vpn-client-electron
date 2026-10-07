import type { DiagnosticsEntry, DiagnosticsSource } from "./types.js";
import { utf8ByteLength } from "./terminal-history.js";

export const MAX_DIAGNOSTICS_HISTORY_ENTRIES = 500;
export const MAX_DIAGNOSTICS_HISTORY_BYTES = 1024 * 1024;
export const MAX_DIAGNOSTIC_MESSAGE_BYTES = 64 * 1024;
export const MAX_DIAGNOSTIC_ID_CHARACTERS = 128;
export const MAX_DIAGNOSTIC_TIMESTAMP_CHARACTERS = 64;

const DIAGNOSTIC_TRUNCATION_MARKER = "\n[diagnostic truncated]";
const DIAGNOSTIC_SOURCES: ReadonlySet<string> = new Set<DiagnosticsSource>(["ssh", "xray", "routing", "update", "app"]);
const byteLengthCache = new WeakMap<readonly DiagnosticsEntry[], number>();

/**
 * Service messages about routing, the TUN adapter or the Windows proxy. They
 * come from a transport, but the user looks for them under Routing.
 */
const ROUTING_DIAGNOSTIC_PATTERN =
  /^(TUN |Routing |Selected[ -](rules|routing|process-name) |Process-name |Per-process enforcement |Local routing proxy |Further local routing |Proxy-all TCP routing |Windows proxy |Reconnect through the protected address |The tunnel has been down for )/u;

/** Bounds untrusted/native diagnostic fields before logging, IPC and retention. */
export function normalizeDiagnosticEntry(
  entry: DiagnosticsEntry,
  maxMessageBytes = MAX_DIAGNOSTIC_MESSAGE_BYTES
): DiagnosticsEntry {
  const id = entry.id.slice(0, MAX_DIAGNOSTIC_ID_CHARACTERS);
  const at = entry.at.slice(0, MAX_DIAGNOSTIC_TIMESTAMP_CHARACTERS);
  const message = truncateUtf8(entry.message, maxMessageBytes, DIAGNOSTIC_TRUNCATION_MARKER);
  const sourceValid = entry.source === undefined || DIAGNOSTIC_SOURCES.has(entry.source);
  if (id === entry.id && at === entry.at && message === entry.message && sourceValid) {
    return entry;
  }
  const normalized: DiagnosticsEntry = { ...entry, id, at, message };
  if (!sourceValid) {
    delete normalized.source;
  }
  return normalized;
}

/**
 * Names the part of the app a diagnostic belongs to. Transport messages about
 * routing are filed under "routing"; everything else keeps its origin.
 */
export function classifyDiagnosticSource(message: string, origin: DiagnosticsSource): DiagnosticsSource {
  if ((origin === "ssh" || origin === "xray") && ROUTING_DIAGNOSTIC_PATTERN.test(message)) {
    return "routing";
  }
  return origin;
}

/** Returns the entry with `source` set, keeping a valid source it already has. */
export function withDiagnosticSource(entry: DiagnosticsEntry, origin: DiagnosticsSource): DiagnosticsEntry {
  if (entry.source !== undefined && DIAGNOSTIC_SOURCES.has(entry.source)) {
    return entry;
  }
  return { ...entry, source: classifyDiagnosticSource(entry.message, origin) };
}

/** Retains the newest diagnostic tail under both entry-count and UTF-8 byte caps. */
export function appendBoundedDiagnosticEntries(
  entries: readonly DiagnosticsEntry[],
  appendedEntries: readonly DiagnosticsEntry[],
  maxEntries = MAX_DIAGNOSTICS_HISTORY_ENTRIES,
  maxBytes = MAX_DIAGNOSTICS_HISTORY_BYTES
): DiagnosticsEntry[] {
  if (maxEntries <= 0 || maxBytes <= 0) {
    const empty: DiagnosticsEntry[] = [];
    byteLengthCache.set(empty, 0);
    return empty;
  }

  const accepted: DiagnosticsEntry[] = [];
  let appendedBytes = 0;
  for (const candidate of appendedEntries) {
    const entry = normalizeDiagnosticEntry(candidate);
    const bytes = diagnosticEntryByteLength(entry);
    if (bytes <= maxBytes) {
      accepted.push(entry);
      appendedBytes += bytes;
    }
  }

  let totalBytes = byteLengthCache.get(entries);
  if (totalBytes === undefined) {
    totalBytes = entries.reduce((total, entry) => total + diagnosticEntryByteLength(entry), 0);
  }
  totalBytes += appendedBytes;
  const next = accepted.length > 0 ? [...entries, ...accepted] : entries.slice();
  let start = 0;
  while (next.length - start > maxEntries || totalBytes > maxBytes) {
    totalBytes -= diagnosticEntryByteLength(next[start] as DiagnosticsEntry);
    start += 1;
  }
  const bounded = start === 0 ? next : next.slice(start);
  byteLengthCache.set(bounded, totalBytes);
  return bounded;
}

export function diagnosticEntryByteLength(entry: DiagnosticsEntry): number {
  return utf8ByteLength(entry.id) + utf8ByteLength(entry.at) + utf8ByteLength(entry.message) + 16;
}

export function truncateUtf8(value: string, maxBytes: number, marker = ""): string {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    return "";
  }

  const markerBytes = utf8ByteLength(marker);
  const markedLimit = markerBytes < maxBytes ? maxBytes - markerBytes : maxBytes;
  let bytes = 0;
  let index = 0;
  let markedEnd = 0;
  while (index < value.length) {
    const { bytes: characterBytes, width } = utf8CharacterSize(value, index);
    if (bytes + characterBytes > maxBytes) {
      return markerBytes < maxBytes ? `${value.slice(0, markedEnd)}${marker}` : value.slice(0, index);
    }
    bytes += characterBytes;
    index += width;
    if (bytes <= markedLimit) {
      markedEnd = index;
    }
  }
  return value;
}

function utf8CharacterSize(value: string, index: number): { bytes: number; width: number } {
  const code = value.charCodeAt(index);
  if (code < 0x80) {
    return { bytes: 1, width: 1 };
  }
  if (code < 0x800) {
    return { bytes: 2, width: 1 };
  }
  if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
    const next = value.charCodeAt(index + 1);
    if (next >= 0xdc00 && next <= 0xdfff) {
      return { bytes: 4, width: 2 };
    }
  }
  return { bytes: 3, width: 1 };
}
