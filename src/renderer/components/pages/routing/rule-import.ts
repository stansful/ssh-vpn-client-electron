import { normalizeRuleValue, validateRoutingRuleValue } from "../../../../shared/validation.js";
import type { RoutingRule, RoutingRuleType } from "../../../../shared/types.js";
import { formatCount, plural } from "../../../lib/format.js";

/** Same limits the main process enforces on the rule set. */
export const MAX_RULE_IMPORT_BYTES = 2 * 1024 * 1024;
export const MAX_ROUTING_RULES = 10_000;
export const EXPORT_FILE_NAME = "shadow-routing-rules.json";

const RULE_TYPES: readonly RoutingRuleType[] = ["domain", "ip", "process.name"];

/** A file that can't be imported at all; `message` is ready for a toast. */
export class RuleImportError extends Error {
  constructor(message: string, readonly technical?: string) {
    super(message);
    this.name = "RuleImportError";
  }
}

export interface SkippedEntries {
  /** Entries whose `type` Shadow doesn't know, e.g. "url". */
  unsupported: number;
  /** The distinct unknown types, in file order. */
  unsupportedTypes: string[];
  /** Known type, but the value isn't a valid rule. */
  invalid: number;
  /** Same type and value as an earlier entry. */
  duplicates: number;
  /** Not an object with a type and a value. */
  malformed: number;
  total: number;
}

export interface RuleImportPreview {
  fileName: string;
  size: number;
  /** Entries in the file. */
  entries: number;
  /** Valid, normalized rules in file order. */
  rules: RoutingRule[];
  counts: Record<RoutingRuleType, number>;
  skipped: SkippedEntries;
}

export interface RuleImportOptions {
  now?: string;
  makeId?: () => string;
}

/** Checked before the file is read: a routing export is far below 2 MB. */
export function assertImportSize(file: { name: string; size: number }): void {
  if (file.size > MAX_RULE_IMPORT_BYTES) {
    throw new RuleImportError(`${file.name} is larger than 2 MB. A routing export is much smaller, so check that it’s the right file.`);
  }
}

/**
 * Reads a routing export before anything is replaced. Broken entries are
 * skipped and counted instead of failing the whole file; a file that is not
 * a rule list at all throws RuleImportError.
 */
export function parseRuleImport(text: string, file: { name: string; size: number }, options: RuleImportOptions = {}): RuleImportPreview {
  const now = options.now ?? new Date().toISOString();
  const makeId = options.makeId ?? (() => crypto.randomUUID());
  assertImportSize(file);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text.replace(/^\uFEFF/u, ""));
  } catch (error) {
    throw new RuleImportError(`${file.name} isn’t valid JSON, so nothing was imported.`, error instanceof Error ? error.message : String(error));
  }
  const list = Array.isArray(parsed)
    ? parsed
    : typeof parsed === "object" && parsed !== null && Array.isArray((parsed as { rules?: unknown }).rules)
      ? (parsed as { rules: unknown[] }).rules
      : undefined;
  if (!list) {
    throw new RuleImportError(`${file.name} doesn’t contain a list of rules. Use a file made with Export.`);
  }
  if (list.length > MAX_ROUTING_RULES) {
    throw new RuleImportError(`${file.name} has ${formatCount(list.length)} rules. Shadow keeps up to ${formatCount(MAX_ROUTING_RULES)}.`);
  }

  const skipped: SkippedEntries = { unsupported: 0, unsupportedTypes: [], invalid: 0, duplicates: 0, malformed: 0, total: 0 };
  const counts: Record<RoutingRuleType, number> = { domain: 0, ip: 0, "process.name": 0 };
  const rules: RoutingRule[] = [];
  const seenValues = new Set<string>();
  const seenIds = new Set<string>();

  for (const entry of list) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      skipped.malformed += 1;
      continue;
    }
    const record = entry as Record<string, unknown>;
    const type = record.type;
    if (typeof type !== "string" || typeof record.value !== "string") {
      if (typeof type === "string" && type && !RULE_TYPES.includes(type as RoutingRuleType)) {
        noteUnsupported(skipped, type);
      } else {
        skipped.malformed += 1;
      }
      continue;
    }
    if (!RULE_TYPES.includes(type as RoutingRuleType)) {
      noteUnsupported(skipped, type);
      continue;
    }
    const ruleType = type as RoutingRuleType;
    if (!validateRoutingRuleValue(ruleType, record.value).ok) {
      skipped.invalid += 1;
      continue;
    }
    const value = ruleType === "ip" && record.value.includes(":") ? record.value.trim().toLowerCase() : normalizeRuleValue(ruleType, record.value);
    const key = `${ruleType}\u0000${value}`;
    if (seenValues.has(key)) {
      skipped.duplicates += 1;
      continue;
    }
    seenValues.add(key);
    const rawId = typeof record.id === "string" ? record.id.trim() : "";
    const id = rawId && !seenIds.has(rawId) ? rawId : makeId();
    seenIds.add(id);
    rules.push({
      id,
      type: ruleType,
      value,
      // Hand-written files often leave the state out; a rule someone bothered to write is meant to be on.
      enabled: typeof record.enabled === "boolean" ? record.enabled : true,
      createdAt: typeof record.createdAt === "string" ? record.createdAt : now,
      updatedAt: typeof record.updatedAt === "string" ? record.updatedAt : now
    });
    counts[ruleType] += 1;
  }
  skipped.total = skipped.unsupported + skipped.invalid + skipped.duplicates + skipped.malformed;
  return { fileName: file.name, size: file.size, entries: list.length, rules, counts, skipped };
}

function noteUnsupported(skipped: SkippedEntries, type: string): void {
  skipped.unsupported += 1;
  if (!skipped.unsupportedTypes.includes(type)) {
    skipped.unsupportedTypes.push(type);
  }
}

/** Text with inline code parts (rendered in mono). */
export type RichText = Array<{ text: string } | { code: string }>;

/**
 * The rules an import's Undo leaves: the imported ones go, the ones they
 * replaced come back, and rules added since the import stay.
 */
export function rulesAfterImportUndo(
  imported: readonly RoutingRule[],
  previous: readonly RoutingRule[],
  current: readonly RoutingRule[]
): RoutingRule[] {
  const importedIds = new Set(imported.map((rule) => rule.id));
  const previousIds = new Set(previous.map((rule) => rule.id));
  return [...previous, ...current.filter((rule) => !importedIds.has(rule.id) && !previousIds.has(rule.id))];
}

export function richTextToString(parts: RichText): string {
  return parts.map((part) => ("code" in part ? part.code : part.text)).join("");
}

function codeList(types: string[]): RichText {
  const parts: RichText = [];
  types.forEach((type, index) => {
    if (index > 0) {
      parts.push({ text: index === types.length - 1 ? " and " : ", " });
    }
    parts.push({ code: type });
  });
  return parts;
}

/**
 * "1 entry will be skipped because its type, url, isn’t supported." — or a
 * breakdown when entries are skipped for different reasons.
 */
export function describeSkipped(skipped: SkippedEntries): RichText | undefined {
  const total = skipped.total;
  if (total === 0) {
    return undefined;
  }
  const lead = `${plural(total, "entry", "entries")} will be skipped`;
  const one = total === 1;
  const reasons = [skipped.unsupported, skipped.invalid, skipped.duplicates, skipped.malformed].filter((count) => count > 0).length;
  if (reasons === 1) {
    if (skipped.unsupported > 0) {
      const types = skipped.unsupportedTypes;
      const several = types.length > 1;
      return [
        { text: `${lead} because ${one ? "its" : "their"} ${several ? "types" : "type"}, ` },
        ...codeList(types),
        { text: `, ${several ? "aren’t" : "isn’t"} supported.` }
      ];
    }
    if (skipped.invalid > 0) {
      return [{ text: `${lead} because ${one ? "its value isn’t a valid rule" : "their values aren’t valid rules"}.` }];
    }
    if (skipped.duplicates > 0) {
      return [{ text: `${lead} because ${one ? "it repeats another entry" : "they repeat other entries"}.` }];
    }
    return [{ text: `${lead} because ${one ? "it isn’t a rule" : "they aren’t rules"}.` }];
  }
  const parts: RichText = [{ text: `${lead}: ` }];
  const clauses: RichText[] = [];
  if (skipped.unsupported > 0) {
    const n = skipped.unsupported;
    clauses.push([{ text: `${formatCount(n)} ${n === 1 ? "has an unsupported type" : "have unsupported types"} (` }, ...codeList(skipped.unsupportedTypes), { text: ")" }]);
  }
  if (skipped.invalid > 0) {
    const n = skipped.invalid;
    clauses.push([{ text: `${formatCount(n)} ${n === 1 ? "isn’t a valid rule" : "aren’t valid rules"}` }]);
  }
  if (skipped.duplicates > 0) {
    const n = skipped.duplicates;
    clauses.push([{ text: `${formatCount(n)} ${n === 1 ? "repeats another entry" : "repeat other entries"}` }]);
  }
  if (skipped.malformed > 0) {
    const n = skipped.malformed;
    clauses.push([{ text: `${formatCount(n)} ${n === 1 ? "isn’t a rule" : "aren’t rules"}` }]);
  }
  clauses.forEach((clause, index) => {
    if (index > 0) {
      parts.push({ text: index === clauses.length - 1 ? " and " : ", " });
    }
    parts.push(...clause);
  });
  parts.push({ text: "." });
  return parts;
}

/** "9 domains · 3 IPs · 2 apps". */
export function ruleCountsText(counts: Record<RoutingRuleType, number>): string {
  return [plural(counts.domain, "domain"), plural(counts.ip, "IP"), plural(counts["process.name"], "app")].join(" · ");
}

export function countRuleTypes(rules: readonly Pick<RoutingRule, "type">[]): Record<RoutingRuleType, number> {
  const counts: Record<RoutingRuleType, number> = { domain: 0, ip: 0, "process.name": 0 };
  for (const rule of rules) {
    counts[rule.type] = (counts[rule.type] ?? 0) + 1;
  }
  return counts;
}

/** The export format: the rule array as the store keeps it. */
export function serializeRules(rules: readonly RoutingRule[]): string {
  return `${JSON.stringify(rules, null, 2)}\n`;
}
