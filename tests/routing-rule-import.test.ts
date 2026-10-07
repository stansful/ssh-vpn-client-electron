import { describe, expect, it } from "vitest";
import {
  countRuleTypes,
  describeSkipped,
  MAX_RULE_IMPORT_BYTES,
  parseRuleImport,
  richTextToString,
  RuleImportError,
  ruleCountsText,
  rulesAfterImportUndo,
  serializeRules,
  type SkippedEntries
} from "../src/renderer/components/pages/routing/rule-import.js";
import type { RoutingRule } from "../src/shared/types.js";

const file = (text: string, name = "routing-backup.json") => ({ name, size: text.length });
const options = () => {
  let next = 0;
  return { now: "2026-10-06T09:00:00.000Z", makeId: () => `gen-${(next += 1)}` };
};

function parse(value: unknown, name?: string) {
  const text = JSON.stringify(value);
  return parseRuleImport(text, file(text, name), options());
}

describe("parseRuleImport", () => {
  it("keeps valid rules, normalizes them and counts what it skips", () => {
    const preview = parse([
      { id: "a", type: "domain", value: "YouTube.com", enabled: true, createdAt: "2026-01-01T00:00:00.000Z", updatedAt: "2026-01-02T00:00:00.000Z" },
      { id: "b", type: "domain", value: "youtube.com", enabled: true },
      { id: "c", type: "ip", value: "2A00:1450::/32", enabled: false },
      { type: "process.name", value: "Telegram.exe" },
      { type: "url", value: "https://example.com" },
      { type: "regex", value: ".*" },
      { type: "url", value: "https://example.org" },
      { type: "domain", value: "not valid" },
      null,
      { type: "domain" }
    ]);
    expect(preview.entries).toBe(10);
    expect(preview.rules).toEqual([
      { id: "a", type: "domain", value: "youtube.com", enabled: true, createdAt: "2026-01-01T00:00:00.000Z", updatedAt: "2026-01-02T00:00:00.000Z" },
      { id: "c", type: "ip", value: "2a00:1450::/32", enabled: false, createdAt: "2026-10-06T09:00:00.000Z", updatedAt: "2026-10-06T09:00:00.000Z" },
      { id: "gen-1", type: "process.name", value: "telegram.exe", enabled: true, createdAt: "2026-10-06T09:00:00.000Z", updatedAt: "2026-10-06T09:00:00.000Z" }
    ]);
    expect(preview.counts).toEqual({ domain: 1, ip: 1, "process.name": 1 });
    expect(preview.skipped).toEqual({ unsupported: 3, unsupportedTypes: ["url", "regex"], invalid: 1, duplicates: 1, malformed: 2, total: 7 });
  });

  it("gives repeated ids a fresh one", () => {
    const preview = parse([
      { id: "same", type: "domain", value: "a.com" },
      { id: "same", type: "domain", value: "b.com" }
    ]);
    expect(preview.rules.map((rule) => rule.id)).toEqual(["same", "gen-1"]);
  });

  it("accepts an object with a rules array and a byte order mark", () => {
    const text = `\uFEFF${JSON.stringify({ rules: [{ type: "ip", value: "8.8.8.8" }] })}`;
    expect(parseRuleImport(text, file(text), options()).rules).toHaveLength(1);
  });

  it("rejects files that aren't rule lists", () => {
    expect(() => parseRuleImport("{", file("{"), options())).toThrow(RuleImportError);
    expect(() => parseRuleImport("{", file("{"), options())).toThrow("routing-backup.json isn’t valid JSON, so nothing was imported.");
    expect(() => parse({ hello: "world" })).toThrow("doesn’t contain a list of rules");
    expect(() => parse(Array.from({ length: 10_001 }, () => ({ type: "domain", value: "a.com" })))).toThrow("Shadow SSH keeps up to 10,000.");
    expect(() => parseRuleImport("[]", { name: "huge.json", size: MAX_RULE_IMPORT_BYTES + 1 }, options())).toThrow("huge.json is larger than 2 MB.");
  });

  it("keeps technical details of JSON errors", () => {
    try {
      parseRuleImport("[1,", file("[1,"), options());
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(RuleImportError);
      expect((error as RuleImportError).technical).toBeTruthy();
    }
  });
});

describe("describeSkipped", () => {
  const skipped = (patch: Partial<SkippedEntries>): SkippedEntries => {
    const base = { unsupported: 0, unsupportedTypes: [], invalid: 0, duplicates: 0, malformed: 0, ...patch };
    return { ...base, total: base.unsupported + base.invalid + base.duplicates + base.malformed };
  };
  const text = (patch: Partial<SkippedEntries>) => {
    const parts = describeSkipped(skipped(patch));
    return parts ? richTextToString(parts) : undefined;
  };

  it("says nothing when every entry imports", () => {
    expect(text({})).toBeUndefined();
  });

  it("names unsupported types", () => {
    expect(text({ unsupported: 1, unsupportedTypes: ["url"] })).toBe("1 entry will be skipped because its type, url, isn’t supported.");
    expect(text({ unsupported: 3, unsupportedTypes: ["url"] })).toBe("3 entries will be skipped because their type, url, isn’t supported.");
    expect(text({ unsupported: 2, unsupportedTypes: ["url", "regex"] })).toBe(
      "2 entries will be skipped because their types, url and regex, aren’t supported."
    );
    expect(describeSkipped(skipped({ unsupported: 1, unsupportedTypes: ["url"] }))).toContainEqual({ code: "url" });
  });

  it("explains single reasons and mixes", () => {
    expect(text({ invalid: 1 })).toBe("1 entry will be skipped because its value isn’t a valid rule.");
    expect(text({ duplicates: 2 })).toBe("2 entries will be skipped because they repeat other entries.");
    expect(text({ malformed: 1 })).toBe("1 entry will be skipped because it isn’t a rule.");
    expect(text({ unsupported: 2, unsupportedTypes: ["url"], invalid: 1, duplicates: 2 })).toBe(
      "5 entries will be skipped: 2 have unsupported types (url), 1 isn’t a valid rule and 2 repeat other entries."
    );
  });
});

describe("rule counts and export", () => {
  it("summarizes rule types", () => {
    const counts = countRuleTypes([{ type: "domain" }, { type: "domain" }, { type: "ip" }]);
    expect(ruleCountsText(counts)).toBe("2 domains · 1 IP · 0 apps");
  });

  it("exports the same shape it imports", () => {
    const rules = parse([{ id: "x", type: "domain", value: "x.com", enabled: false }]).rules;
    const text = serializeRules(rules);
    expect(text.endsWith("\n")).toBe(true);
    expect(parseRuleImport(text, file(text), options()).rules).toEqual(rules);
  });
});

describe("undoing an import", () => {
  const at = "2026-10-06T09:00:00.000Z";
  const make = (id: string, value: string, enabled = true): RoutingRule => ({ id, type: "domain", value, enabled, createdAt: at, updatedAt: at });

  it("swaps the imported rules back for the old ones and keeps rules added since", () => {
    const previous = [make("old-1", "a.com", false)];
    const imported = [make("new-1", "b.com"), make("new-2", "c.com")];
    const current = [make("new-1", "b.com", false), make("added", "d.com")];

    expect(rulesAfterImportUndo(imported, previous, current)).toEqual([make("old-1", "a.com", false), make("added", "d.com")]);
  });
});
