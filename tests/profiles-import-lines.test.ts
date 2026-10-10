import { describe, expect, it } from "vitest";
import { parseProxyShareLink, parseProxyShareLinks } from "../src/core/proxy/share-link-parser.js";
import {
  boxHoldsLine,
  buildImportReport,
  contentLineCount,
  describeImportNotes,
  describeInsecureLines,
  describeLineNumbers,
  describeProfileLimit,
  editImportBox,
  fixBoxLine,
  generalImportMessage,
  gutterNumber,
  importedSentence,
  insecureLinkLines,
  isProfileLimitError,
  linesHint,
  matchLinksToLibrary,
  trimTrailingBlankLines,
  visualLineCount,
  type ImportBox
} from "../src/renderer/components/pages/profiles/import-lines.js";
import type { ImportProxyProfilesResult, ProxyProfile } from "../src/shared/types.js";

const WAW = "vless://3c8f2a4e-91b0-4d7a-a6e2-5f0d9c1b7e44@198.51.100.140:443?type=xhttp&security=reality#pl-waw-xhttp";
const TOKYO = "trojan://b71e0c2a9d4f6e83@203.0.113.77:443?security=tls&type=tcp#trojan-tokyo";
const TYPO = "vles://8e2d41c0-5a7b-4c19-b3f6-2d9e0a1c7b55@203.0.113.91:443?type=ws&security=tls#jp-osa-ws";
const AMS = "vless://f40a9b1e-77c3-4e2d-8a10-6b5c3d2e1f09@192.0.2.140:8443?type=grpc&security=tls#nl-ams-grpc";
const HEL = "hysteria2://letmein@hel.example.net:443,20000-30000?sni=hel.example.net#fi-hel-hy2";
const HY1 = "hysteria://hel.example.net:443?auth=letmein&upmbps=50#fi-hel-v1";
const PASTE = ["# friends list, October", WAW, TOKYO, TYPO, AMS].join("\n");

function profile(overrides: Partial<ProxyProfile>): ProxyProfile {
  return {
    id: "p1",
    name: "profile",
    protocol: "vless",
    host: "example.com",
    port: 443,
    transport: "tcp",
    security: "tls",
    flow: "",
    source: "manual",
    rawUriSecretId: "secret",
    fingerprint: "sha256:0",
    isSelected: false,
    isPinned: false,
    isStale: false,
    lastTestStatus: "unknown",
    createdAt: "2026-10-06T09:00:00.000Z",
    updatedAt: "2026-10-06T09:00:00.000Z",
    lastSeenAt: "2026-10-06T09:00:00.000Z",
    ...overrides
  };
}

/** What the main process would answer, from the real parser (all links new). */
function importResult(text: string, updated = 0): ImportProxyProfilesResult {
  const parsed = parseProxyShareLinks(text);
  return { imported: parsed.profiles.length - updated, updated, skipped: parsed.skipped, failed: parsed.errors.length, errors: parsed.errors };
}

describe("import box", () => {
  it("counts rows and content lines", () => {
    expect(visualLineCount("")).toBe(1);
    expect(visualLineCount("a\nb\n")).toBe(3);
    expect(contentLineCount("a\nb\n\n  \n")).toBe(2);
    expect(contentLineCount("   ")).toBe(0);
    expect(trimTrailingBlankLines("a\r\nb\r\n  \r\n")).toBe("a\r\nb");
  });

  it("keeps original numbering while typing in place and drops it when rows change", () => {
    const box: ImportBox = { text: TYPO, lineNumbers: [4] };
    expect(gutterNumber(box, 0)).toBe(4);
    expect(editImportBox(box, TYPO.replace("vles", "vless"))).toEqual({ text: TYPO.replace("vles", "vless"), lineNumbers: [4] });
    expect(editImportBox(box, `${TYPO}\n`)).toEqual({ text: `${TYPO}\n`, lineNumbers: null });
  });

  it("describes line numbers and the lines hint", () => {
    expect(describeLineNumbers([4])).toBe("line 4");
    expect(describeLineNumbers([4, 9])).toBe("lines 4 and 9");
    expect(describeLineNumbers([4, 9, 12])).toBe("lines 4, 9 and 12");
    expect(describeLineNumbers([4, 9, 12, 20, 31])).toBe("lines 4, 9, 12 and 2 more");
    expect(linesHint({ text: "", lineNumbers: null })).toEqual({ text: "Empty", blocked: true });
    expect(linesHint({ text: PASTE, lineNumbers: null })).toEqual({ text: "5 lines · up to 10,000" });
    expect(linesHint({ text: TYPO, lineNumbers: [4] })).toEqual({ text: "1 line kept · line 4" });
    expect(linesHint({ text: Array.from({ length: 10_050 }, () => "x").join("\n"), lineNumbers: null })).toEqual({
      text: "10,050 lines · only the first 10,000 are read",
      tone: "danger"
    });
    expect(linesHint({ text: "x".repeat(2 * 1024 * 1024 + 1), lineNumbers: null }).blocked).toBe(true);
  });
});

describe("import report", () => {
  it("lists every failed line with its number, text and a typo fix, and keeps it", () => {
    const report = buildImportReport({ text: PASTE, lineNumbers: null }, importResult(PASTE, 1));
    expect(report.outcome).toBe("partial");
    expect(report.title).toBe("Imported with 1 problem");
    expect(report.countsLine).toBe("Imported 2 · Updated 1 · Skipped 1 · Failed 1");
    expect(report.failures).toEqual([
      {
        line: 4,
        message: "Only vless://, vmess://, trojan:// and hysteria2:// links are supported.",
        text: TYPO,
        hint: "Looks like a typo: vles:// instead of vless://",
        fix: { from: "vles", to: "vless" }
      }
    ]);
    expect(report.kept).toEqual({ text: TYPO, lineNumbers: [4] });
  });

  it("points Hysteria v1 lines at Hysteria 2 and passes Hysteria 2 parser errors through", () => {
    const text = [HEL, HY1, "hy2://letmein@hel.example.net:443?obfs=gecko&obfs-password=x#gecko"].join("\n");
    const report = buildImportReport({ text, lineNumbers: null }, importResult(text));
    expect(report.imported).toBe(1);
    expect(report.failures).toEqual([
      {
        line: 2,
        message: "Only vless://, vmess://, trojan:// and hysteria2:// links are supported.",
        text: HY1,
        hint: "Hysteria v1 links can’t run in Shadow. Hysteria 2 links (hysteria2:// or hy2://) work.",
        fix: undefined
      },
      {
        line: 3,
        message: "Unsupported Hysteria 2 obfuscation: gecko. Only salamander works.",
        text: "hy2://letmein@hel.example.net:443?obfs=gecko&obfs-password=x#gecko",
        hint: undefined,
        fix: undefined
      }
    ]);
  });

  it("maps errors from a second import back to the original line numbers", () => {
    const sent: ImportBox = { text: `${TYPO}\nnot-a-link`, lineNumbers: [4, 9] };
    const report = buildImportReport(sent, importResult(sent.text));
    expect(report.outcome).toBe("failed");
    expect(report.title).toBe("Nothing was imported");
    expect(report.failures.map((item) => item.line)).toEqual([4, 9]);
    expect(report.kept).toEqual({ text: `${TYPO}\nnot-a-link`, lineNumbers: [4, 9] });
  });

  it("separates limit errors and keeps the lines past 10,000", () => {
    const text = [...Array.from({ length: 10_000 }, () => "# filler"), WAW, "", "# note"].join("\n");
    const report = buildImportReport({ text, lineNumbers: null }, importResult(text));
    expect(report.general).toEqual(["Only the first 10,000 of 10,003 lines were read. Import the rest in another batch."]);
    expect(report.kept).toEqual({ text: WAW, lineNumbers: [10_001] });
    expect(generalImportMessage("Import text is longer than 2097152 characters.")).toBe("The text is over 2 MB, so nothing was read. Split it into smaller batches.");
  });

  it("finds failed lines the main process didn't list", () => {
    const text = ["bad-1", WAW, "bad-2", "bad-3"].join("\n");
    const result: ImportProxyProfilesResult = {
      imported: 1,
      updated: 0,
      skipped: 0,
      failed: 3,
      errors: ["Line 1: Only vless://, vmess://, trojan://, and hysteria2:// links are supported."]
    };
    const report = buildImportReport({ text, lineNumbers: null }, result);
    expect(report.unlisted).toBe(2);
    expect(report.kept.lineNumbers).toEqual([1, 3, 4]);
  });

  it("reports clean and empty imports", () => {
    expect(buildImportReport({ text: WAW, lineNumbers: null }, importResult(WAW))).toMatchObject({ outcome: "clean", title: "All lines imported", kept: { text: "", lineNumbers: null } });
    expect(buildImportReport({ text: "# only a note", lineNumbers: null }, importResult("# only a note"))).toMatchObject({ outcome: "nothing" });
  });

  it("applies a quick fix where the box holds the line", () => {
    const box: ImportBox = { text: `${TYPO}\nnot-a-link`, lineNumbers: [4, 9] };
    expect(boxHoldsLine(box, 4)).toBe(true);
    expect(boxHoldsLine({ text: TYPO, lineNumbers: null }, 4)).toBe(false);
    expect(fixBoxLine(box, 4, "vless")).toEqual({ text: `${TYPO.replace("vles://", "vless://")}\nnot-a-link`, lineNumbers: [4, 9] });
    expect(fixBoxLine(box, 7, "vless")).toBe(box);
  });

  it("recognises the profile cap error", () => {
    expect(isProfileLimitError(new Error("Error invoking remote method 'shadow-ssh:import-proxy-profiles': Error: Proxy profile count exceeds the 10000 profile limit."))).toBe(true);
    expect(isProfileLimitError(new Error("Something else"))).toBe(false);
  });
});

describe("import notes", () => {
  const tokyo = profile({ id: "tokyo", name: "trojan-tokyo", fingerprint: parseProxyShareLink(TOKYO).fingerprint });

  it("names skipped comment lines and updated profiles by line", async () => {
    const sent: ImportBox = { text: `${PASTE}\n${WAW}\n`, lineNumbers: null };
    const match = await matchLinksToLibrary(sent, [tokyo]);
    expect(match).toEqual({ existing: [{ line: 3, name: "trojan-tokyo" }], repeats: [{ line: 6, of: 2 }], newCount: 2 });
    expect(describeImportNotes(sent, { updated: 2 }, match)).toBe(
      "Line 1 was skipped because it starts with #. 1 empty line was skipped too. Line 3 updated trojan-tokyo, which you already had. Line 6 repeats line 2, so it counted as an update."
    );
  });

  it("matches Hysteria 2 lines by fingerprint, whichever scheme spelling they use", async () => {
    const hel = profile({ id: "hel", name: "fi-hel-hy2", protocol: "hysteria2", fingerprint: parseProxyShareLink(HEL).fingerprint });
    const sent: ImportBox = { text: [HEL.replace("hysteria2://", "hy2://"), WAW].join("\n"), lineNumbers: null };
    expect(await matchLinksToLibrary(sent, [hel])).toEqual({ existing: [{ line: 1, name: "fi-hel-hy2" }], repeats: [], newCount: 1 });
  });

  it("names lines that ask to skip certificate checks without a pin, by their original numbers", () => {
    const insecure = "hy2://letmein@self.example.net?insecure=1#self-signed";
    const pinned = `hy2://letmein@pinned.example.net?insecure=1&pinSHA256=${"ab".repeat(32)}#pinned`;
    const sent: ImportBox = { text: ["# list", insecure, pinned, HEL, TYPO, WAW.replace("security=reality", "security=tls&allowInsecure=1")].join("\n"), lineNumbers: null };
    expect(insecureLinkLines(sent)).toEqual([2]);
    expect(describeInsecureLines(sent)).toBe(
      "Line 2 asks to skip certificate checks (insecure=1) without a pinSHA256. The bundled Xray checks certificates anyway, so its card is tagged insecure=1. If the server uses a self-signed certificate, add the link again with its pinSHA256 and remove the tagged profile."
    );
    expect(describeImportNotes(sent, { updated: 0 }, undefined)).toBe(
      "Line 1 was skipped because it starts with #. Line 2 asks to skip certificate checks (insecure=1) without a pinSHA256. The bundled Xray checks certificates anyway, so its card is tagged insecure=1. If the server uses a self-signed certificate, add the link again with its pinSHA256 and remove the tagged profile."
    );

    const kept: ImportBox = { text: [insecure, WAW, insecure.replace("insecure=1", "allowInsecure=1")].join("\n"), lineNumbers: [4, 9, 12] };
    expect(insecureLinkLines(kept)).toEqual([4, 12]);
    expect(describeInsecureLines(kept)).toBe(
      "Lines 4 and 12 ask to skip certificate checks (insecure=1) without a pinSHA256. The bundled Xray checks certificates anyway, so their cards are tagged insecure=1. If a server uses a self-signed certificate, add its link again with the server’s pinSHA256 and remove the tagged profile."
    );
    expect(describeInsecureLines({ text: [WAW, HEL].join("\n"), lineNumbers: null })).toBeUndefined();
  });

  it("falls back to counts when the match doesn't add up", () => {
    const sent: ImportBox = { text: TOKYO, lineNumbers: null };
    expect(describeImportNotes(sent, { updated: 3 }, undefined)).toBe("3 lines updated profiles you already had.");
    expect(describeImportNotes({ text: WAW, lineNumbers: null }, { updated: 0 }, undefined)).toBeUndefined();
  });

  it("says how many new profiles would pass the cap", async () => {
    const sent: ImportBox = { text: PASTE, lineNumbers: null };
    const match = await matchLinksToLibrary(sent, [tokyo]);
    expect(describeProfileLimit(9_990, match)).toBe(
      "These links would add 2 new profiles to the 9,990 you have, past the 10,000-profile limit, so nothing was added or updated. Remove profiles you don’t use, then import again."
    );
    expect(describeProfileLimit(9_990, undefined)).toMatch(/^These links would take your library past the 10,000-profile limit, so nothing/u);
  });

  it("names what an import added", () => {
    const before = [profile({ id: "a", name: "a" })];
    expect(importedSentence(before, [...before, profile({ id: "b", name: "jp-osa-ws" })])).toBe("jp-osa-ws is in Xray profiles.");
    expect(importedSentence(before, [profile({ id: "a", name: "a", updatedAt: "2026-10-06T10:00:00.000Z" }), profile({ id: "c", name: "c" })])).toBe("All 2 are in Xray profiles.");
  });
});
