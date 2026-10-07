import { describe, expect, it } from "vitest";
import {
  baseName,
  clearDescription,
  clearedToastText,
  describeLogSize,
  fileManagerName,
  firstNewLine,
  formatLogSize,
  LOG_READ_LIMIT_BYTES,
  logReadFailure,
  parseLogContent,
  parseLogLine,
  utcOffsetNote,
  withTrailingSeparator,
  type LogRead
} from "../src/renderer/components/pages/activity/activity-log.js";

const PATH = "C:\\Users\\alex\\AppData\\Roaming\\Shadow SSH\\logs\\main.log";

describe("parseLogLine", () => {
  it("splits the timestamp, level, Xray prefix and message", () => {
    expect(parseLogLine("[2026-10-06T08:57:40.093Z] ERROR Xray: [Error] dial tcp 185.244.30.9:443: i/o timeout")).toEqual({
      raw: "[2026-10-06T08:57:40.093Z] ERROR Xray: [Error] dial tcp 185.244.30.9:443: i/o timeout",
      timestamp: "2026-10-06T08:57:40.093Z",
      levelText: "ERROR",
      tone: "error",
      xray: true,
      message: "[Error] dial tcp 185.244.30.9:443: i/o timeout"
    });
    expect(parseLogLine("[2026-10-06T08:41:04.311Z] WARNING DNS lookup failed.")).toMatchObject({ levelText: "WARNING", tone: "warn", xray: false, message: "DNS lookup failed." });
    expect(parseLogLine("[2026-10-06T08:41:04.311Z] ATTENTION tun-unavailable: TUN adapter not used")).toMatchObject({ levelText: "ATTENTION", tone: "warn" });
  });

  it("keeps lines without a level or timestamp readable", () => {
    expect(parseLogLine("[2026-10-06T08:40:00.000Z] Storage initialized before renderer startup.")).toMatchObject({
      timestamp: "2026-10-06T08:40:00.000Z",
      levelText: undefined,
      tone: undefined,
      message: "Storage initialized before renderer startup."
    });
    expect(parseLogLine("    at Object.openSync (node:fs:573:18)")).toEqual({ raw: "    at Object.openSync (node:fs:573:18)", xray: false, message: "    at Object.openSync (node:fs:573:18)" });
  });
});

describe("parseLogContent", () => {
  it("reads the header path and the lines", () => {
    const read = parseLogContent(`### ${PATH}\n[2026-10-06T08:40:12.418Z] INFO Started.\n[2026-10-06T08:41:03.902Z] INFO Connecting.\n`);
    expect(read.state).toBe("lines");
    if (read.state !== "lines") {
      return;
    }
    expect(read.path).toBe(PATH);
    expect(read.lines.map((line) => line.message)).toEqual(["Started.", "Connecting."]);
    expect(read.text).toBe("[2026-10-06T08:40:12.418Z] INFO Started.\n[2026-10-06T08:41:03.902Z] INFO Connecting.");
    expect(read.bytes).toBe(new TextEncoder().encode(read.text).length);
    expect(read.truncated).toBe(false);
  });

  it("accepts content without a header (browser preview)", () => {
    const read = parseLogContent("[2026-10-06T08:40:12.418Z] INFO Started.");
    expect(read).toMatchObject({ state: "lines", path: undefined });
  });

  it("reports an empty file and an unreadable one", () => {
    expect(parseLogContent("")).toEqual({ state: "empty", path: undefined });
    expect(parseLogContent(`### ${PATH}\n`)).toEqual({ state: "empty", path: PATH });
    expect(parseLogContent(`### ${PATH}\nUnable to read log file: EBUSY: resource busy or locked, open 'main.log'`)).toEqual({
      state: "error",
      path: PATH,
      message: "EBUSY: resource busy or locked, open 'main.log'",
      details: ["Unable to read log file: EBUSY: resource busy or locked, open 'main.log'"]
    });
  });

  it("treats a read at the 1 MB limit as cut", () => {
    const line = `[2026-10-06T08:40:12.418Z] INFO ${"x".repeat(990)}`;
    const content = Array.from({ length: Math.ceil(LOG_READ_LIMIT_BYTES / (line.length + 1)) }, () => line).join("\n");
    const read = parseLogContent(content);
    expect(read.state === "lines" && read.truncated).toBe(true);
  });
});

describe("firstNewLine", () => {
  const read = (...messages: string[]): LogRead => parseLogContent(messages.map((message, index) => `[2026-10-06T08:40:0${index}.000Z] INFO ${message}`).join("\n"));

  it("marks nothing new on the first read", () => {
    const first = read("a", "b");
    expect(firstNewLine(undefined, first)).toBe(2);
  });

  it("marks the lines after the previous last line", () => {
    const before = read("a", "b");
    const after = read("a", "b", "c", "d");
    expect(firstNewLine(before, after)).toBe(2);
    expect(firstNewLine(after, after)).toBe(4);
  });

  it("marks everything when the file was emptied in between or the old tail is gone", () => {
    expect(firstNewLine(parseLogContent(""), read("a"))).toBe(0);
    expect(firstNewLine(read("x"), read("a", "b"))).toBe(0);
    expect(firstNewLine(logReadFailure("EBUSY"), read("a"))).toBe(1);
  });
});

describe("sizes", () => {
  it("formats binary sizes like the limits", () => {
    expect(formatLogSize(0)).toBe("0 KB");
    expect(formatLogSize(20)).toBe("0.1 KB");
    expect(formatLogSize(5 * 1024 + 300)).toBe("5.3 KB");
    expect(formatLogSize(300 * 1024)).toBe("300 KB");
    expect(formatLogSize(1.2 * 1024 * 1024)).toBe("1.2 MB");
  });

  it("describes what a read says about main.log and its archives", () => {
    expect(describeLogSize(undefined)).toEqual({ archives: "unknown" });
    expect(describeLogSize(logReadFailure("EBUSY"))).toEqual({ archives: "unknown" });
    expect(describeLogSize(parseLogContent(""))).toMatchObject({ mainSize: "0 KB", archives: "none", tabCount: "Empty", capPercent: 0 });
    const small = describeLogSize(parseLogContent("[2026-10-06T08:40:12.418Z] INFO Started."));
    expect(small).toMatchObject({ archives: "none", meta: `${small.mainSize} of 5 MB · no archives` });
    expect(small.capPercent).toBeGreaterThan(0);
    const line = `[2026-10-06T08:40:12.418Z] INFO ${"x".repeat(990)}`;
    const big = parseLogContent(Array.from({ length: 1100 }, () => line).join("\n"));
    expect(describeLogSize(big)).toEqual({ mainSize: "1 MB or more", archives: "maybe", meta: "1 MB or more · only the last 1 MB is shown", tabCount: "1 MB+" });
  });

  it("uses the sizes on disk when the main process reports them", () => {
    const mb = 1024 * 1024;
    const files = [
      { path: PATH, size: 1.2 * mb, exists: true },
      { path: `${PATH}.1`, size: 5 * mb, exists: true },
      { path: `${PATH}.2`, size: 5 * mb, exists: true }
    ];
    const line = `[2026-10-06T08:40:12.418Z] INFO ${"x".repeat(990)}`;
    const big = parseLogContent(Array.from({ length: 1100 }, () => line).join("\n"));
    expect(describeLogSize(big, files)).toEqual({
      mainSize: "1.2 MB",
      archives: "present",
      archiveCount: 2,
      archiveSizes: ["5.0 MB", "5.0 MB"],
      meta: "1.2 MB of 5 MB · 2 archives",
      capPercent: 24,
      tabCount: "1.2 MB"
    });
    const cleared = [
      { path: PATH, size: 0, exists: true },
      { path: `${PATH}.1`, size: 0, exists: false },
      { path: `${PATH}.2`, size: 0, exists: false }
    ];
    expect(describeLogSize(logReadFailure("EBUSY"), cleared)).toMatchObject({
      archives: "none",
      archiveCount: 0,
      archiveSizes: [undefined, undefined],
      meta: "0 KB of 5 MB · no archives",
      tabCount: "Empty"
    });
  });
});

describe("copy helpers", () => {
  it("states the UTC offset of the local clock", () => {
    const at = (offsetMinutes: number): Date => ({ getTimezoneOffset: () => offsetMinutes }) as Date;
    expect(utcOffsetNote(at(-180))).toBe("Times are UTC, 3 hours behind your clock.");
    expect(utcOffsetNote(at(-60))).toBe("Times are UTC, 1 hour behind your clock.");
    expect(utcOffsetNote(at(-330))).toBe("Times are UTC, 5 hours 30 minutes behind your clock.");
    expect(utcOffsetNote(at(300))).toBe("Times are UTC, 5 hours ahead of your clock.");
    expect(utcOffsetNote(at(0))).toBe("Times are UTC, the same as your clock.");
  });

  it("names the file manager and paths", () => {
    expect(fileManagerName("windows")).toBe("File Explorer");
    expect(fileManagerName("macos")).toBe("Finder");
    expect(fileManagerName("linux")).toBe("your file manager");
    expect(baseName(PATH)).toBe("main.log");
    expect(baseName("/home/alex/.config/Shadow SSH/logs/main.log.2")).toBe("main.log.2");
    expect(withTrailingSeparator("C:\\logs")).toBe("C:\\logs\\");
    expect(withTrailingSeparator("/var/logs")).toBe("/var/logs/");
    expect(withTrailingSeparator("/var/logs/")).toBe("/var/logs/");
  });

  it("words the Clear confirmation and its toast", () => {
    expect(clearDescription({ liveCount: 312, attentionCount: 2, archives: "maybe" })).toBe(
      "This deletes main.log, its archives and the 312 live events from this session. It can’t be undone."
    );
    expect(clearDescription({ liveCount: 1, attentionCount: 0, archives: "none" })).toBe("This deletes main.log and the 1 live event from this session. It can’t be undone.");
    expect(clearDescription({ liveCount: 0, attentionCount: 0, archives: "none" })).toBe("This empties main.log. It can’t be undone.");
    expect(clearedToastText({ liveCount: 1312, attentionCount: 0, archives: "maybe" })).toBe("main.log, its archives and 1,312 events were deleted.");
    expect(clearedToastText({ liveCount: 4, attentionCount: 0, archives: "none" })).toBe("main.log and 4 events were deleted.");
    expect(clearedToastText({ liveCount: 0, attentionCount: 0, archives: "none" })).toBe("main.log was emptied.");
  });

  it("counts the archives when their sizes are known", () => {
    expect(clearDescription({ liveCount: 312, attentionCount: 0, archives: "present", archiveCount: 2 })).toBe(
      "This deletes main.log, its 2 archives and the 312 live events from this session. It can’t be undone."
    );
    expect(clearDescription({ liveCount: 0, attentionCount: 0, archives: "present", archiveCount: 1 })).toBe(
      "This deletes main.log and its archive. It can’t be undone."
    );
    expect(clearedToastText({ liveCount: 312, attentionCount: 0, archives: "present", archiveCount: 2 })).toBe(
      "main.log, its 2 archives and 312 events were deleted."
    );
  });
});
