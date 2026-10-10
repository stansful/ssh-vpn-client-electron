import { describe, expect, it } from "vitest";
import {
  buildFeed,
  copyEventsTitle,
  countEvents,
  countNewerThan,
  feedFooterText,
  formatActivityReport,
  formatEventsForCopy,
  hasActiveFilters,
  matchesFilters,
  messageParts,
  routineKind,
  routineNote,
  sourceChipTitle,
  summarizeGroup,
  toActivityEvents,
  EMPTY_FILTERS,
  type ActivityEvent
} from "../src/renderer/components/pages/activity/activity-feed.js";
import type { DiagnosticsEntry } from "../src/shared/types.js";

let counter = 0;
function entry(message: string, level: DiagnosticsEntry["level"] = "info", source?: DiagnosticsEntry["source"], at?: string): DiagnosticsEntry {
  counter += 1;
  return { id: `e${counter}`, at: at ?? new Date(Date.UTC(2026, 9, 6, 9, 0, counter)).toISOString(), level, message, source };
}

/** Oldest first, as the snapshot keeps them. */
function eventsOf(...entries: DiagnosticsEntry[]): ActivityEvent[] {
  return toActivityEvents(entries);
}

describe("routineKind", () => {
  it("recognises per-connection proxy notes, traffic summaries and Xray notices", () => {
    expect(routineKind({ level: "info", message: "SOCKS5 CONNECT x.com:443 from 127.0.0.1:62410." })).toBe("connection");
    expect(routineKind({ level: "info", message: "HTTP CONNECT tunnel opened for chatgpt.com:443." })).toBe("connection");
    expect(routineKind({ level: "info", message: "SOCKS5 tunnel opened for discord.com:443." })).toBe("connection");
    expect(routineKind({ level: "info", message: "SOCKS5 connection from 127.0.0.1:62410." })).toBe("connection");
    expect(routineKind({ level: "info", message: "Accepted local TCP connection from 127.0.0.1:5000." })).toBe("connection");
    expect(routineKind({ level: "info", message: "Local proxy activity: active=9, down=41.8 MB, up=2.6 MB since last check." })).toBe("traffic");
    expect(routineKind({ level: "info", message: "Xray: [Info] proxy/vless/outbound: tunneling request to tcp:x.com:443" })).toBe("xray");
  });

  it("never folds warnings, errors or ordinary events", () => {
    expect(routineKind({ level: "warning", message: "SOCKS5 tunnel opened for x.com:443." })).toBeUndefined();
    expect(routineKind({ level: "error", message: "Xray: [Info] something" })).toBeUndefined();
    expect(routineKind({ level: "info", message: "Connected to Frankfurt-01. Local proxy 127.0.0.1:50817." })).toBeUndefined();
    expect(routineKind({ level: "info", message: "Further proxy connection diagnostics are suppressed for this session." })).toBeUndefined();
  });
});

describe("toActivityEvents", () => {
  it("returns newest first with sources from the entry or the wording", () => {
    const events = eventsOf(entry("Connecting to 203.0.113.10:22 over SSH.", "info", "ssh"), entry("Update 2.3.0 is available for Windows x64."));
    expect(events.map((event) => event.source)).toEqual(["update", "ssh"]);
    expect(events[0].entry.message).toContain("Update");
  });

  it("keeps the same event object for the same entry", () => {
    const first = entry("Connected.", "info", "ssh");
    expect(toActivityEvents([first])[0]).toBe(toActivityEvents([first])[0]);
  });
});

describe("filters", () => {
  const events = eventsOf(
    entry("Connecting to 203.0.113.10:22 over SSH.", "info", "ssh"),
    entry("TUN adapter skipped: the app is not running as administrator.", "warning", "routing"),
    entry("Reconnect attempt could not be started: connect ENETUNREACH 203.0.113.10:22", "error", "ssh"),
    entry("Update 2.3.0 is available.", "info", "update")
  );

  it("matches level, sources and a case-insensitive search over the message and source name", () => {
    expect(events.filter((event) => matchesFilters(event, { ...EMPTY_FILTERS, level: "error" }))).toHaveLength(1);
    expect(events.filter((event) => matchesFilters(event, { ...EMPTY_FILTERS, sources: ["ssh", "update"] }))).toHaveLength(3);
    expect(events.filter((event) => matchesFilters(event, { ...EMPTY_FILTERS, query: "  203.0.113.10 " }))).toHaveLength(2);
    expect(events.filter((event) => matchesFilters(event, { ...EMPTY_FILTERS, query: "updates" }))).toHaveLength(1);
    expect(events.filter((event) => matchesFilters(event, { level: "info", sources: ["routing"], query: "" }))).toHaveLength(0);
  });

  it("knows when filters are active", () => {
    expect(hasActiveFilters(EMPTY_FILTERS)).toBe(false);
    expect(hasActiveFilters({ ...EMPTY_FILTERS, query: "   " })).toBe(false);
    expect(hasActiveFilters({ ...EMPTY_FILTERS, sources: ["app"] })).toBe(true);
  });

  it("counts levels and sources", () => {
    const counts = countEvents(events);
    expect(counts.total).toBe(4);
    expect(counts.levels).toEqual({ info: 2, warning: 1, error: 1 });
    expect(counts.sources).toEqual({ ssh: 2, xray: 0, routing: 1, update: 1, app: 0 });
  });
});

describe("buildFeed", () => {
  const traffic = (n: number): DiagnosticsEntry => entry(`Local proxy activity: active=${n}, down=1 MB, up=0.1 MB since last check.`, "info", "ssh");
  const opened = (host: string): DiagnosticsEntry => entry(`SOCKS5 CONNECT tunnel opened for ${host}:443.`, "info", "ssh");

  it("folds a run of routine entries but keeps the newest entry of the feed as a row", () => {
    const connected = entry("Connected to Frankfurt-01.", "info", "ssh");
    const run = [opened("a.com"), traffic(1), opened("b.com"), traffic(2)];
    const latest = traffic(3);
    const feed = buildFeed(eventsOf(connected, ...run, latest));
    expect(feed.map((item) => item.kind)).toEqual(["event", "group", "event"]);
    expect(feed[0].kind === "event" && feed[0].event.entry.id).toBe(latest.id);
    const group = feed[1];
    expect(group.kind === "group" && group.events.length).toBe(4);
    // The id follows the oldest member, so it survives new entries joining at the top.
    expect(group.id).toBe(`group-${run[0].id}`);
  });

  it("keeps short runs as rows and splits runs at other events", () => {
    const feed = buildFeed(eventsOf(traffic(1), traffic(2), entry("Tunnel check passed.", "info", "ssh"), traffic(3), entry("Done.", "info", "app")));
    expect(feed.every((item) => item.kind === "event")).toBe(true);
    expect(feed).toHaveLength(5);
  });

  it("does not fold warnings", () => {
    const feed = buildFeed(eventsOf(traffic(1), entry("SOCKS5 tunnel failed for x.com:443: timed out.", "warning", "ssh"), traffic(2), traffic(3), entry("Top.", "info", "app")));
    expect(feed.map((item) => item.kind)).toEqual(["event", "event", "event", "event", "event"]);
  });
});

describe("summarizeGroup", () => {
  it("describes the kinds, the time range and how many are not sampled", () => {
    const events = eventsOf(
      ...Array.from({ length: 6 }, (_, index) =>
        index % 2 === 0
          ? entry(`SOCKS5 CONNECT tunnel opened for h${index}.com:443.`, "info", "ssh", new Date(2026, 9, 6, 12, 12, 10 + index).toISOString())
          : entry("Local proxy activity: active=1, down=1 MB, up=0 B since last check.", "info", "ssh", new Date(2026, 9, 6, 12, 12, 10 + index).toISOString())
      )
    );
    const summary = summarizeGroup(events);
    expect(summary.countText).toBe("6 routine entries");
    expect(summary.note).toBe("proxy connections and 30-second traffic summaries · 12:12:10 – 12:12:15");
    expect(summary.time).toBe("12:12:15");
    expect(summary.samples).toHaveLength(4);
    expect(summary.samples[0].time).toBe("12:12:15");
    expect(summary.more).toBe("and 2 more like these. Copy the events to get all of them.");
  });

  it("names a single kind and lists three in a series", () => {
    const xray = eventsOf(entry("Xray: [Info] a", "info", "xray"), entry("Xray: [Info] b", "info", "xray"));
    expect(routineNote(xray)).toBe("Xray connection notices");
    const all = eventsOf(entry("Xray: [Info] a", "info", "xray"), entry("Local proxy activity: x", "info"), entry("SOCKS5 tunnel opened for a.com:443.", "info"));
    expect(routineNote(all)).toBe("proxy connections, 30-second traffic summaries and Xray connection notices");
    expect(summarizeGroup(xray).more).toBeUndefined();
  });
});

describe("messageParts", () => {
  it("sets hosts with ports and IP addresses in mono", () => {
    expect(messageParts("Tunnel check passed: youtube.com:443 answered in 184 ms.")).toEqual([
      { text: "Tunnel check passed: ", mono: false },
      { text: "youtube.com:443", mono: true },
      { text: " answered in 184 ms.", mono: false }
    ]);
    expect(messageParts("connect ENETUNREACH 203.0.113.10:22").map((part) => part.text)).toEqual(["connect ENETUNREACH ", "203.0.113.10:22"]);
    expect(messageParts("SOCKS5 tunnel opened for rr3---sn-4g5e6nzl.googlevideo.com:443.").filter((part) => part.mono).map((part) => part.text)).toEqual([
      "rr3---sn-4g5e6nzl.googlevideo.com:443"
    ]);
    expect(messageParts("Proxy at [2001:db8::1]:8080 is up.").filter((part) => part.mono).map((part) => part.text)).toEqual(["[2001:db8::1]:8080"]);
  });

  it("leaves versions, sizes and plain names alone", () => {
    expect(messageParts("Xray 25.9.11 started, down=41.8 MB, Connected to Frankfurt-01.")).toEqual([
      { text: "Xray 25.9.11 started, down=41.8 MB, Connected to Frankfurt-01.", mono: false }
    ]);
  });
});

describe("copy and labels", () => {
  it("copies events oldest first with level and source", () => {
    const events = eventsOf(entry("First.", "info", "ssh", "2026-10-06T09:00:00.000Z"), entry("Second.", "warning", "routing", "2026-10-06T09:00:01.000Z"));
    expect(formatEventsForCopy(events)).toBe("[2026-10-06T09:00:00.000Z] INFO SSH: First.\n[2026-10-06T09:00:01.000Z] WARNING Routing: Second.");
  });

  it("builds a report of everything Clear deletes", () => {
    const report = formatActivityReport({
      events: eventsOf(entry("Connected.", "info", "ssh", "2026-10-06T09:00:00.000Z")),
      attention: [{ at: "2026-10-06T08:00:00.000Z", level: "warning", title: "TUN adapter not used", message: "Apps may go direct." }],
      logText: "[2026-10-06T09:00:00.000Z] INFO Connected.",
      now: new Date("2026-10-06T10:00:00.000Z")
    });
    expect(report).toBe(
      [
        "Shadow activity, copied 2026-10-06T10:00:00.000Z",
        "",
        "Needs your attention (1)",
        "[2026-10-06T08:00:00.000Z] WARNING TUN adapter not used. Apps may go direct.",
        "",
        "Live events (1)",
        "[2026-10-06T09:00:00.000Z] INFO SSH: Connected.",
        "",
        "main.log (last 1 MB)",
        "[2026-10-06T09:00:00.000Z] INFO Connected."
      ].join("\n")
    );
    expect(formatActivityReport({ events: [], attention: [], logText: undefined, now: new Date(0) })).toContain("Live events (0)\nNone\n\nmain.log (last 1 MB)\nCouldn't be read.");
  });

  it("words the copy button, footer and source chips", () => {
    expect(copyEventsTitle(12, 40, true)).toBe("Copy the 12 events that match");
    expect(copyEventsTitle(1, 40, true)).toBe("Copy the 1 event that matches");
    expect(copyEventsTitle(40, 1312, false)).toBe("Copy all 1,312 events");
    expect(feedFooterText(3, 18, true)).toBe("Showing 3 of 18");
    expect(feedFooterText(18, 18, false)).toBe("Showing all 18, newest first");
    expect(sourceChipTitle("xray", 0, false)).toBe("No Xray events in this connection");
    expect(sourceChipTitle("update", 2, false)).toBe("Show Updates events");
    expect(sourceChipTitle("ssh", 2, true)).toBe("Stop filtering by SSH");
  });
});

describe("countNewerThan", () => {
  it("counts entries that arrived after the pause", () => {
    const a = entry("a");
    const b = entry("b");
    const c = entry("c");
    const d = entry("d");
    expect(countNewerThan([a, b], [a, b, c, d])).toBe(2);
    expect(countNewerThan([a, b], [a, b])).toBe(0);
    // A new connect cleared the list: all of it is new.
    expect(countNewerThan([a, b], [c])).toBe(1);
    expect(countNewerThan([], [c, d])).toBe(2);
  });
});
