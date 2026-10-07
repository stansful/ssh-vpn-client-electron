import { describe, expect, it } from "vitest";
import { attentionAction, attentionTone, attentionWhen, sessionStartedAt } from "../src/renderer/components/pages/activity/activity-attention.js";

describe("attentionAction", () => {
  it("opens routing for a split tunnel that lost its targets", () => {
    expect(attentionAction({ kind: "split-tunnel-no-targets", level: "error", message: "" })).toMatchObject({ type: "navigate", view: "routing", label: "Open routing" });
  });

  it("offers setup steps when TUN never started, and Connect when it stopped mid-session", () => {
    expect(attentionAction({ kind: "tun-unavailable", level: "warning", message: "" })).toEqual({ type: "tun-steps" });
    expect(attentionAction({ kind: "tun-unavailable", level: "error", message: "Reconnect to bring it back." })).toMatchObject({ view: "connect" });
  });

  it("follows the advice in the message", () => {
    expect(attentionAction({ kind: "reconnect-stopped", level: "error", message: "Check the server and its key in SSH servers, then connect again." })).toMatchObject({
      view: "servers",
      label: "Open SSH servers"
    });
    expect(attentionAction({ kind: "auto-connect-skipped", level: "warning", message: "Add a target in Routing, then connect." })).toMatchObject({ view: "routing" });
    expect(attentionAction({ kind: "auto-connect-failed", level: "error", message: "Add the profile again in Xray profiles." })).toMatchObject({ view: "profiles" });
    expect(attentionAction({ kind: "auto-connect-failed", level: "error", message: "Couldn’t connect to Frankfurt-01 at start: timed out." })).toMatchObject({ view: "connect" });
    expect(attentionAction({ kind: "auto-connect-skipped", level: "warning", message: "Something else." })).toBeUndefined();
  });

  it("has nothing to offer for repaired settings or unreadable storage", () => {
    expect(attentionAction({ kind: "system-proxy-recovered", level: "info", message: "" })).toBeUndefined();
    expect(attentionAction({ kind: "storage-unreadable", level: "error", message: "" })).toBeUndefined();
    expect(attentionAction({ kind: "other", level: "warning", message: "" })).toBeUndefined();
  });
});

describe("attentionTone", () => {
  it("maps levels to tones", () => {
    expect(attentionTone("error")).toBe("danger");
    expect(attentionTone("warning")).toBe("warn");
    expect(attentionTone("info")).toBe("info");
  });
});

describe("session timing", () => {
  const diagnostics = [{ at: "2026-10-06T09:03:51.000Z" }, { at: "2026-10-06T09:03:53.000Z" }];

  it("takes the session start from the oldest live event or connectedAt, whichever is earlier", () => {
    expect(sessionStartedAt("Connected", "2026-10-06T09:03:53.000Z", diagnostics)).toBe("2026-10-06T09:03:51.000Z");
    expect(sessionStartedAt("Reconnecting", "2026-10-06T09:00:00.000Z", diagnostics)).toBe("2026-10-06T09:00:00.000Z");
    expect(sessionStartedAt("Connecting", undefined, [])).toBeUndefined();
    expect(sessionStartedAt("Disconnected", "2026-10-06T09:03:53.000Z", diagnostics)).toBeUndefined();
  });

  it("labels events against the running session, else relative to now", () => {
    const start = "2026-10-06T09:03:51.000Z";
    expect(attentionWhen("2026-10-06T09:03:52.000Z", start)).toBe("This connection");
    expect(attentionWhen("2026-10-06T09:01:44.000Z", start)).toBe("Previous connection");
    const now = new Date(2026, 9, 6, 12, 30, 0);
    expect(attentionWhen(new Date(2026, 9, 6, 12, 25, 0).toISOString(), undefined, now)).toBe("5 min ago");
    expect(attentionWhen(new Date(2026, 9, 6, 12, 29, 50).toISOString(), undefined, now)).toBe("Just now");
  });
});
