import { describe, expect, it } from "vitest";
import { TunnelTransitionTracker } from "../src/main/app/session-transitions.js";

describe("tunnel transition tracker", () => {
  it("announces a dropped tunnel once and its return", () => {
    const tracker = new TunnelTransitionTracker();
    expect(tracker.observe("Connecting", "")).toEqual([]);
    expect(tracker.observe("Connected", "")).toEqual([]);
    expect(tracker.observe("Reconnecting", "keepalive timed out")).toEqual([{ kind: "lost" }]);
    expect(tracker.observe("Reconnecting", "attempt 2")).toEqual([]);
    expect(tracker.observe("Connecting", "")).toEqual([]);
    expect(tracker.observe("Connected", "")).toEqual([{ kind: "restored" }]);
    expect(tracker.observe("Connected", "")).toEqual([]);
  });

  it("does not call a first attempt that fails 'lost'", () => {
    const tracker = new TunnelTransitionTracker();
    tracker.observe("Connecting", "");
    expect(tracker.observe("Reconnecting", "retrying")).toEqual([]);
    expect(tracker.observe("Error", "auth failed")).toEqual([]);
    expect(tracker.hasPendingStop).toBe(false);
  });

  it("reports a stop when reconnecting gives up", () => {
    const tracker = new TunnelTransitionTracker();
    tracker.observe("Connected", "");
    tracker.observe("Reconnecting", "");
    expect(tracker.isRecovering).toBe(true);
    expect(tracker.observe("Error", "Reconnect stopped.")).toEqual([]);
    expect(tracker.hasPendingStop).toBe(true);
    expect(tracker.settle()).toEqual([{ kind: "stopped", reason: "Reconnect stopped." }]);
    expect(tracker.isRecovering).toBe(false);
    // The story is over until the next connect.
    expect(tracker.observe("Reconnecting", "")).toEqual([]);
  });

  it("keeps a reconnect loop going through a failed Xray restart attempt", () => {
    const tracker = new TunnelTransitionTracker();
    tracker.observe("Connected", "");
    tracker.observe("Error", "Xray runtime exited with code 1.");
    expect(tracker.observe("Reconnecting", "Restarting Xray transport after failure")).toEqual([{ kind: "lost" }]);
    tracker.observe("Connecting", "");
    // The restarted process dies during startup: not a final stop yet.
    expect(tracker.observe("Error", "Xray runtime exited with code 1.")).toEqual([]);
    expect(tracker.isRecovering).toBe(true);
    expect(tracker.observe("Reconnecting", "Restarting Xray transport after failure")).toEqual([]);
    expect(tracker.hasPendingStop).toBe(false);
    expect(tracker.settle()).toEqual([]);
    tracker.observe("Connecting", "");
    expect(tracker.observe("Connected", "")).toEqual([{ kind: "restored" }]);
    expect(tracker.isRecovering).toBe(false);
  });

  it("waits to see whether an Error from a live session turns into a restart", () => {
    const xray = new TunnelTransitionTracker();
    xray.observe("Connected", "");
    expect(xray.observe("Error", "Xray runtime exited with code 1.")).toEqual([]);
    expect(xray.hasPendingStop).toBe(true);
    expect(xray.observe("Reconnecting", "Restarting Xray transport after failure")).toEqual([{ kind: "lost" }]);
    expect(xray.settle()).toEqual([]);

    const ssh = new TunnelTransitionTracker();
    ssh.observe("Connected", "");
    ssh.observe("Error", "Host key changed.");
    expect(ssh.settle()).toEqual([{ kind: "stopped", reason: "Host key changed." }]);
    expect(ssh.settle()).toEqual([]);
  });

  it("forgets everything on a disconnect or reset", () => {
    const tracker = new TunnelTransitionTracker();
    tracker.observe("Connected", "");
    tracker.observe("Disconnecting", "");
    expect(tracker.observe("Reconnecting", "")).toEqual([]);

    tracker.observe("Connected", "");
    tracker.reset();
    expect(tracker.observe("Reconnecting", "")).toEqual([]);
  });
});
