import { describe, expect, it } from "vitest";
import { TunnelCheckSessionGuard } from "../src/main/app/tunnel-check-guard.js";

const connectedA = { state: "Connected" as const, activeConfigId: "a", connectedAt: "2026-10-06T10:00:00.000Z" };
const connectedB = { state: "Connected" as const, activeConfigId: "b", connectedAt: "2026-10-06T10:05:00.000Z" };

describe("tunnel check session guard", () => {
  it("publishes a check that finishes on the session it started on", () => {
    const guard = new TunnelCheckSessionGuard();
    guard.observe("ssh", connectedA);
    const ticket = guard.begin("ssh", "Frankfurt-01");

    // Status updates of the same session (proxy ready, new message) keep it.
    guard.observe("ssh", { ...connectedA });
    expect(guard.accepts(ticket, "ssh", "Connected")).toBe(true);
    expect(ticket.targetName).toBe("Frankfurt-01");
  });

  it("drops a check whose session was replaced by another server while it ran", () => {
    const guard = new TunnelCheckSessionGuard();
    guard.observe("ssh", connectedA);
    const ticket = guard.begin("ssh", "Frankfurt-01");

    guard.reset();
    guard.observe("ssh", { state: "Disconnecting", activeConfigId: "a", connectedAt: undefined });
    guard.observe("ssh", { state: "Connecting", activeConfigId: "b", connectedAt: undefined });
    guard.observe("ssh", connectedB);

    expect(guard.accepts(ticket, "ssh", "Connected")).toBe(false);
  });

  it("drops a check that finishes after a disconnect, or on another transport", () => {
    const guard = new TunnelCheckSessionGuard();
    guard.observe("ssh", connectedA);
    const ticket = guard.begin("ssh");

    expect(guard.accepts(ticket, "xray", "Connected")).toBe(false);
    guard.observe("ssh", { state: "Disconnected", activeConfigId: undefined, connectedAt: undefined });
    expect(guard.accepts(ticket, "ssh", "Disconnected")).toBe(false);
  });

  it("drops a check that started before a reconnect brought the session back", () => {
    const guard = new TunnelCheckSessionGuard();
    guard.observe("xray", connectedA);
    const ticket = guard.begin("xray");

    guard.observe("xray", { state: "Error", activeConfigId: "a", connectedAt: connectedA.connectedAt });
    guard.observe("xray", { ...connectedA, connectedAt: "2026-10-06T10:01:00.000Z" });

    expect(guard.accepts(ticket, "xray", "Connected")).toBe(false);
    expect(guard.accepts(guard.begin("xray"), "xray", "Connected")).toBe(true);
  });
});
