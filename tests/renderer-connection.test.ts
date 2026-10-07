import { describe, expect, it } from "vitest";
import {
  hysteria2CheckState,
  isConnectionSelectionLocked,
  presentConnection,
  presentGlobalStatus,
  type ConnectionInput
} from "../src/renderer/lib/connection.js";
import type { ConnectionState, TunnelCheckResult } from "../src/shared/types.js";
import { createTestRuntime } from "./renderer-fixtures.js";

function input(state: ConnectionState, overrides: Partial<ConnectionInput> = {}, message = ""): ConnectionInput {
  return {
    transport: "ssh",
    activeTransport: "ssh",
    runtime: createTestRuntime({ state, message }),
    platform: "windows",
    routingMode: "selected-rules",
    targetName: "Frankfurt-01",
    targetAddress: "203.0.113.10:22",
    ...overrides
  };
}

describe("Connect presentation", () => {
  it.each<[ConnectionState, string, string, string, boolean]>([
    ["Disconnected", "Off", "Not connected", "Tap to connect", false],
    ["Connecting", "Connecting", "Connecting…", "Connecting…", true],
    ["Connected", "Protected", "Connected", "Tap to disconnect", false],
    ["Reconnecting", "Reconnecting", "Reconnecting…", "Tap to stop", false],
    ["Disconnecting", "Disconnecting", "Stopping…", "Stopping…", true],
    ["Error", "Needs attention", "Error", "Tap to retry", false]
  ])("maps %s to its word, badge and orb label", (state, word, badge, orbLabel, orbDisabled) => {
    const view = presentConnection(input(state));
    expect(view.stateWord).toBe(word);
    expect(view.badge.text).toBe(badge);
    expect(view.orbLabel).toBe(orbLabel);
    expect(view.orbDisabled).toBe(orbDisabled);
  });

  it("marks busy states with a spinner and an ellipsis", () => {
    for (const state of ["Connecting", "Reconnecting", "Disconnecting"] satisfies ConnectionState[]) {
      const view = presentConnection(input(state));
      expect(view.badge.spinner).toBe(true);
      expect(view.badge.text.endsWith("…")).toBe(true);
    }
  });

  it("reads Proxy ready on macOS and Linux, where traffic is not redirected", () => {
    expect(presentConnection(input("Connected", { platform: "macos" })).stateWord).toBe("Proxy ready");
    expect(presentConnection(input("Connected", { platform: "linux" })).description).toContain("Linux won't send app traffic");
    expect(presentGlobalStatus({ runtime: createTestRuntime({ state: "Connected" }), activeTransport: "ssh", platform: "macos", targetName: "Frankfurt-01" }).title).toBe("Proxy ready");
  });

  it("never calls a simulator session Protected", () => {
    const view = presentConnection(input("Connected", { runtime: createTestRuntime({ state: "Connected", transport: "simulator", realTunnelAvailable: false }) }));
    expect(view.stateWord).toBe("Preview only");
    expect(view.orbState).toBe("preview");
    expect(view.badge).toEqual({ text: "Not routing", tone: "warn", spinner: false });
  });

  it("shows the reconnect attempt and flags errors that won't clear on their own", () => {
    const routine = presentConnection(input("Reconnecting", {}, "Reconnecting to 203.0.113.10:22 (attempt 3)."));
    expect(routine.badge.text).toBe("Attempt 3…");
    expect(routine.primaryAction).toBe("stop-reconnecting");

    const stuck = presentConnection(input("Reconnecting", {}, "Reconnect attempt 7 failed: getaddrinfo ENOTFOUND helsinki.example.net"));
    expect(stuck.reconnectReason?.likelyStuck).toBe(true);
    expect(stuck.description).toBe("Still trying 203.0.113.10:22. Retries keep going until you stop them.");
  });

  it("explains blocked, unsupported and first-run Off states and disables the orb", () => {
    const blocked = presentConnection(input("Disconnected", { routingBlocked: true }));
    expect(blocked).toMatchObject({ orbState: "blocked", orbDisabled: true, orbLabel: "Add a target first" });
    expect(blocked.badge.text).toBe("Blocked by routing");

    const unsupported = presentConnection(input("Disconnected", { transport: "xray", activeTransport: "xray", unsupportedTarget: true, targetName: "lab-unknown" }));
    expect(unsupported.badge.text).toBe("Can't connect");
    expect(unsupported.orbLabel).toBe("Pick another profile");

    const firstRun = presentConnection(input("Disconnected", { noTarget: true }));
    expect(firstRun.orbLabel).toBe("Add a server first");
    expect(firstRun.orbDisabled).toBe(true);
    expect(presentConnection(input("Disconnected", { transport: "xray", activeTransport: "xray", noTarget: true })).description).toBe(
      "Add or import an Xray profile to carry your traffic. A VLESS, VMess, Trojan or Hysteria 2 link is all you need."
    );
  });

  it("names the Hysteria 2 profile Xray is starting", () => {
    const view = presentConnection(
      input("Connecting", { transport: "xray", activeTransport: "xray", targetName: "fi-hel-hy2", targetAddress: "hel.example.net:443,20000-30000", protocolLabel: "Hysteria 2" })
    );
    expect(view.description).toBe("Starting the Xray engine with Hysteria 2 profile fi-hel-hy2…");
  });

  it("reads Off on the inactive transport and offers a switch", () => {
    const view = presentConnection(input("Connected", { transport: "ssh", activeTransport: "xray" }));
    expect(view.stateWord).toBe("Off");
    expect(view.otherTransportActive).toBe(true);
    expect(view.primaryAction).toBe("switch");
    expect(view.orbLabel).toBe("Tap to switch to SSH");
  });

  it("surfaces useful error text and ignores generic restatements", () => {
    expect(presentConnection(input("Error", {}, "Authentication failed.")).description).toBe("Authentication failed.");
    expect(presentConnection(input("Error", {}, "Disconnected.")).errorDetail).toBeUndefined();
  });

  it("locks server selection for every in-flight or active session", () => {
    expect(isConnectionSelectionLocked("Disconnected")).toBe(false);
    expect(isConnectionSelectionLocked("Error")).toBe(false);
    for (const state of ["Connecting", "Connected", "Reconnecting", "Disconnecting"] satisfies ConnectionState[]) {
      expect(isConnectionSelectionLocked(state)).toBe(true);
    }
  });
});

describe("global status card", () => {
  it("names the active transport and target", () => {
    const status = presentGlobalStatus({ runtime: createTestRuntime({ state: "Connected" }), activeTransport: "ssh", platform: "windows", targetName: "Frankfurt-01" });
    expect(status).toMatchObject({ tone: "ok", title: "Protected", subtitle: "SSH · Frankfurt-01" });
    expect(status.ariaLabel).toBe("Protected, SSH · Frankfurt-01. Open Connect.");
  });

  it("invites a connect when off", () => {
    const status = presentGlobalStatus({ runtime: createTestRuntime(), activeTransport: "xray", platform: "windows" });
    expect(status).toMatchObject({ tone: "neutral", title: "Not connected", subtitle: "Tap Connect to start" });
  });
});

// Xray reports Connected for Hysteria 2 as soon as its local proxy listens,
// even when UDP to the server is blocked: only the tunnel check proves it.
describe("a connected Hysteria 2 session", () => {
  const connectedAt = "2026-10-07T10:00:00.000Z";
  const runtime = createTestRuntime({ state: "Connected", transport: "xray", connectedAt, activeConfigId: "hel", activeConfigName: "fi-hel-hy2" });
  const check = (overrides: Partial<TunnelCheckResult> = {}): TunnelCheckResult => ({
    endpoint: "youtube.com:443",
    ok: true,
    at: "2026-10-07T10:00:02.000Z",
    message: "youtube.com:443 answered the TLS handshake.",
    transport: "xray",
    ...overrides
  });
  const failed = check({ ok: false, message: "The tunnel opened a connection to youtube.com:443 but nothing came back within 12s." });
  const state = (lastTunnelCheck?: TunnelCheckResult, overrides: Partial<Parameters<typeof hysteria2CheckState>[0]> = {}) =>
    hysteria2CheckState({ runtime, activeTransport: "xray", protocol: "hysteria2", lastTunnelCheck, ...overrides });
  const hero = (hysteria2Check: ConnectionInput["hysteria2Check"], overrides: Partial<ConnectionInput> = {}) =>
    presentConnection(
      input("Connected", {
        transport: "xray",
        activeTransport: "xray",
        runtime,
        targetName: "fi-hel-hy2",
        protocolLabel: "Hysteria 2",
        hysteria2Check,
        ...overrides
      })
    );

  it("reads the latest check made since this session connected", () => {
    expect(state()).toBe("pending");
    expect(state(check())).toBe("passed");
    expect(state(failed)).toBe("failed");
    expect(state(check({ note: true, endpoint: "smtp.example.com:25" }))).toBe("unverified");
    // From before an Xray restart, or of the SSH tunnel: not this session's.
    expect(state(check({ ...failed, at: "2026-10-07T09:59:58.000Z" }))).toBe("pending");
    expect(state(check({ transport: "ssh" }))).toBe("pending");
    expect(state(failed, { runtime: createTestRuntime({ state: "Connected", transport: "xray" }) })).toBe("failed");
    // Only connected Hysteria 2 sessions on Xray get one.
    expect(state(failed, { protocol: "vless" })).toBeUndefined();
    expect(state(failed, { protocol: undefined })).toBeUndefined();
    expect(state(failed, { activeTransport: "ssh" })).toBeUndefined();
    expect(state(failed, { runtime: { ...runtime, state: "Reconnecting" } })).toBeUndefined();
  });

  it("doesn't call it Protected when the tunnel check failed", () => {
    const view = hero("failed");
    expect(view).toMatchObject({
      phase: "connected",
      heroState: "preview",
      orbState: "preview",
      tone: "warn",
      stateWord: "Check failed",
      badge: { text: "Connected", tone: "warn", spinner: false },
      primaryAction: "disconnect",
      orbLabel: "Tap to disconnect",
      pickerLocked: true,
      session: true
    });
    expect(view.description).toBe(
      "Xray is up, but the tunnel check failed. Hysteria 2 needs UDP to reach the server; the tunnel check lists what to try."
    );
    expect(hero("failed", { platform: "macos" }).stateWord).toBe("Check failed");
    expect(hero("failed", { routingMode: "proxy-all" }).description).not.toMatch(/All your traffic/u);
  });

  it("hedges until a check passes, and claims the route only after one did", () => {
    const pending = hero("pending", { routingMode: "proxy-all" });
    expect(pending).toMatchObject({ stateWord: "Protected", tone: "ok", heroState: "connected" });
    expect(pending.description).toBe("Xray is up. Hysteria 2 can’t confirm the server until the tunnel check passes.");
    expect(hero("unverified").description).toBe(
      "Xray is up, but the check endpoint sent nothing back, so the Hysteria 2 server isn’t confirmed. Use a TLS or HTTP check endpoint to confirm it."
    );
    expect(hero("passed", { routingMode: "proxy-all" }).description).toBe("All your traffic now goes through fi-hel-hy2.");
  });

  it("leaves other protocols, SSH and other phases as they were", () => {
    expect(hero(undefined, { routingMode: "proxy-all" })).toMatchObject({ stateWord: "Protected", description: "All your traffic now goes through fi-hel-hy2." });
    // The SSH tab never reads an Xray check.
    expect(presentConnection(input("Connected", { hysteria2Check: "failed" })).stateWord).toBe("Protected");
    expect(hero("failed", { transport: "ssh" }).stateWord).toBe("Off");
  });

  it("says the same in the global status card", () => {
    const status = (hysteria2Check: ConnectionInput["hysteria2Check"], platform: "windows" | "macos" = "windows") =>
      presentGlobalStatus({ runtime, activeTransport: "xray", platform, targetName: "fi-hel-hy2", hysteria2Check });
    expect(status("failed")).toMatchObject({ tone: "warn", title: "Check failed", icon: "warn", subtitle: "Xray · fi-hel-hy2" });
    expect(status("failed", "macos").title).toBe("Check failed");
    expect(status("pending")).toMatchObject({ tone: "ok", title: "Protected" });
    expect(status(undefined)).toMatchObject({ tone: "ok", title: "Protected" });
  });
});
