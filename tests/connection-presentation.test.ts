import { describe, expect, it } from "vitest";
import {
  isConnectionSelectionLocked,
  sshConnectionPresentation
} from "../src/renderer/lib/connection-presentation.js";
import type { ConnectionState } from "../src/shared/types.js";

describe("SSH connection presentation", () => {
  it.each<[ConnectionState, string, string, boolean]>([
    ["Disconnected", "Ready to connect", "Connect", false],
    ["Connecting", "Establishing SSH tunnel", "Connecting…", true],
    ["Connected", "SSH tunnel is active", "Disconnect", false],
    ["Reconnecting", "Restoring SSH connection", "Disconnect", false],
    ["Disconnecting", "Closing SSH tunnel", "Disconnecting…", true],
    ["Error", "Connection failed", "Try again", false]
  ])("maps %s to explicit status and action copy", (state, title, actionLabel, actionPending) => {
    expect(sshConnectionPresentation(state, true)).toMatchObject({ title, actionLabel, actionPending });
  });

  it("does not claim that preview or simulator sessions route system traffic", () => {
    expect(sshConnectionPresentation("Connected", false, "Browser preview connected.")).toMatchObject({
      statusLabel: "Preview only",
      title: "Connected without system routing",
      tone: "warning"
    });
  });

  it("surfaces useful runtime errors and ignores generic state messages", () => {
    expect(sshConnectionPresentation("Error", false, "Authentication failed.").description).toBe("Authentication failed.");
    expect(sshConnectionPresentation("Connected", true, "Connected.").description).toBe(
      "The encrypted proxy and traffic routing are running."
    );
  });

  it("locks server selection for every in-flight or active session", () => {
    expect(isConnectionSelectionLocked("Disconnected")).toBe(false);
    expect(isConnectionSelectionLocked("Error")).toBe(false);
    for (const state of ["Connecting", "Connected", "Reconnecting", "Disconnecting"] satisfies ConnectionState[]) {
      expect(isConnectionSelectionLocked(state)).toBe(true);
    }
  });
});
