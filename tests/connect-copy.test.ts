import { describe, expect, it } from "vitest";
import {
  closedForRoutingHint,
  describeSshFailure,
  networkChangeSummary,
  shellFailureCopy,
  splitLead
} from "../src/renderer/components/pages/connect/connect-copy.js";
import type { AttentionEvent } from "../src/shared/types.js";

const context = { name: "Frankfurt-01", username: "root" };

describe("SSH failure copy", () => {
  it.each([
    ["SSH authentication failed: password auth rejected", "Frankfurt-01 rejected the password for root. Update the server credentials, then try again."],
    ["SSH authentication failed: private-key auth rejected", "Frankfurt-01 rejected the key for root. Check which key the server expects, then try again."],
    ["SSH password is unavailable.", "No password is saved for Frankfurt-01. Add it in the server settings, then try again."],
    ["SSH private key is unavailable.", "No key is attached to Frankfurt-01. Pick a key in the server settings, then try again."],
    [
      "SSH authentication failed: Encrypted OpenSSH private keys are not supported yet. Use an unencrypted OpenSSH key or convert the key to encrypted PKCS8/PEM.",
      "The key for Frankfurt-01 is a passphrase-protected OpenSSH key, which Shadow can't load yet. Use an unencrypted key or convert it to PKCS8 or PEM."
    ],
    [
      "SSH server fingerprint mismatch: expected SHA256:aaa, got SHA256:bbb.",
      "Frankfurt-01 presented a host key that doesn't match the pinned one. If the server was reinstalled, update the pinned key; otherwise don't connect."
    ],
    ["Unsupported SSH host key algorithm ssh-dss.", "Frankfurt-01 uses a host key type Shadow can't verify, so it won't connect."]
  ])("explains %s", (message, description) => {
    const copy = describeSshFailure(message, context);
    expect(copy.description).toBe(description);
    expect(copy.technical).toBe(message);
  });

  it("looks through the reconnect envelope", () => {
    expect(describeSshFailure("Reconnect attempt 4 failed: SSH authentication failed: password auth rejected", context).description).toMatch(
      /^Frankfurt-01 rejected the password for root\./u
    );
  });

  it("leaves out the user when it is unknown", () => {
    expect(describeSshFailure("password auth rejected", { name: "Lab" }).description).toBe("Lab rejected the password. Update the server credentials, then try again.");
  });

  it("falls back to a calm generic sentence and keeps the raw text", () => {
    const copy = describeSshFailure("Something unexpected happened in the transport.", context);
    expect(copy.description).toBe("The connection to Frankfurt-01 stopped and won't retry on its own. Try again, or edit the server.");
    expect(copy.technical).toBe("Something unexpected happened in the transport.");
  });
});

describe("Reconnect copy", () => {
  it("summarises a network change by interface names", () => {
    expect(networkChangeSummary("network-changed: network interfaces changed (lost Wi-Fi=192.168.1.24; gained Ethernet=10.0.0.12)")).toBe("Wi-Fi → Ethernet");
    expect(networkChangeSummary("network-changed: network interfaces changed (lost Wi-Fi 192.168.1.24; gained Ethernet 10.0.0.12)")).toBe("Wi-Fi → Ethernet");
  });

  it("handles one-sided and same-interface changes", () => {
    expect(networkChangeSummary("network interfaces changed (lost Wi-Fi=192.168.1.24, Wi-Fi=fe80::1)")).toBe("Wi-Fi went away");
    expect(networkChangeSummary("network interfaces changed (gained Ethernet=10.0.0.12 and 2 more)")).toBe("Ethernet came up");
    expect(networkChangeSummary("network interfaces changed (lost Wi-Fi=192.168.1.24; gained Wi-Fi=192.168.1.30)")).toBe("Wi-Fi got a new address");
    expect(networkChangeSummary("network interfaces changed")).toBeUndefined();
    expect(networkChangeSummary(undefined)).toBeUndefined();
  });

  it("splits a cause from its advice", () => {
    expect(splitLead("The server name can't be found. Stop, fix it, then connect again.")).toEqual({
      lead: "The server name can't be found",
      rest: "Stop, fix it, then connect again."
    });
    expect(splitLead("Only one sentence.")).toEqual({ lead: "Only one sentence", rest: "" });
  });
});

describe("Closed-for-routing hint", () => {
  const event = (message: string): AttentionEvent => ({
    id: "a1",
    at: new Date(2026, 9, 6, 12, 6, 40).toISOString(),
    kind: "split-tunnel-no-targets",
    level: "error",
    source: "routing",
    title: "Split tunnel lost its last target",
    message
  });

  it("names the tunnel and the time it closed", () => {
    expect(closedForRoutingHint([event("A routing change left nothing to send through the tunnel, so Frankfurt-01 was disconnected. Turn on a rule.")])).toBe(
      "The Frankfurt-01 tunnel closed at 12:06:40 because its last target was turned off."
    );
  });

  it("falls back when the name is unknown and stays quiet without an event", () => {
    expect(closedForRoutingHint([event("A routing change left nothing to send through the tunnel, so the tunnel was disconnected.")])).toBe(
      "The tunnel closed at 12:06:40 because its last target was turned off."
    );
    expect(closedForRoutingHint([])).toBeUndefined();
  });
});

describe("Shell failure copy", () => {
  it("separates a refusal from a timeout", () => {
    expect(shellFailureCopy("PTY allocation failed.", context)).toBe(
      "Frankfurt-01 refused the terminal request. The tunnel is fine; the server may not allow terminals for root."
    );
    expect(shellFailureCopy("Timed out waiting for SSH channel 3.", context)).toBe(
      "Frankfurt-01 didn't answer the terminal request in time. The tunnel is fine; try again."
    );
    expect(shellFailureCopy("Something else", context)).toBe("The shell couldn't start. The tunnel is fine; try again.");
  });
});
