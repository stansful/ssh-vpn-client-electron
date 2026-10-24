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
      "SSH authentication failed: Encrypted OpenSSH private keys are not supported with this cipher or bcrypt round count. Re-encrypt the key with ssh-keygen -p -Z aes256-ctr, or convert it to encrypted PKCS8/PEM.",
      "The key for Frankfurt-01 is encrypted in a way Shadow can't open. Re-encrypt it with ssh-keygen -p -Z aes256-ctr, then paste it again in SSH keys."
    ],
    [
      "SSH authentication failed: Unable to load SSH private key because it is protected with a passphrase, and none was provided.",
      "The key for Frankfurt-01 is protected with a passphrase that isn't saved. Edit the key in SSH keys and type its passphrase."
    ],
    [
      "SSH authentication failed: Unable to load SSH private key because the passphrase is wrong.",
      "The saved passphrase for the key of Frankfurt-01 is wrong. Edit the key in SSH keys and type it again."
    ],
    [
      "SSH authentication failed: Unable to load SSH private key. Check the key format and passphrase.",
      "The key for Frankfurt-01 couldn't be read. Check the key format and its passphrase, then try again."
    ],
    [
      "SSH server fingerprint mismatch: expected SHA256:aaa, got SHA256:bbb (ssh-ed25519), SHA256:ccc (ssh-rsa).",
      "Frankfurt-01 presented a host key that doesn't match the pinned one. If the server was reinstalled, update the pinned key; otherwise don't connect."
    ],
    [
      "SSH server fingerprint mismatch: expected SHA256:aaa, got SHA256:bbb.",
      "Frankfurt-01 presented a host key that doesn't match the pinned one. If the server was reinstalled, update the pinned key; otherwise don't connect."
    ],
    [
      "SSH server host key does not match the key Shadow trusted on its first connection to vpn.example.com: expected SHA256:aaa, got SHA256:bbb (ssh-ed25519). Shadow stopped so nothing is sent to a server that may be an impostor. If the server's key was changed on purpose, paste the new fingerprint into the server's Fingerprint field.",
      "Frankfurt-01 presented a different host key than the one Shadow trusted on the first connection. If the server's key was changed on purpose, paste the new fingerprint into the server's Fingerprint field; otherwise don't connect."
    ],
    [
      "Reconnect attempt 3 failed: SSH server host key does not match the key vpn.example.com presented earlier in this session: expected SHA256:aaa, got SHA256:bbb (ssh-ed25519). Shadow stopped so nothing is sent to a server that may be an impostor. If the server's key was changed on purpose, paste the new fingerprint into the server's Fingerprint field.",
      "Frankfurt-01 presented a different host key than earlier in this session. If the server's key was changed on purpose, paste the new fingerprint into the server's Fingerprint field; otherwise don't connect."
    ],
    [
      "SSH authentication failed: Unable to load SSH private key because it is a security-key (FIDO) key, which signs only with its hardware key. Use an Ed25519, ECDSA or RSA key.",
      "The key for Frankfurt-01 is a security-key (FIDO) key, which Shadow can't sign in with. Use an Ed25519, ECDSA or RSA key."
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
