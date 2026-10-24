import { describe, expect, it } from "vitest";
import {
  AttentionStore,
  attentionFromDiagnostic,
  autoConnectFailedAttention,
  autoConnectSkippedAttention,
  MAX_ATTENTION_EVENTS,
  splitTunnelNoTargetsAttention,
  storageUnreadableAttention
} from "../src/main/app/attention-store.js";

function store(): AttentionStore {
  let id = 0;
  let tick = 0;
  return new AttentionStore({
    createId: () => `a${++id}`,
    now: () => new Date(Date.UTC(2026, 9, 6, 12, 0, tick++))
  });
}

describe("attention store", () => {
  it("keeps events newest first and replaces an older event of the same kind", () => {
    const attention = store();
    attention.add(autoConnectSkippedAttention("no-targets"));
    attention.add(splitTunnelNoTargetsAttention("Frankfurt-01"));
    attention.add(autoConnectSkippedAttention("no-server"));

    const events = attention.list();
    expect(events.map((event) => event.kind)).toEqual(["auto-connect-skipped", "split-tunnel-no-targets"]);
    expect(events[0]).toMatchObject({ id: "a3", message: expect.stringContaining("No SSH server is picked") });
  });

  it("dedupes 'other' events only by title", () => {
    const attention = store();
    attention.add({ kind: "other", level: "warning", source: "routing", title: "A", message: "first" });
    attention.add({ kind: "other", level: "warning", source: "routing", title: "B", message: "second" });
    attention.add({ kind: "other", level: "warning", source: "routing", title: "A", message: "third" });

    expect(attention.list().map((event) => `${event.title}:${event.message}`)).toEqual(["A:third", "B:second"]);
  });

  it("caps the list at the newest twenty events", () => {
    const attention = store();
    for (let index = 0; index < MAX_ATTENTION_EVENTS + 5; index += 1) {
      attention.add({ kind: "other", level: "info", source: "app", title: `event ${index}`, message: "m" });
    }
    const events = attention.list();
    expect(events).toHaveLength(MAX_ATTENTION_EVENTS);
    expect(events[0]?.title).toBe(`event ${MAX_ATTENTION_EVENTS + 4}`);
  });

  it("dismisses one event, a kind, or everything and reports whether anything changed", () => {
    const attention = store();
    const first = attention.add(autoConnectSkippedAttention("no-targets"));
    attention.add(storageUnreadableAttention("Unexpected token } in JSON at position 4182"));

    expect(attention.dismiss("missing")).toBe(false);
    expect(attention.dismiss(first.id)).toBe(true);
    expect(attention.has("auto-connect-skipped")).toBe(false);
    expect(attention.dismissKind("storage-unreadable")).toBe(true);
    expect(attention.size).toBe(0);
    attention.add(autoConnectSkippedAttention("no-profile"));
    expect(attention.dismiss()).toBe(true);
    expect(attention.dismiss()).toBe(false);
  });

  it("hands out copies so callers cannot edit stored events", () => {
    const attention = store();
    attention.add(autoConnectSkippedAttention("no-targets"));
    const [event] = attention.list();
    if (event) {
      event.title = "changed";
    }
    expect(attention.list()[0]?.title).toBe("Auto-connect skipped");
  });
});

describe("attention from transport diagnostics", () => {
  it("turns a halted SSH reconnect into a reconnect-stopped event with the reason and the next step", () => {
    const event = attentionFromDiagnostic(
      { level: "warning", message: "Reconnect stopped. Update the SSH configuration or key, then connect again." },
      "ssh",
      { targetName: "Frankfurt-01", statusMessage: "All configured authentication methods failed" }
    );
    expect(event).toMatchObject({
      kind: "reconnect-stopped",
      level: "error",
      source: "ssh",
      title: "Reconnect stopped · Frankfurt-01"
    });
    expect(event?.message).toBe(
      "All configured authentication methods failed. Retrying won’t fix this. Check the server and its key in SSH servers, then connect again."
    );
  });

  it("says what happens next when the TUN adapter stops under a session", () => {
    const ssh = attentionFromDiagnostic(
      { level: "warning", message: "TUN dataplane stopped unexpectedly: Native helper exited (3). Routing is being applied again: the adapter is restarted, or the Windows proxy path takes over." },
      "ssh"
    );
    expect(ssh).toMatchObject({ kind: "tun-unavailable", level: "error", title: "TUN adapter stopped" });
    // Both transports restore routing by themselves; telling the user to
    // reconnect would send them after a fix that already happened.
    expect(ssh?.message).toContain("applied routing again right away");
    expect(ssh?.message).not.toContain("Reconnect");

    const xray = attentionFromDiagnostic(
      { level: "warning", message: "TUN dataplane stopped unexpectedly: Native helper exited (3). Routing is being applied again: the adapter is restarted, or the Windows proxy path takes over." },
      "xray"
    );
    expect(xray).toMatchObject({ kind: "tun-unavailable", level: "error", title: "TUN adapter stopped" });
    expect(xray?.message).toContain("applied routing again right away");
    expect(xray?.message).not.toContain("Reconnect");
  });

  it("does not claim routing was applied again when the adapter stopped while the connection was down", () => {
    for (const [origin, message] of [
      ["ssh", "TUN dataplane stopped unexpectedly: Native helper exited (3). Routing is applied again when the session is back: the adapter is restarted, or the Windows proxy path takes over. Until then apps connect directly."],
      ["xray", "TUN dataplane stopped unexpectedly: Native helper exited (3). Routing is applied again when Xray is back: the adapter is restarted, or the Windows proxy path takes over. Until then apps connect directly."]
    ] as const) {
      const attention = attentionFromDiagnostic({ level: "warning", message }, origin);
      expect(attention).toMatchObject({ kind: "tun-unavailable", level: "error", title: "TUN adapter stopped" });
      expect(attention?.message).toContain("apps connect directly until it is back");
      expect(attention?.message).not.toContain("right away");
    }
  });

  it("names the missing TUN prerequisite", () => {
    const message = "TUN routing is unavailable, continuing on the Windows proxy path: The native helper cannot create a tunnel adapter.";
    expect(attentionFromDiagnostic({ level: "warning", message }, "ssh", { tun: { elevated: false, wintunFound: true } })?.title).toBe(
      "TUN adapter not used: not running as administrator"
    );
    expect(attentionFromDiagnostic({ level: "warning", message }, "xray", { tun: { elevated: true, wintunFound: false } })?.title).toBe(
      "TUN adapter not used: wintun.dll wasn’t found"
    );
    expect(
      attentionFromDiagnostic({ level: "warning", message }, "ssh", { tun: { elevated: false, wintunFound: true }, launchedAtSignIn: true })
    ).toMatchObject({ kind: "tun-unavailable", title: "TUN is off this session", source: "routing" });
    expect(
      attentionFromDiagnostic(
        { level: "warning", message: "TUN routing could not start, continuing on the Windows proxy path - process rules will not reach applications: boom" },
        "ssh",
        { tun: { elevated: true, wintunFound: true } }
      )?.title
    ).toBe("TUN adapter not used");
  });

  it("maps proxy restore failures, adapter teardown and the routing hold timeout", () => {
    expect(attentionFromDiagnostic({ level: "warning", message: "Windows proxy restore failed: access denied" }, "xray")?.kind).toBe(
      "system-proxy-restore-failed"
    );
    expect(
      attentionFromDiagnostic({ level: "error", message: "TUN routing teardown failed; the machine may still be routing through a stale adapter: x" }, "ssh")
    ).toMatchObject({ kind: "other", title: "TUN adapter didn’t stop cleanly" });
    expect(
      attentionFromDiagnostic(
        { level: "warning", message: "The tunnel has been down for 30 s; returning the machine to direct routing until the session is back." },
        "ssh",
        { targetName: "Frankfurt-01" }
      )?.message
    ).toContain("Frankfurt-01 was down for 30 s");
    // Xray says the same of the same event, and of a hold another program cut short.
    const xrayHold = attentionFromDiagnostic(
      { level: "warning", message: "The tunnel has been down for 30 s; returning the machine to direct routing until the session is back." },
      "xray",
      { targetName: "Paris VLESS" }
    );
    expect(xrayHold).toMatchObject({ title: "Traffic went direct while the tunnel was down", source: "routing" });
    expect(xrayHold?.message).toContain("Paris VLESS was down for 30 s");
    expect(
      attentionFromDiagnostic(
        {
          level: "warning",
          message:
            "Another program took Xray's local port while Xray was down (listen EADDRINUSE 127.0.0.1:32000); returning the machine to direct routing until Xray is back."
        },
        "xray",
        { targetName: "Paris VLESS" }
      )
    ).toMatchObject({ title: "Traffic went direct while the tunnel was down", source: "routing" });
  });

  it("ignores routine diagnostics without building the context", () => {
    let built = false;
    const event = attentionFromDiagnostic({ level: "info", message: "SOCKS5 tunnel opened for discord.com:443." }, "ssh", () => {
      built = true;
      return {};
    });
    expect(event).toBeUndefined();
    expect(built).toBe(false);
  });
});

describe("attention copy for start-up events", () => {
  it("explains an unreadable saved password per platform", () => {
    const windows = autoConnectFailedAttention({
      transport: "ssh",
      targetName: "Frankfurt-01",
      reason: "Secret record is missing.",
      secretKind: "password",
      platform: "win32"
    });
    expect(windows.message).toBe(
      "Couldn’t read the saved password for Frankfurt-01. It was saved on another PC or Windows account. Enter it again in SSH servers."
    );
    const mac = autoConnectFailedAttention({
      transport: "xray",
      targetName: "de-fra-reality",
      reason: "Error while decrypting the ciphertext provided to safeStorage.decryptString.",
      platform: "darwin"
    });
    expect(mac.message).toContain("saved link for de-fra-reality");
    expect(mac.message).toContain("another computer or user account");
  });

  it("keeps other auto-connect failures as a plain reason", () => {
    expect(
      autoConnectFailedAttention({ transport: "ssh", targetName: "Frankfurt-01", reason: "connect ECONNREFUSED 203.0.113.10:22", platform: "linux" })
        .message
    ).toBe("Couldn’t connect to Frankfurt-01 at start: connect ECONNREFUSED 203.0.113.10:22.");
  });
});
