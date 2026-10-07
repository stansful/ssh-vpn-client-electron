import { describe, expect, it } from "vitest";
import {
  formatBytes,
  formatClock,
  formatCount,
  formatDuration,
  formatHostPort,
  formatLatency,
  formatProfileAddress,
  formatProfileSummary,
  formatRelative,
  formatSshTarget,
  formatTransportSecurity,
  formatWhen,
  initials,
  plural,
  profileTransportLabel,
  protocolKeywords,
  protocolLabel,
  shortenMiddle
} from "../src/renderer/lib/format.js";
import { MAX_VISIBLE_TOASTS, pushToast, removeToast, toastDuration, type ToastRecord } from "../src/renderer/lib/toast-queue.js";

describe("format helpers", () => {
  const now = new Date(2026, 9, 6, 12, 30, 0);

  it("formats times and days in local time", () => {
    expect(formatClock(new Date(2026, 9, 6, 12, 4, 18))).toBe("12:04:18");
    expect(formatWhen(new Date(2026, 9, 6, 12, 4), now)).toBe("today at 12:04");
    expect(formatWhen(new Date(2026, 9, 5, 9, 10), now)).toBe("yesterday at 09:10");
    expect(formatWhen(new Date(2026, 9, 1, 8, 0), now)).toBe("1 Oct at 08:00");
    expect(formatWhen(new Date(2025, 11, 31, 8, 0), now)).toBe("31 Dec 2025 at 08:00");
    expect(formatRelative(new Date(2026, 9, 6, 12, 29, 50), now)).toBe("just now");
    expect(formatRelative(new Date(2026, 9, 6, 12, 25, 0), now)).toBe("5 min ago");
    expect(formatClock("not a date")).toBe("");
  });

  it("formats sizes, counts and durations", () => {
    expect(formatBytes(92_000_000)).toBe("92 MB");
    expect(formatBytes(1_400_000_000)).toBe("1.4 GB");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatCount(1982)).toBe("1,982");
    expect(plural(1, "domain")).toBe("1 domain");
    expect(plural(1982, "domain")).toBe("1,982 domains");
    expect(formatLatency(184)).toBe("184 ms");
    expect(formatLatency(1250)).toBe("1.3 s");
    expect(formatDuration(2 * 3600_000 + 14 * 60_000)).toBe("2 h 14 min");
  });

  it("builds avatars and addresses", () => {
    expect(initials("Frankfurt-01")).toBe("FR");
    expect(initials("Lab Raspberry")).toBe("LR");
    expect(initials("Amsterdam-edge")).toBe("AM");
    expect(formatHostPort("2001:db8::1", 443)).toBe("[2001:db8::1]:443");
    expect(formatSshTarget({ username: "root", host: "203.0.113.10", port: 22 })).toBe("root@203.0.113.10:22");
    expect(formatProfileSummary({ protocol: "vless", host: "192.0.2.9", port: 443, transport: "tcp", security: "unknown" })).toBe(
      "VLESS · 192.0.2.9:443 · tcp · ?"
    );
    expect(shortenMiddle("sha256:4f1c9e0b7d2a51c8e3f6a0b94d17c2e85a6f3b10d9c4e27f81a5b3c6d0e9a92e")).toBe("sha256:4f1c9e…a92e");
  });

  it("names protocols and shows Hysteria 2 as quic with its hop ports", () => {
    expect((["vless", "vmess", "trojan", "hysteria2"] as const).map((protocol) => protocolLabel(protocol))).toEqual(["VLESS", "VMess", "Trojan", "Hysteria 2"]);
    expect(protocolKeywords("hysteria2")).toBe("hysteria2 hy2");
    expect(protocolKeywords("vmess")).toBe("vmess");
    const hy2 = { protocol: "hysteria2", host: "example.com", port: 443, hopPorts: "443,20000-30000", transport: "hysteria", security: "tls" } as const;
    expect(formatProfileSummary(hy2)).toBe("Hysteria 2 · example.com:443,20000-30000 · quic · tls");
    expect(formatProfileSummary({ ...hy2, hopPorts: undefined, host: "2001:db8::7" })).toBe("Hysteria 2 · [2001:db8::7]:443 · quic · tls");
    expect(formatProfileAddress({ host: "2001:db8::7", port: 20000, hopPorts: "20000-30000" })).toBe("[2001:db8::7]:20000-30000");
    expect(formatTransportSecurity(hy2)).toBe("quic · tls");
    expect(profileTransportLabel({ protocol: "vless", transport: "hysteria" })).toBe("hysteria");
    expect(profileTransportLabel({ protocol: "hysteria2", transport: "unknown" })).toBe("?");
    expect(formatTransportSecurity({ protocol: "vless", transport: "tcp", security: "reality" })).toBe("tcp · reality");
  });
});

describe("toast queue", () => {
  it("closes success and info after 5 s, 8 s with an action, and keeps warnings and errors", () => {
    expect(toastDuration({ tone: "success" })).toBe(5000);
    expect(toastDuration({ tone: "info", action: { label: "Undo", onClick: () => undefined } })).toBe(8000);
    expect(toastDuration({ tone: "warning" })).toBeNull();
    expect(toastDuration({ tone: "error" })).toBeNull();
    expect(toastDuration({ tone: "error", duration: 3000 })).toBe(3000);
  });

  it("shows at most three, drops the oldest, and replaces a toast with the same id in place", () => {
    let list: ToastRecord[] = [];
    for (const id of ["a", "b", "c", "d"]) {
      list = pushToast(list, { tone: "info", title: id }, id);
    }
    expect(list.map((toast) => toast.id)).toEqual(["b", "c", "d"]);
    expect(list).toHaveLength(MAX_VISIBLE_TOASTS);

    list = pushToast(list, { tone: "error", title: "c again" }, "c");
    expect(list.map((toast) => toast.title)).toEqual(["b", "c again", "d"]);
    expect(list[1]).toMatchObject({ revision: 1, duration: null });

    expect(removeToast(list, "b").map((toast) => toast.id)).toEqual(["c", "d"]);
  });
});
