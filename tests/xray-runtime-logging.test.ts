import { describe, expect, it, vi } from "vitest";
import type { SystemProxyApplyRequest, WindowsSystemProxyManager } from "../src/core/network/windows-system-proxy.js";
import { classifyXrayLogLevel, redactSecrets, XrayServiceBridge, xrayStartupFailureReason } from "../src/service/xray-service.js";
import type { RuntimeStatus } from "../src/shared/types.js";

// Xray writes one "[Info] ... accepted ..." line per connection. A client like
// Telegram opens hundreds in a minute, and a single shared log budget spent
// itself on that chatter and then detached the stream - so the "[Warning]"
// saying why the outbound failed never reached the log. Diagnosing anything
// downstream of the proxy was impossible until this was separated.

interface XrayLogInternals {
  appendProcessLog(level: "info" | "warning" | "error", chunk: string): boolean;
}

describe("Xray runtime logging", () => {
  it("reads Xray's own severity marker rather than the stream it arrived on", () => {
    // Everything comes in on stdout, so the stream level is worthless alone.
    expect(classifyXrayLogLevel("2026/08/28 [Info] proxy: accepted tcp:1.1.1.1:443", "info")).toBe("info");
    expect(classifyXrayLogLevel("2026/08/28 [Warning] failed to process outbound traffic", "info")).toBe("warning");
    expect(classifyXrayLogLevel("2026/08/28 [Error] connection ended", "info")).toBe("error");
    // An unmarked line keeps whatever the stream implied.
    expect(classifyXrayLogLevel("Xray 26.3.27 started", "warning")).toBe("warning");
    // ...except the one Xray prints for a config it refuses, which has no
    // marker at all and arrives on stdout.
    expect(classifyXrayLogLevel("Failed to start: main: failed to load config files: [/tmp/x.json] > infra/conf: bad", "info")).toBe("error");
  });

  it("reads the reason out of Xray's startup failure line", () => {
    // Verbatim from Xray 26.3.27, given a Hysteria outbound with allowInsecure.
    expect(xrayStartupFailureReason(
      "Failed to start: main: failed to load config files: [/Users/me/runtime/xray-config.json] > infra/conf: failed to build outbound config with tag proxy > infra/conf: failed to build stream settings for outbound detour > infra/conf: Failed to build TLS config. > common/errors: The feature \"allowInsecure\" has been removed and migrated to \"pinnedPeerCertSha256\". Please update your config(s) according to release note and documentation."
    )).toBe(
      "infra/conf: failed to build outbound config with tag proxy > infra/conf: failed to build stream settings for outbound detour > infra/conf: Failed to build TLS config. > common/errors: The feature \"allowInsecure\" has been removed and migrated to \"pinnedPeerCertSha256\". Please update your config(s) according to release note and documentation."
    );
    // Other startup failures keep their own wording.
    expect(xrayStartupFailureReason("Failed to start: main: failed to create server > app/proxyman/inbound: failed to listen TCP on 32000"))
      .toBe("main: failed to create server > app/proxyman/inbound: failed to listen TCP on 32000");
    expect(xrayStartupFailureReason("2026/08/28 [Error] connection ended")).toBeUndefined();
    expect(xrayStartupFailureReason("Failed to start:   ")).toBeUndefined();

    // The most specific cause comes last, so a long chain loses its front.
    const long = xrayStartupFailureReason(`Failed to start: ${"infra/conf: wrapper > ".repeat(40)}the actual cause`);
    expect(long?.startsWith("…")).toBe(true);
    expect(long?.endsWith("the actual cause")).toBe(true);
    expect(long?.length).toBeLessThanOrEqual(401);

    expect(xrayStartupFailureReason("Failed to start: infra/conf: bad salamander {\"password\":\"mask-secret\"}"))
      .toBe("infra/conf: bad salamander {\"password\":\"<redacted>\"}");
  });

  it("redacts the Hysteria 2 credentials Xray can echo back", () => {
    // Config fragments, as Xray quotes them in its errors.
    expect(redactSecrets('hysteriaSettings: {"version":2,"auth":"hy-secret"}')).toBe('hysteriaSettings: {"version":2,"auth":"<redacted>"}');
    expect(redactSecrets('{"type":"salamander","settings":{"password": "mask \\"quoted\\" secret"}}'))
      .toBe('{"type":"salamander","settings":{"password":"<redacted>"}}');
    expect(redactSecrets('{"obfs-password":"a","obfsPassword":"b"}')).toBe('{"obfs-password":"<redacted>","obfsPassword":"<redacted>"}');
    // Share-link forms: the auth is the userinfo, the salamander key a query value.
    expect(redactSecrets("dial hysteria2://hy-secret@hy.example.com:443/?sni=a failed")).toBe("dial hysteria2://<redacted>@hy.example.com:443/?sni=a failed");
    expect(redactSecrets("obfs=salamander&obfs-password=mask-secret")).toBe("obfs=salamander&obfs-password=<redacted>");
    // A certificate pin is a public hash and stays readable for diagnosis.
    const pin = "ab".repeat(32);
    expect(redactSecrets(`pinSHA256=${pin} did not match`)).toBe(`pinSHA256=${pin} did not match`);
    expect(redactSecrets(`{"pinnedPeerCertSha256":"${pin}"}`)).toBe(`{"pinnedPeerCertSha256":"${pin}"}`);
    // The existing key=value forms are unchanged.
    expect(redactSecrets("password: hunter2")).toBe("password=<redacted>");
  });

  // Every Xray line is redacted, and the share-link pattern used to restart at
  // each label of a dotted host and rescan the rest of it: a second of
  // blocked service for one 64 KB line.
  it("redacts a 64 KB diagnostic in linear time", () => {
    const dotted = "a.".repeat(32 * 1024);
    const hostile = [
      `Xray: [Warning] dial tcp ${dotted}`,
      `Failed to start: main: failed to load config files: [${"x".repeat(64 * 1024)}`,
      `"auth":"${"\\\"".repeat(32 * 1024)}`,
      `password${" ".repeat(64 * 1024)}`,
      "a://".repeat(16 * 1024),
      `a://${"b".repeat(64 * 1024)}`,
      "x.y-z+1".repeat(9 * 1024)
    ];
    redactSecrets(dotted);
    for (const line of hostile) {
      const startedAt = performance.now();
      redactSecrets(line);
      xrayStartupFailureReason(`Failed to start: ${line}`);
      expect(performance.now() - startedAt, line.slice(0, 40)).toBeLessThan(50);
    }

    // Still redacted, after a long host and with any scheme.
    expect(redactSecrets(`dial ${dotted}hysteria2://user:pass@host:443 failed`)).toBe(`dial ${dotted}hysteria2://<redacted>@host:443 failed`);
    expect(redactSecrets("hysteria2://user:pass@host")).toBe("hysteria2://<redacted>@host");
    expect(redactSecrets("hy2://pass@host, vless://uuid@host")).toBe("hy2://<redacted>@host, vless://<redacted>@host");
    const scheme = `x${"-y".repeat(40)}`;
    expect(redactSecrets(`${scheme}://secret@host`)).toBe(`${scheme}://<redacted>@host`);
    // A path or query that merely contains "@" is not a userinfo.
    expect(redactSecrets("https://example.com/a@b?c=d@e")).toBe("https://example.com/a@b?c=d@e");
  });

  it("keeps Hysteria 2 credentials out of the Activity log", () => {
    const service = createService();
    const internals = service as unknown as XrayLogInternals;
    const messages: string[] = [];
    service.onEvent((event) => {
      if (event.type === "diagnostics-appended") {
        messages.push(event.entry.message);
      }
    });

    internals.appendProcessLog("info", '2026/08/28 [Warning] infra/conf: {"auth":"hy-secret","password":"mask-secret"}\n');

    expect(messages).toHaveLength(1);
    expect(messages[0]).not.toContain("hy-secret");
    expect(messages[0]).not.toContain("mask-secret");
  });

  it("keeps recording warnings after connection notices are capped", () => {
    const service = createService();
    const internals = service as unknown as XrayLogInternals;
    const messages: { level: string; message: string }[] = [];
    service.onEvent((event) => {
      if (event.type === "diagnostics-appended") {
        messages.push({ level: event.entry.level, message: event.entry.message });
      }
    });

    // Far more connection notices than the routine budget allows.
    for (let index = 0; index < 500; index += 1) {
      internals.appendProcessLog("info", `2026/08/28 [Info] proxy: accepted tcp:149.154.167.41:80 #${index}\n`);
    }

    const stillListening = internals.appendProcessLog(
      "info",
      "2026/08/28 [Warning] core: failed to process outbound traffic > context deadline exceeded\n"
    );

    expect(stillListening).toBe(true);
    const warning = messages.find((entry) => entry.message.includes("failed to process outbound traffic"));
    expect(warning).toBeDefined();
    expect(warning?.level).toBe("warning");

    // The chatter is capped, and says so once.
    const notices = messages.filter((entry) => entry.message.includes("accepted tcp:"));
    expect(notices.length).toBeLessThan(60);
    expect(messages.some((entry) => entry.message.includes("connection notices are suppressed"))).toBe(true);
  });
});

function createService(): XrayServiceBridge {
  const applies: SystemProxyApplyRequest[] = [];
  return new XrayServiceBridge(initialStatus(), {
    runtimeDirectory: "/tmp/shadow-ssh-xray-logging",
    systemProxy: {
      apply: vi.fn(async (request: SystemProxyApplyRequest) => {
        applies.push(request);
        return { applied: true, message: "applied" };
      }),
      restore: vi.fn(async () => undefined)
    } as unknown as WindowsSystemProxyManager,
    processConnectionsProvider: async () => [],
    processDnsEntriesProvider: async () => []
  });
}

function initialStatus(): RuntimeStatus {
  return {
    state: "Disconnected",
    message: "",
    reconnectAttempt: 0,
    transport: "xray",
    platformTarget: {
      platform: "windows",
      arch: "x64",
      serviceExecutableName: "",
      serviceRelativePath: "",
      supportsPrivilegedService: true
    },
    realTunnelAvailable: false
  };
}
