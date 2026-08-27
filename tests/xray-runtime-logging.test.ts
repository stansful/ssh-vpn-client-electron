import { describe, expect, it, vi } from "vitest";
import type { SystemProxyApplyRequest, WindowsSystemProxyManager } from "../src/core/network/windows-system-proxy.js";
import { classifyXrayLogLevel, XrayServiceBridge } from "../src/service/xray-service.js";
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
