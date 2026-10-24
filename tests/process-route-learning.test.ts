import { afterEach, describe, expect, it, vi } from "vitest";
import { ProcessRouteLearner, supportsDynamicProcessRouting } from "../src/service/process-route-learning.js";
import type { RoutingRule } from "../src/shared/types.js";

const PROCESS_NAME = "example-app.exe";
const ADDRESS = "203.0.113.10";

describe("shared process-route learning", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("learns the addresses a selected process holds open and the names they had", async () => {
    await withWin32(async () => {
      const learner = new ProcessRouteLearner({
        connectionsProvider: async () => [
          { processName: PROCESS_NAME, remoteAddress: ADDRESS, remotePort: 443, state: "Established" },
          { processName: "other.exe", remoteAddress: "198.51.100.1", remotePort: 443, state: "Established" }
        ],
        dnsEntriesProvider: async () => [{ address: ADDRESS, domain: "media.example-app.test", ttlSeconds: 60 }],
        onWarning: () => undefined
      });

      expect(await learner.learn([processRule()])).toBe(true);
      expect(learner.currentIps()).toEqual(new Set([ADDRESS]));
      expect(learner.currentDomains()).toEqual(new Set(["media.example-app.test"]));
      expect(learner.lastMatchedConnections).toBe(1);

      // Nothing new on the next cycle: the routes are renewed, not changed.
      expect(await learner.learn([processRule()])).toBe(false);
    });
  });

  it("names the transport in a DNS failure, once, until a lookup works again", async () => {
    await withWin32(async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      const warnings: string[] = [];
      let lookups = 0;
      let failing = true;
      const learner = new ProcessRouteLearner({
        connectionsProvider: async () => [
          { processName: PROCESS_NAME, remoteAddress: ADDRESS, remotePort: 443, state: "Established" }
        ],
        dnsEntriesProvider: async () => {
          lookups += 1;
          if (failing) {
            throw new Error("cache unreadable");
          }
          return [{ address: ADDRESS, domain: "media.example-app.test", ttlSeconds: 1 }];
        },
        refreshIntervalMs: () => 1_000,
        onWarning: (message) => warnings.push(message),
        transportLabel: " for Xray transport"
      });
      const warning = "Process-name DNS enrichment failed for Xray transport; IP fallback remains active: cache unreadable";

      await learner.learn([processRule()]);
      expect(warnings).toEqual([warning]);
      // The literal address still routes while names cannot be read.
      expect(learner.currentIps()).toEqual(new Set([ADDRESS]));

      // A failed lookup backs off; past that delay the next cycle asks again,
      // fails again, and says nothing new.
      vi.setSystemTime(Date.now() + 11_000);
      await learner.learn([processRule()]);
      expect(lookups).toBe(2);
      expect(warnings).toEqual([warning]);

      // A lookup that works re-arms the warning for the next failure.
      failing = false;
      vi.setSystemTime(Date.now() + 21_000);
      await learner.learn([processRule()]);
      expect(lookups).toBe(3);
      failing = true;
      vi.setSystemTime(Date.now() + 2_000);
      await learner.learn([processRule()]);
      expect(lookups).toBe(4);
      expect(warnings).toEqual([warning, warning]);
    });
  });

  it("stops a cycle whose routing was replaced while it waited", async () => {
    await withWin32(async () => {
      let stale = false;
      const learner = new ProcessRouteLearner({
        connectionsProvider: async () => {
          stale = true;
          return [{ processName: PROCESS_NAME, remoteAddress: ADDRESS, remotePort: 443, state: "Established" }];
        },
        dnsEntriesProvider: async () => [],
        onWarning: () => undefined
      });

      expect(await learner.learn([processRule()], [], () => stale)).toBe(false);
      expect(learner.currentIps()).toEqual(new Set());
    });
  });

  it("learns nothing without an enabled process rule or off Windows", () => {
    const rules = [processRule()];
    expect(supportsDynamicProcessRouting("selected-rules", rules, "win32")).toBe(true);
    expect(supportsDynamicProcessRouting("proxy-all", rules, "win32")).toBe(false);
    expect(supportsDynamicProcessRouting("selected-rules", rules, "darwin")).toBe(false);
    expect(supportsDynamicProcessRouting("selected-rules", [{ ...processRule(), enabled: false }], "win32")).toBe(false);
  });
});

async function withWin32(run: () => Promise<void>): Promise<void> {
  const platform = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
  try {
    await run();
  } finally {
    if (platform) {
      Object.defineProperty(process, "platform", platform);
    }
  }
}

function processRule(): RoutingRule {
  return {
    id: "process-rule",
    type: "process.name",
    value: PROCESS_NAME,
    enabled: true,
    createdAt: "",
    updatedAt: ""
  };
}
