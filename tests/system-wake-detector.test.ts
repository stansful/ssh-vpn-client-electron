import { afterEach, describe, expect, it, vi } from "vitest";
import type os from "node:os";
import { SystemWakeDetector, type SystemWakeEvent } from "../src/service/system-wake-detector.js";

describe("system wake detector", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("reports a clock jump when a tick arrives long after it was due", () => {
    vi.useFakeTimers();
    const events: SystemWakeEvent[] = [];
    const detector = new SystemWakeDetector((event) => events.push(event), {
      tickIntervalMs: 5_000,
      clockJumpThresholdMs: 15_000,
      interfaces: () => interfaces({ en0: ["192.168.1.10"] })
    });
    detector.start();

    // Ordinary ticks: the timer fires when due, nothing to report.
    vi.advanceTimersByTime(5_000);
    vi.advanceTimersByTime(5_000);
    expect(events).toEqual([]);

    // The process stopped for two minutes: the next tick runs late.
    vi.setSystemTime(Date.now() + 120_000);
    vi.advanceTimersByTime(5_000);
    expect(events).toHaveLength(1);
    expect(events[0].reason).toBe("clock-jump");
    expect(events[0].detail).toContain("about 120 s");

    // Back to a normal cadence afterwards.
    vi.advanceTimersByTime(5_000);
    expect(events).toHaveLength(1);
    detector.stop();
    expect(detector.running).toBe(false);
  });

  it("reports a network change once per change and ignores tunnel adapters", () => {
    vi.useFakeTimers();
    const events: SystemWakeEvent[] = [];
    let addresses: Record<string, string[]> = { en0: ["192.168.1.10", "fe80::1"], lo0: ["127.0.0.1"] };
    const detector = new SystemWakeDetector((event) => events.push(event), {
      tickIntervalMs: 5_000,
      ignoredInterfaceNames: ["Shadow"],
      interfaces: () => interfaces(addresses)
    });
    detector.start();

    // The app's own adapter and a VPN's utun come and go without a wake.
    addresses = { ...addresses, "Shadow": ["10.66.0.2"], utun3: ["10.8.0.2"] };
    vi.advanceTimersByTime(5_000);
    expect(events).toEqual([]);

    // A link-local address change is not a network change either.
    addresses = { ...addresses, en0: ["192.168.1.10", "fe80::2"] };
    vi.advanceTimersByTime(5_000);
    expect(events).toEqual([]);

    // Roaming to another network is.
    addresses = { ...addresses, en0: ["10.0.0.7"] };
    vi.advanceTimersByTime(5_000);
    expect(events).toHaveLength(1);
    expect(events[0].reason).toBe("network-changed");
    expect(events[0].detail).toContain("lost en0=192.168.1.10");
    expect(events[0].detail).toContain("gained en0=10.0.0.7");

    // Stable afterwards: no repeated wakes for the same view.
    vi.advanceTimersByTime(15_000);
    expect(events).toHaveLength(1);
    detector.stop();
  });

  it("ignores Windows virtual adapters and keeps one timer across forced ticks", () => {
    vi.useFakeTimers();
    const events: SystemWakeEvent[] = [];
    let addresses: Record<string, string[]> = { "Wi-Fi": ["192.168.1.10"] };
    const detector = new SystemWakeDetector((event) => events.push(event), {
      tickIntervalMs: 5_000,
      interfaces: () => interfaces(addresses)
    });
    detector.start();
    addresses = {
      ...addresses,
      "vEthernet (WSL)": ["172.28.0.1"],
      "VMware Network Adapter VMnet8": ["192.168.88.1"],
      "Bluetooth Network Connection": ["169.254.10.10"],
      "Loopback Pseudo-Interface 1": ["127.0.0.1"]
    };
    detector.tick();
    detector.tick();
    expect(events).toEqual([]);
    expect(vi.getTimerCount()).toBe(1);

    addresses = { ...addresses, "Wi-Fi": ["10.1.1.5"] };
    vi.advanceTimersByTime(5_000);
    expect(events).toHaveLength(1);
    expect(events[0].reason).toBe("network-changed");
    detector.stop();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("keeps the last view when interface enumeration fails and stops cleanly", () => {
    vi.useFakeTimers();
    const events: SystemWakeEvent[] = [];
    let fail = false;
    const detector = new SystemWakeDetector((event) => events.push(event), {
      tickIntervalMs: 5_000,
      interfaces: () => {
        if (fail) {
          throw new Error("getifaddrs failed");
        }
        return interfaces({ eth0: ["192.168.1.10"] });
      }
    });
    detector.start();
    fail = true;
    vi.advanceTimersByTime(10_000);
    expect(events).toEqual([]);
    detector.stop();
    vi.advanceTimersByTime(60_000);
    expect(events).toEqual([]);
    expect(vi.getTimerCount()).toBe(0);
  });
});

function interfaces(map: Record<string, string[]>): NodeJS.Dict<os.NetworkInterfaceInfo[]> {
  const result: NodeJS.Dict<os.NetworkInterfaceInfo[]> = {};
  for (const [name, addresses] of Object.entries(map)) {
    result[name] = addresses.map((address) => {
      const ipv6 = address.includes(":");
      return {
        address,
        netmask: ipv6 ? "ffff:ffff:ffff:ffff::" : "255.255.255.0",
        family: ipv6 ? "IPv6" : "IPv4",
        mac: "00:00:00:00:00:00",
        internal: name.startsWith("lo"),
        cidr: null,
        scopeid: ipv6 ? 0 : undefined
      } as os.NetworkInterfaceInfo;
    });
  }
  return result;
}
