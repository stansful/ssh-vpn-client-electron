import { describe, expect, it } from "vitest";
import { ProxyActivityHeartbeat } from "../src/core/network/proxy-activity-heartbeat.js";
import type { ProxyActivityStats } from "../src/core/network/socks5-proxy.js";

function stats(overrides: Partial<ProxyActivityStats> = {}): ProxyActivityStats {
  return {
    active: 0,
    accepted: 0,
    established: 0,
    errored: 0,
    bytesToClient: 0,
    bytesToChannel: 0,
    pendingChannelOpens: 0,
    ...overrides
  };
}

describe("proxy activity heartbeat", () => {
  // The line this produces is the whole instrument: connections held open while
  // no bytes move is a tunnel that accepts and then stalls, which no routing log
  // can show.
  it("reports a data-plane stall: connections open, nothing flowing", () => {
    const messages: string[] = [];
    let current = stats({ active: 12, accepted: 12, established: 12, bytesToClient: 500_000, bytesToChannel: 40_000 });
    const heartbeat = new ProxyActivityHeartbeat(() => current, (message) => messages.push(message));
    heartbeat.start();

    // Next interval: still 12 connections open, but not one byte crossed and two
    // died - the signature of a stalled tunnel.
    current = stats({ active: 12, accepted: 12, established: 12, errored: 2, bytesToClient: 500_000, bytesToChannel: 40_000 });
    heartbeat.tick();

    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain("active=12");
    expect(messages[0]).toContain("errored=2");
    expect(messages[0]).toContain("down=0 B");
    expect(messages[0]).toContain("up=0 B");
  });

  it("reports healthy flow with human-readable byte deltas", () => {
    const messages: string[] = [];
    let current = stats();
    const heartbeat = new ProxyActivityHeartbeat(() => current, (message) => messages.push(message));
    heartbeat.start();
    current = stats({ active: 3, accepted: 5, established: 5, bytesToClient: 3 * 1024 * 1024, bytesToChannel: 2048 });
    heartbeat.tick();

    expect(messages[0]).toContain("active=3");
    expect(messages[0]).toContain("opened=5");
    expect(messages[0]).toContain("down=3.0 MiB");
    expect(messages[0]).toContain("up=2.0 KiB");
  });

  // A quiet tunnel (an idle push socket, a backgrounded app) must not fill the
  // log with heartbeats that say nothing happened.
  it("stays silent across a fully idle interval", () => {
    const messages: string[] = [];
    const current = stats({ active: 0, accepted: 7, established: 7, bytesToClient: 10, bytesToChannel: 10 });
    const heartbeat = new ProxyActivityHeartbeat(() => current, (message) => messages.push(message));
    heartbeat.start();
    heartbeat.tick();
    heartbeat.tick();
    expect(messages).toHaveLength(0);
  });

  // Held-open connections with no traffic are NOT idle - that is the stall we
  // most want to see - so a non-zero active count always reports.
  it("reports while connections are held open even with no byte movement", () => {
    const messages: string[] = [];
    const current = stats({ active: 8, accepted: 8, established: 8 });
    const heartbeat = new ProxyActivityHeartbeat(() => current, (message) => messages.push(message));
    heartbeat.start();
    heartbeat.tick();
    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain("active=8");
  });

  it("drops its baseline when the listener goes away, then re-baselines cleanly", () => {
    const messages: string[] = [];
    let current: ProxyActivityStats | undefined = stats({ active: 2, accepted: 2 });
    const heartbeat = new ProxyActivityHeartbeat(() => current, (message) => messages.push(message));
    heartbeat.start();

    current = undefined; // proxy stopped
    heartbeat.tick();
    expect(messages).toHaveLength(0);

    // A new listener starts its counters from zero; the delta must be measured
    // against the new baseline, not the old high-water mark (which would produce
    // a nonsensical negative).
    current = stats({ active: 1, accepted: 1, bytesToClient: 100 });
    heartbeat.tick(); // re-baseline, silent
    current = stats({ active: 1, accepted: 2, bytesToClient: 300 });
    heartbeat.tick();
    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain("opened=1");
    expect(messages[0]).toContain("down=200 B");
  });
});
