import { describe, expect, it } from "vitest";
import {
  hasRoutingTargets,
  profileInitials,
  resolveTarget,
  sessionTargetName,
  summarizeRouting
} from "../src/renderer/components/pages/connect/connect-target.js";
import { createDefaultStore } from "../src/shared/defaults.js";
import type { AppStore, ProxyProfile, RoutingRule, SshConfig } from "../src/shared/types.js";
import { createTestRuntime, createTestSnapshot } from "./renderer-fixtures.js";

const at = "2026-10-06T12:00:00.000Z";

function config(id: string, name: string, overrides: Partial<SshConfig> = {}): SshConfig {
  return {
    id,
    name,
    host: "203.0.113.10",
    port: 22,
    username: "root",
    authType: "password",
    passwordSecretId: "secret",
    expectedServerFingerprint: "",
    keepaliveIntervalSec: 120,
    note: "",
    createdAt: at,
    updatedAt: at,
    ...overrides
  };
}

function profile(id: string, name: string, overrides: Partial<ProxyProfile> = {}): ProxyProfile {
  return {
    id,
    name,
    protocol: "vless",
    host: "185.244.30.9",
    port: 443,
    transport: "tcp",
    security: "reality",
    flow: "",
    source: "manual",
    rawUriSecretId: "uri",
    fingerprint: id,
    isSelected: false,
    isPinned: false,
    isStale: false,
    lastTestStatus: "unknown",
    createdAt: at,
    updatedAt: at,
    lastSeenAt: at,
    ...overrides
  };
}

function rule(type: RoutingRule["type"], value: string, enabled = true): RoutingRule {
  return { id: `${type}-${value}`, type, value, enabled, createdAt: at, updatedAt: at };
}

function store(overrides: Partial<AppStore> = {}): AppStore {
  return { ...createDefaultStore(), ...overrides };
}

describe("Connect target", () => {
  const frankfurt = config("fra", "Frankfurt-01");
  const amsterdam = config("ams", "Amsterdam-edge", { host: "198.51.100.24", port: 2222, username: "deploy" });

  it("shows the selected server while nothing runs", () => {
    const snapshot = createTestSnapshot({ store: store({ sshConfigs: [frankfurt, amsterdam], selectedConfigId: "ams" }) });
    const state = resolveTarget(snapshot, "ssh");
    expect(state.target).toMatchObject({ name: "Amsterdam-edge", sub: "deploy@198.51.100.24:2222", address: "198.51.100.24:2222", initials: "AM" });
    expect(state.fromSession).toBe(false);
    expect(state.noneSaved).toBe(false);
  });

  it("shows the server the session started with, not a newer selection", () => {
    const snapshot = createTestSnapshot({
      store: store({ sshConfigs: [frankfurt, amsterdam], selectedConfigId: "ams" }),
      runtime: createTestRuntime({ state: "Connected", activeConfigId: "fra", activeConfigName: "Frankfurt-01" })
    });
    const state = resolveTarget(snapshot, "ssh");
    expect(state.target?.name).toBe("Frankfurt-01");
    expect(state.fromSession).toBe(true);
  });

  it("keeps the session's name when its server was deleted meanwhile", () => {
    const snapshot = createTestSnapshot({
      store: store({ sshConfigs: [amsterdam], selectedConfigId: "ams" }),
      runtime: createTestRuntime({ state: "Reconnecting", activeConfigId: "fra", activeConfigName: "Frankfurt-01", activeTarget: "203.0.113.10:22" })
    });
    const target = resolveTarget(snapshot, "ssh").target;
    expect(target).toMatchObject({ name: "Frankfurt-01", sub: "203.0.113.10:22" });
    expect(target?.id).toBeUndefined();
  });

  it("uses the selection on the transport that isn't running", () => {
    const snapshot = createTestSnapshot({
      store: store({ sshConfigs: [frankfurt], selectedConfigId: "fra", proxyProfiles: [profile("de", "de-fra-reality", { isSelected: true })], selectedProxyProfileId: "de" }),
      runtime: createTestRuntime({ state: "Connected", activeConfigId: "fra" }),
      activeTransport: "ssh"
    });
    const xray = resolveTarget(snapshot, "xray");
    expect(xray.target).toMatchObject({ name: "de-fra-reality", sub: "VLESS · 185.244.30.9:443 · tcp · reality", initials: "VL" });
    expect(xray.fromSession).toBe(false);
    expect(sessionTargetName(snapshot)).toBe("Frankfurt-01");
  });

  it("separates nothing saved from nothing selected", () => {
    expect(resolveTarget(createTestSnapshot(), "ssh")).toMatchObject({ noneSaved: true, noneSelected: false, count: 0 });
    const unselected = createTestSnapshot({ store: store({ sshConfigs: [frankfurt] }) });
    expect(resolveTarget(unselected, "ssh")).toMatchObject({ noneSaved: false, noneSelected: true, count: 1, target: undefined });
  });

  it("flags profiles the bundled engine can't run", () => {
    const snapshot = createTestSnapshot({
      store: store({
        proxyProfiles: [profile("lab", "lab-unknown", { security: "unknown" }), profile("ws", "nl-ams-ws", { transport: "unknown" })],
        selectedProxyProfileId: "lab"
      })
    });
    expect(resolveTarget(snapshot, "xray").target?.unsupported).toBe("security");
    expect(profileInitials({ protocol: "vmess" })).toBe("VM");
    expect(profileInitials({ protocol: "trojan" })).toBe("TR");
    expect(profileInitials({ protocol: "hysteria2" })).toBe("HY");
  });

  it("describes a Hysteria 2 profile with its hop ports", () => {
    const hel = profile("hel", "fi-hel-hy2", {
      protocol: "hysteria2",
      host: "hel.example.net",
      port: 443,
      hopPorts: "443,20000-30000",
      transport: "hysteria",
      security: "tls"
    });
    const snapshot = createTestSnapshot({ store: store({ proxyProfiles: [hel], selectedProxyProfileId: "hel" }) });
    expect(resolveTarget(snapshot, "xray").target).toMatchObject({
      name: "fi-hel-hy2",
      sub: "Hysteria 2 · hel.example.net:443,20000-30000 · quic · tls",
      address: "hel.example.net:443,20000-30000",
      initials: "HY",
      unsupported: undefined
    });
    const single = createTestSnapshot({ store: store({ proxyProfiles: [{ ...hel, hopPorts: undefined }], selectedProxyProfileId: "hel" }) });
    expect(resolveTarget(single, "xray").target).toMatchObject({ sub: "Hysteria 2 · hel.example.net:443 · quic · tls", address: "hel.example.net:443" });
  });

  it("carries the insecure=1 mark of the selected or running Hysteria 2 profile, without blocking it", () => {
    const hy = (id: string, name: string, overrides: Partial<ProxyProfile> = {}) =>
      profile(id, name, { protocol: "hysteria2", host: `${id}.example.net`, transport: "hysteria", security: "tls", ...overrides });
    const selfSigned = hy("hel", "fi-hel-hy2", { insecureWithoutPin: true });
    const pinned = hy("waw", "pl-waw-hy2");
    const selected = createTestSnapshot({ store: store({ proxyProfiles: [selfSigned, pinned], selectedProxyProfileId: "hel" }) });
    expect(resolveTarget(selected, "xray").target).toMatchObject({ id: "hel", insecureWithoutPin: true, unsupported: undefined });

    const other = createTestSnapshot({ store: store({ proxyProfiles: [selfSigned, pinned], selectedProxyProfileId: "waw" }) });
    expect(resolveTarget(other, "xray").target?.insecureWithoutPin).toBeUndefined();

    // A running session describes the profile it started with, mark included.
    const running = createTestSnapshot({
      activeTransport: "xray",
      runtime: createTestRuntime({ state: "Connected", activeConfigId: "hel", activeConfigName: "fi-hel-hy2" }),
      store: store({ proxyProfiles: [selfSigned, pinned], selectedProxyProfileId: "waw" })
    });
    expect(resolveTarget(running, "xray")).toMatchObject({ fromSession: true, target: { id: "hel", insecureWithoutPin: true } });
  });
});

describe("Routing summary", () => {
  it("counts only enabled, valid rules by type and names the list", () => {
    const summary = summarizeRouting(
      store({
        routingMode: "selected-rules",
        routingRules: [
          rule("domain", "youtube.com"),
          rule("domain", "*.googlevideo.com"),
          rule("domain", "*.discord.gg", false),
          rule("domain", "https://bad.example/path"),
          rule("ip", "8.8.8.8"),
          rule("process.name", "telegram.exe")
        ],
        routingProxyList: { enabled: true, sourceUrl: "", domains: ["example.org"] }
      })
    );
    expect(summary.title).toBe("Split tunnel");
    expect(summary.badges).toEqual(["2 domains", "1 IP", "1 app", "Blocked in Russia list"]);
    expect(summary.blocked).toBe(false);
    expect(summary.hint).toBe("Split tunnel: only your routing rules and the Blocked in Russia list use it.");
  });

  it("blocks split tunnel with nothing to route", () => {
    const empty = store({
      routingMode: "selected-rules",
      routingRules: [rule("domain", "youtube.com", false)],
      routingProxyList: { enabled: true, sourceUrl: "", domains: [] }
    });
    expect(hasRoutingTargets(empty)).toBe(false);
    expect(summarizeRouting(empty)).toMatchObject({ blocked: true, badges: [] });
  });

  it("treats a non-empty proxy list as a target on its own", () => {
    const listOnly = store({ routingMode: "selected-rules", routingProxyList: { enabled: true, sourceUrl: "", domains: ["# comment", "example.org"] } });
    expect(hasRoutingTargets(listOnly)).toBe(true);
    expect(summarizeRouting(listOnly).hint).toBe("Split tunnel: only the Blocked in Russia list uses it.");
  });

  it("describes full tunnel without blocking it", () => {
    const full = summarizeRouting(store({ routingMode: "proxy-all", routingDirectList: { enabled: true, sourceUrl: "", domains: ["vk.com"] } }));
    expect(full).toMatchObject({ title: "Full tunnel", blocked: false, badges: ["All traffic", "Russian services stay direct"] });
    expect(full.hint).toBe("Full tunnel: all your traffic uses it, except the Russian services list.");
    expect(summarizeRouting(store({ routingMode: "proxy-all" })).hint).toBe("Full tunnel: all your traffic uses it.");
  });
});
