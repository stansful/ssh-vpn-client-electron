import { describe, expect, it } from "vitest";
import { buildTrayMenuModel, type TrayModelInput, type TrayStoreView } from "../src/main/app/tray-model.js";
import { createDefaultRuntimeStatus, DEFAULT_SETTINGS } from "../src/shared/defaults.js";
import { createPlatformTarget } from "../src/main/platform/targets.js";
import type { ProxyProfile, RuntimeStatus, SshConfig } from "../src/shared/types.js";

const NOW = "2026-10-06T12:04:00.000Z";

function config(id: string, name: string, extra: Partial<SshConfig> = {}): SshConfig {
  return {
    id,
    name,
    host: `${id}.example.net`,
    port: 22,
    username: "root",
    authType: "password",
    passwordSecretId: `secret-${id}`,
    expectedServerFingerprint: "",
    keepaliveIntervalSec: 30,
    note: "",
    createdAt: NOW,
    updatedAt: NOW,
    ...extra
  };
}

function profile(id: string, name: string, extra: Partial<ProxyProfile> = {}): ProxyProfile {
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
    rawUriSecretId: `raw-${id}`,
    fingerprint: id,
    isSelected: false,
    isPinned: true,
    isStale: false,
    lastTestStatus: "unknown",
    createdAt: NOW,
    updatedAt: NOW,
    lastSeenAt: NOW,
    ...extra
  };
}

function storeView(extra: Partial<TrayStoreView> = {}): TrayStoreView {
  return {
    sshConfigs: [
      config("fra", "Frankfurt-01"),
      config("ams", "Amsterdam-edge", { authType: "private-key", passwordSecretId: undefined, privateKeyId: "key-1" }),
      config("lab", "Lab Raspberry", { passwordSecretId: undefined })
    ],
    proxyProfiles: [
      profile("xr", "de-fra-reality"),
      profile("xt", "trojan-tokyo", { protocol: "trojan", security: "tls" }),
      profile("xu", "odd-one", { transport: "unknown" }),
      profile("np", "not-pinned", { isPinned: false })
    ],
    selectedConfigId: "fra",
    selectedProxyProfileId: "xr",
    settings: DEFAULT_SETTINGS,
    routingMode: "proxy-all",
    routingRules: [],
    routingProxyList: { enabled: false, sourceUrl: "", domains: [] },
    ...extra
  };
}

function runtime(extra: Partial<RuntimeStatus> = {}): RuntimeStatus {
  return { ...createDefaultRuntimeStatus(createPlatformTarget("win32", "x64")), transport: "live-ssh", ...extra };
}

function input(extra: Partial<TrayModelInput> = {}): TrayModelInput {
  return {
    appName: "Shadow SSH",
    platform: "win32",
    activeTransport: "ssh",
    runtime: runtime(),
    store: storeView(),
    checkInProgress: false,
    storageReadable: true,
    ...extra
  };
}

describe("tray menu model", () => {
  it("offers Connect for the selected server while off", () => {
    const model = buildTrayMenuModel(input());
    expect(model).toMatchObject({
      tone: "off",
      statusTitle: "Not connected · SSH · Frankfurt-01 selected",
      tooltip: "Shadow SSH — not connected",
      primary: { label: "Connect", action: "connect", enabled: true },
      switchEnabled: true,
      check: { label: "Run check", enabled: false, sublabel: "Needs a tunnel" },
      quitSublabel: "Closes Shadow SSH"
    });
    expect(model.switchNote).toBeUndefined();
  });

  it("lists SSH servers then pinned Xray profiles, disabling the ones that can't connect", () => {
    const { servers } = buildTrayMenuModel(input());
    expect(servers.map((server) => [server.kind, server.label, server.checked, server.enabled, server.sublabel])).toEqual([
      ["ssh", "Frankfurt-01", true, true, undefined],
      ["ssh", "Amsterdam-edge", false, true, undefined],
      ["ssh", "Lab Raspberry", false, false, "No password saved"],
      ["xray", "de-fra-reality", false, true, "VLESS"],
      ["xray", "trojan-tokyo", false, true, "Trojan"],
      ["xray", "odd-one", false, false, "Unsupported"]
    ]);
  });

  it("names pinned Hysteria 2 and VMess profiles by their protocol", () => {
    const { servers } = buildTrayMenuModel(
      input({
        store: storeView({
          proxyProfiles: [
            profile("hy", "hy2-helsinki", { protocol: "hysteria2", transport: "hysteria", security: "tls", hopPorts: "443,20000-30000" }),
            profile("vm", "vmess-paris", { protocol: "vmess", transport: "ws", security: "none" })
          ]
        })
      })
    );
    expect(servers.filter((server) => server.kind === "xray").map((server) => [server.label, server.enabled, server.sublabel])).toEqual([
      ["hy2-helsinki", true, "Hysteria 2"],
      ["vmess-paris", true, "VMess"]
    ]);
  });

  it("marks a Hysteria 2 profile that asks to skip certificate checks without a pin", () => {
    const hysteria = { protocol: "hysteria2", transport: "hysteria", security: "tls" } as const;
    const { servers } = buildTrayMenuModel(
      input({
        store: storeView({
          proxyProfiles: [
            profile("hi", "hy2-self-signed", { ...hysteria, insecureWithoutPin: true }),
            profile("hp", "hy2-pinned", hysteria),
            profile("hu", "hy2-odd", { ...hysteria, transport: "unknown", insecureWithoutPin: true })
          ]
        })
      })
    );
    expect(servers.filter((server) => server.kind === "xray").map((server) => [server.label, server.enabled, server.sublabel])).toEqual([
      ["hy2-self-signed", true, "Hysteria 2 · insecure=1"],
      ["hy2-pinned", true, "Hysteria 2"],
      ["hy2-odd", false, "Unsupported"]
    ]);
  });

  it("shows the protected session, its server and the last check", () => {
    const model = buildTrayMenuModel(
      input({
        runtime: runtime({ state: "Connected", activeConfigId: "fra", activeConfigName: "Frankfurt-01", connectedAt: NOW }),
        lastTunnelCheck: { endpoint: "youtube.com:443", ok: true, at: NOW, message: "ok", latencyMs: 184.2, transport: "ssh" }
      })
    );
    expect(model).toMatchObject({
      tone: "ok",
      statusTitle: "Protected · SSH · Frankfurt-01",
      tooltip: "Shadow SSH — protected · SSH · Frankfurt-01",
      primary: { label: "Disconnect", action: "disconnect", enabled: true },
      switchNote: "Picking another one closes the current tunnel first, then connects.",
      check: { label: "Run check", enabled: true, sublabel: "Passed · 184 ms" },
      quitSublabel: "Disconnects the tunnel first"
    });
  });

  it("says Proxy ready on macOS and Linux, and flags a simulated session", () => {
    const connected = runtime({ state: "Connected", activeConfigId: "fra", connectedAt: NOW });
    expect(buildTrayMenuModel(input({ platform: "darwin", runtime: connected })).statusTitle).toBe("Proxy ready · SSH · Frankfurt-01");
    const preview = buildTrayMenuModel(input({ runtime: { ...connected, transport: "simulator" } }));
    expect(preview.tone).toBe("attention");
    expect(preview.statusTitle).toBe("Preview only · SSH · Frankfurt-01");
  });

  it("locks the menu while connecting", () => {
    const model = buildTrayMenuModel(input({ runtime: runtime({ state: "Connecting", activeConfigId: "fra" }) }));
    expect(model).toMatchObject({
      tone: "busy",
      statusTitle: "Connecting… · SSH · Frankfurt-01",
      tooltip: "Shadow SSH — connecting to Frankfurt-01",
      primary: { label: "Connecting…", action: "none", enabled: false, sublabel: "Can’t be cancelled" },
      switchEnabled: false,
      quitSublabel: "Disconnects the tunnel first"
    });
  });

  it("offers Try again after an error and checks the profile in use", () => {
    const model = buildTrayMenuModel(
      input({
        activeTransport: "xray",
        runtime: runtime({ state: "Error", transport: "xray", activeConfigId: "np", activeConfigName: "not-pinned", message: "Xray runtime exited." })
      })
    );
    expect(model).toMatchObject({
      tone: "attention",
      statusTitle: "Needs attention · Xray · not-pinned",
      tooltip: "Shadow SSH — needs attention",
      primary: { label: "Try again", action: "retry", enabled: true },
      quitSublabel: "Closes Shadow SSH"
    });
    // The profile in use stays in the menu even though it is not pinned.
    expect(model.servers.find((server) => server.checked)).toMatchObject({ kind: "xray", id: "np" });
  });

  it("blocks Connect when split tunnel has nothing to route", () => {
    const model = buildTrayMenuModel(input({ store: storeView({ routingMode: "selected-rules" }) }));
    expect(model.primary).toEqual({ label: "Connect", action: "none", enabled: false, sublabel: "Add a routing target first" });
    expect(model.switchEnabled).toBe(false);
    expect(model.switchNote).toBe("Split tunnel has nothing to route yet");
  });

  it("follows the last used transport when idle", () => {
    const model = buildTrayMenuModel(
      input({ store: storeView({ settings: { ...DEFAULT_SETTINGS, lastConnectedTransport: "xray" } }) })
    );
    expect(model.statusTitle).toBe("Not connected · Xray · de-fra-reality selected");
    expect(model.servers.find((server) => server.checked)).toMatchObject({ kind: "xray", id: "xr" });
  });

  it("asks for a server first on an empty library", () => {
    const model = buildTrayMenuModel(input({ store: storeView({ sshConfigs: [], proxyProfiles: [], selectedConfigId: undefined }) }));
    expect(model.primary).toEqual({ label: "Connect", action: "none", enabled: false, sublabel: "Add a server first" });
    expect(model.statusTitle).toBe("Not connected");
    expect(model.switchEnabled).toBe(false);
  });

  it("shows the checking state and ignores a result from the other transport", () => {
    const connected = runtime({ state: "Connected", activeConfigId: "fra", connectedAt: NOW });
    expect(buildTrayMenuModel(input({ runtime: connected, checkInProgress: true })).check).toEqual({
      label: "Run check",
      enabled: false,
      sublabel: "Checking…"
    });
    expect(
      buildTrayMenuModel(
        input({ runtime: connected, lastTunnelCheck: { endpoint: "x:443", ok: false, at: NOW, message: "no", transport: "xray" } })
      ).check
    ).toEqual({ label: "Run check", enabled: true });
  });

  it("disables everything while saved data is unreadable", () => {
    const model = buildTrayMenuModel(input({ storageReadable: false }));
    expect(model).toMatchObject({ tone: "attention", servers: [], switchEnabled: false, primary: { action: "none", enabled: false } });
  });

  it("keeps the tooltip within the Windows limit", () => {
    const longName = "x".repeat(200);
    const model = buildTrayMenuModel(
      input({ runtime: runtime({ state: "Connected", activeConfigId: "fra", activeConfigName: longName, connectedAt: NOW }) })
    );
    expect(model.tooltip.length).toBeLessThanOrEqual(127);
    expect(model.tooltip.endsWith("…")).toBe(true);
  });
});
