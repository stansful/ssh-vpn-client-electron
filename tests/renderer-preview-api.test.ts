import { describe, expect, it } from "vitest";
import { createBrowserPreviewApi } from "../src/renderer/browser-preview-api.js";
import { isAppSnapshot, snapshotOf } from "../src/renderer/hooks/useAsyncAction.js";

describe("browser preview API", () => {
  it("seeds the canon sample data", async () => {
    const api = createBrowserPreviewApi();
    const snapshot = await api.loadSnapshot();

    expect(snapshot.store.sshConfigs.map((config) => config.name)).toEqual(["Frankfurt-01", "Amsterdam-edge", "Helsinki-backup", "Lab Raspberry"]);
    expect(snapshot.store.sshKeys.map((key) => key.name)).toEqual(["work-ed25519", "home-rsa", "old-laptop"]);
    expect(snapshot.store.proxyProfiles).toHaveLength(128);
    expect(snapshot.store.proxyProfiles.filter((profile) => profile.isPinned)).toHaveLength(12);
    expect(snapshot.store.routingRules).toHaveLength(14);
    expect(snapshot.store.routingProxyList.domains).toHaveLength(1982);
    expect(snapshot.runtime).toMatchObject({ state: "Connected", activeConfigName: "Frankfurt-01", localProxy: { httpPort: 50817 } });
    expect(snapshot.lastTunnelCheck).toMatchObject({ ok: true, latencyMs: 184, transport: "ssh" });
    expect(snapshot.attention.length).toBeGreaterThan(0);
    expect(snapshot.diagnostics.every((entry) => entry.source !== undefined)).toBe(true);
    expect(snapshot.updateInfo).toMatchObject({ available: true, latestVersion: "2.3.0" });
    expect(snapshot.environment).toMatchObject({ platform: "windows", version: "2.2.0" });
    expect(snapshot.storageHealth).toEqual({ state: "ok" });
  });

  it("returns routing mutations as { snapshot } and blocks unsupported profiles", async () => {
    const api = createBrowserPreviewApi();
    const result = await api.updateRoutingMode("proxy-all");

    expect(snapshotOf(result)?.store.routingMode).toBe("proxy-all");
    expect(isAppSnapshot(result)).toBe(false);
    expect(result.applyError).toBeUndefined();

    const snapshot = await api.loadSnapshot();
    const unsupported = snapshot.store.proxyProfiles.find((profile) => profile.security === "unknown");
    await expect(api.selectProxyProfile(unsupported!.id)).rejects.toThrow("unsupported security mode or transport");
  });

  it("dismisses attention events one at a time or all at once", async () => {
    const api = createBrowserPreviewApi();
    const first = (await api.loadSnapshot()).attention[0];

    const afterOne = await api.dismissAttention(first.id);
    expect(afterOne.attention.some((event) => event.id === first.id)).toBe(false);

    const afterAll = await api.dismissAttention();
    expect(afterAll.attention).toEqual([]);
  });

  it("refreshes the public list like the main process: same links update, missing ones go stale", async () => {
    const api = createBrowserPreviewApi();
    const before = await api.loadSnapshot();
    const { snapshot, result } = await api.refreshProxyProfiles();

    expect(result).toMatchObject({ imported: 2, failed: 0 });
    expect(result.updated).toBeGreaterThan(100);
    expect(snapshot.store.proxyProfiles).toHaveLength(before.store.proxyProfiles.length + 2);
    expect(snapshot.store.proxyProfiles.find((profile) => profile.name === "public-58")?.isStale).toBe(true);
  });

  it("matches imported links by fingerprint and reports parser errors per line", async () => {
    const api = createBrowserPreviewApi();
    await api.loadSnapshot();
    const link = "vless://11111111-1111-4111-8111-111111111111@example.org:443?security=tls&type=ws#one";
    const first = await api.importProxyProfiles({ text: `${link}\nhttps://example.org`, source: "clipboard" });
    expect(first.result).toMatchObject({ imported: 1, updated: 0, failed: 1 });
    expect(first.result.errors).toEqual(["Line 2: Only vless://, vmess://, trojan://, and hysteria2:// links are supported."]);

    const again = await api.importProxyProfiles({ text: link, source: "clipboard" });
    expect(again.result).toMatchObject({ imported: 0, updated: 1 });
  });

  it("seeds Hysteria 2 public profiles, some hopping ports, and keeps them through a refresh", async () => {
    const api = createBrowserPreviewApi();
    const before = await api.loadSnapshot();
    const hysteria = before.store.proxyProfiles.filter((profile) => profile.protocol === "hysteria2");
    expect(hysteria.length).toBeGreaterThan(5);
    expect(hysteria.every((profile) => profile.transport === "hysteria" && profile.security === "tls")).toBe(true);
    expect(before.store.proxyProfiles.find((profile) => profile.name === "public-04")).toMatchObject({ protocol: "hysteria2", port: 443, hopPorts: "443,20000-30000" });
    expect(before.store.proxyProfiles.find((profile) => profile.name === "public-14")).not.toHaveProperty("hopPorts");
    expect(hysteria.some((profile) => profile.isPinned)).toBe(true);

    const { snapshot } = await api.refreshProxyProfiles();
    expect(snapshot.store.proxyProfiles.find((profile) => profile.name === "public-04")).toMatchObject({ hopPorts: "443,20000-30000", isStale: false });
  });

  it("carries hop ports when a Hysteria 2 link is added or imported", async () => {
    const api = createBrowserPreviewApi();
    await api.loadSnapshot();
    const link = "hy2://letmein@hel.example.net:443,20000-30000?sni=hel.example.net#fi-hel-hy2";
    const added = await api.upsertProxyProfile({ name: "", rawUri: link, source: "manual" });
    expect(added.store.proxyProfiles.find((profile) => profile.name === "fi-hel-hy2")).toMatchObject({
      protocol: "hysteria2",
      host: "hel.example.net",
      port: 443,
      hopPorts: "443,20000-30000",
      transport: "hysteria",
      security: "tls"
    });

    const again = await api.importProxyProfiles({ text: link.replace("hy2://", "hysteria2://"), source: "clipboard" });
    expect(again.result).toMatchObject({ imported: 0, updated: 1 });
    expect(again.snapshot.store.proxyProfiles.filter((profile) => profile.name === "fi-hel-hy2")).toHaveLength(1);
  });

  it("marks insecure=1 Hysteria 2 links without a pin when seeded, refreshed, imported or added", async () => {
    const api = createBrowserPreviewApi();
    const before = await api.loadSnapshot();
    const marked = (profiles: readonly { name: string; insecureWithoutPin?: boolean }[]) =>
      profiles.filter((profile) => profile.insecureWithoutPin).map((profile) => profile.name);
    expect(marked(before.store.proxyProfiles)).toEqual(["public-14"]);
    expect(before.store.proxyProfiles.find((profile) => profile.name === "public-04")).not.toHaveProperty("insecureWithoutPin");

    const { snapshot } = await api.refreshProxyProfiles();
    expect(marked(snapshot.store.proxyProfiles)).toEqual(["public-14"]);

    const imported = await api.importProxyProfiles({
      text: ["hy2://letmein@a.example.net?insecure=1#self-signed", `hy2://letmein@b.example.net?insecure=1&pinSHA256=${"ab".repeat(32)}#pinned`].join("\n"),
      source: "clipboard"
    });
    expect(marked(imported.snapshot.store.proxyProfiles)).toEqual(["public-14", "self-signed"]);

    const selfSigned = imported.snapshot.store.proxyProfiles.find((profile) => profile.name === "self-signed");
    const fixed = await api.upsertProxyProfile({ id: selfSigned?.id, name: "", rawUri: `hy2://letmein@a.example.net?insecure=1&pinSHA256=${"cd".repeat(32)}#self-signed` });
    expect(fixed.store.proxyProfiles.find((profile) => profile.id === selfSigned?.id)).not.toHaveProperty("insecureWithoutPin");
  });

  it("clears attention with Activity and reports log files with their archives", async () => {
    const api = createBrowserPreviewApi();
    const loaded = await api.loadSnapshot();
    expect(loaded.logFilePaths).toHaveLength(3);
    expect((await api.readLogFile()).startsWith(`### ${loaded.logFilePaths[0]}\n`)).toBe(true);

    const files = await api.getLogFileInfo();
    expect(files.map((file) => file.exists)).toEqual([true, true, true]);

    expect((await api.clearDiagnostics()).attention).toEqual([]);
    await api.clearLogFile();
    expect((await api.getLogFileInfo()).map((file) => file.exists)).toEqual([true, false, false]);
  });
});
