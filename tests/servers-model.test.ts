import { describe, expect, it } from "vitest";
import { findExiting, mergeExiting } from "../src/renderer/components/pages/servers/exiting-items.js";
import {
  filterServers,
  liveDeletedCallout,
  matchLabel,
  serverDeleteCopy,
  serverDeletedMessage,
  serverSignIn,
  sshSessionView,
  upNextCallout,
  type SshSessionView
} from "../src/renderer/components/pages/servers/server-model.js";
import type { SshConfig, SshKeyMetadata } from "../src/shared/types.js";
import { createTestRuntime } from "./renderer-fixtures.js";

const at = "2026-10-06T10:00:00.000Z";

function server(overrides: Partial<SshConfig> & Pick<SshConfig, "id" | "name">): SshConfig {
  return {
    host: "203.0.113.10",
    port: 22,
    username: "root",
    authType: "password",
    expectedServerFingerprint: "",
    keepaliveIntervalSec: 120,
    note: "",
    createdAt: at,
    updatedAt: at,
    ...overrides
  };
}

const keys: SshKeyMetadata[] = [
  { id: "key-work", name: "work-ed25519", privateKeySecretId: "s1", fingerprint: "sha256:x", keyType: "ed25519", createdAt: at, updatedAt: at }
];

const fra = server({ id: "fra", name: "Frankfurt-01", passwordSecretId: "pw-fra", expectedServerFingerprint: "SHA256:abc" });
const ams = server({ id: "ams", name: "Amsterdam-edge", host: "198.51.100.24", port: 2222, username: "deploy", authType: "private-key", privateKeyId: "key-work" });
const hel = server({ id: "hel", name: "Helsinki-backup", host: "helsinki.example.net", username: "admin" });
const lab = server({ id: "lab", name: "Lab Raspberry", host: "192.0.2.55", username: "pi" });
const configs = [fra, ams, hel, lab];

const live = (activeId: string, state: SshSessionView["state"] = "connected"): SshSessionView => ({ on: true, state, activeId, activeName: "Frankfurt-01" });
const off: SshSessionView = { on: false };

describe("sshSessionView", () => {
  it("reports the SSH session only while it starts, runs or reconnects", () => {
    expect(sshSessionView({ activeTransport: "ssh", runtime: createTestRuntime({ state: "Connected", activeConfigId: "fra", activeConfigName: "Frankfurt-01" }) })).toEqual({
      on: true,
      state: "connected",
      activeId: "fra",
      activeName: "Frankfurt-01"
    });
    expect(sshSessionView({ activeTransport: "ssh", runtime: createTestRuntime({ state: "Reconnecting", activeConfigId: "fra" }) }).state).toBe("reconnecting");
    expect(sshSessionView({ activeTransport: "ssh", runtime: createTestRuntime({ state: "Error", activeConfigId: "fra" }) }).on).toBe(false);
    expect(sshSessionView({ activeTransport: "ssh", runtime: createTestRuntime({ state: "Disconnecting", activeConfigId: "fra" }) }).on).toBe(false);
    expect(sshSessionView({ activeTransport: "xray", runtime: createTestRuntime({ state: "Connected", activeConfigId: "profile" }) }).on).toBe(false);
    expect(sshSessionView({ activeTransport: "ssh", runtime: createTestRuntime({ state: "Connected", transport: "simulator", activeConfigId: "fra" }) }).state).toBe("preview");
  });
});

describe("filterServers", () => {
  it("matches names, hosts and usernames, every word", () => {
    expect(filterServers(configs, "").length).toBe(4);
    expect(filterServers(configs, "  ").length).toBe(4);
    expect(filterServers(configs, "frank").map((config) => config.id)).toEqual(["fra"]);
    expect(filterServers(configs, "example.net").map((config) => config.id)).toEqual(["hel"]);
    expect(filterServers(configs, "DEPLOY").map((config) => config.id)).toEqual(["ams"]);
    expect(filterServers(configs, "pi 192.0.2").map((config) => config.id)).toEqual(["lab"]);
    expect(filterServers(configs, "tokyo")).toEqual([]);
  });

  it("labels the match count", () => {
    expect(matchLabel(0)).toBe("no matches");
    expect(matchLabel(1)).toBe("1 match");
    expect(matchLabel(3)).toBe("3 matches");
  });
});

describe("serverSignIn", () => {
  it("tells password, missing password, key and missing key apart", () => {
    expect(serverSignIn(fra, keys)).toEqual({ kind: "password", saved: true });
    expect(serverSignIn(lab, keys)).toEqual({ kind: "password", saved: false });
    expect(serverSignIn(ams, keys)).toEqual({ kind: "key", key: keys[0] });
    expect(serverSignIn(server({ id: "x", name: "x", authType: "private-key" }), keys)).toEqual({ kind: "key", key: undefined });
  });
});

describe("delete copy", () => {
  it("mentions the saved password and what Connect uses next", () => {
    const copy = serverDeleteCopy(fra, { configs, keys, selectedId: "fra", session: live("fra") });
    expect(copy).toEqual({
      title: "Delete Frankfurt-01?",
      description: "The server and its saved password are removed from this device. This can’t be undone.",
      live: true,
      nextLine: "Connect will use Amsterdam-edge next."
    });
  });

  it("says the key stays for key sign-in and skips the next line for other servers", () => {
    const copy = serverDeleteCopy(ams, { configs, keys, selectedId: "fra", session: off });
    expect(copy.description).toBe("The server is removed from this device. The key work-ed25519 stays in SSH keys.");
    expect(copy.live).toBe(false);
    expect(copy.nextLine).toBeUndefined();
  });

  it("warns when no server will be left", () => {
    expect(serverDeleteCopy(lab, { configs: [lab], keys, selectedId: "lab", session: off }).nextLine).toBe(
      "No servers will be left. Add one before you connect again."
    );
  });

  it("words the result toast", () => {
    expect(serverDeletedMessage(fra, { keys, wasLive: true })).toBe("Frankfurt-01 is gone from your list. Its session keeps running until you disconnect.");
    expect(serverDeletedMessage(fra, { keys, wasLive: false })).toBe("Frankfurt-01 and its saved password were removed from this device.");
    expect(serverDeletedMessage(ams, { keys, wasLive: false })).toBe("Amsterdam-edge was removed. The key work-ed25519 is still in SSH keys.");
    expect(serverDeletedMessage(lab, { keys, wasLive: false })).toBe("Lab Raspberry was removed from this device.");
  });
});

describe("session callouts", () => {
  it("announces the next server while the session runs on another one", () => {
    expect(upNextCallout(configs, "ams", live("fra"))).toEqual({
      title: "Amsterdam-edge is up next",
      message: "You’re still connected to Frankfurt-01. Connect switches to Amsterdam-edge the next time you connect."
    });
    expect(upNextCallout(configs, "fra", live("fra"))).toBeUndefined();
    expect(upNextCallout(configs, "ams", off)).toBeUndefined();
  });

  it("keeps a deleted live server visible", () => {
    const rest = [ams, hel, lab];
    expect(liveDeletedCallout(rest, "ams", live("fra"))).toEqual({
      title: "Still connected to a deleted server",
      message: "Frankfurt-01 is no longer in your list, but its session keeps running until you disconnect. Next time, Connect uses Amsterdam-edge."
    });
    expect(liveDeletedCallout([], undefined, live("fra"))?.message).toMatch(/Add a server before you connect again\.$/u);
    expect(liveDeletedCallout(configs, "fra", live("fra"))).toBeUndefined();
    expect(upNextCallout(rest, "ams", live("fra"))).toBeUndefined();
  });
});

describe("exiting items", () => {
  const id = (item: { id: string }): string => item.id;

  it("finds only marked items that disappeared", () => {
    const before = [{ id: "a" }, { id: "b" }, { id: "c" }];
    const after = [{ id: "a" }, { id: "c" }];
    expect(findExiting(before, after, new Set(["b"]), id)).toEqual([{ id: "b", item: { id: "b" }, index: 1 }]);
    expect(findExiting(before, after, new Set(), id)).toEqual([]);
    expect(findExiting(before, [{ id: "a" }], new Set(["b"]), id).map((ghost) => ghost.id)).toEqual(["b"]);
  });

  it("puts leaving items back where they were", () => {
    const merged = mergeExiting([{ id: "a" }, { id: "c" }], [{ id: "b", item: { id: "b" }, index: 1 }], id);
    expect(merged).toEqual([
      { item: { id: "a" }, leaving: false },
      { item: { id: "b" }, leaving: true },
      { item: { id: "c" }, leaving: false }
    ]);
    expect(mergeExiting([], [{ id: "z", item: { id: "z" }, index: 4 }], id)).toEqual([{ item: { id: "z" }, leaving: true }]);
    // A ghost whose id came back is not shown twice.
    expect(mergeExiting([{ id: "b" }], [{ id: "b", item: { id: "b" }, index: 0 }], id)).toEqual([{ item: { id: "b" }, leaving: false }]);
  });
});
