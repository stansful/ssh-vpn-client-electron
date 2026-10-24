import { describe, expect, it } from "vitest";
import {
  parseBoolean,
  parseCheckEndpointArgument,
  parseImportProxyProfilesInput,
  parseRoutingMode,
  parseRoutingRules,
  parseSettingsPatch,
  parseUpsertSshConfigInput
} from "../src/main/app/ipc-validation.js";
import { DEFAULT_SETTINGS } from "../src/shared/defaults.js";
import type { RoutingRule } from "../src/shared/types.js";

const at = "2026-10-01T10:00:00.000Z";

function rule(overrides: Partial<RoutingRule> = {}): RoutingRule {
  return { id: "rule-1", type: "domain", value: "example.com", enabled: true, createdAt: at, updatedAt: at, ...overrides };
}

describe("settings patch", () => {
  it("accepts every setting the renderer changes", () => {
    const editable: Partial<typeof DEFAULT_SETTINGS> = { ...DEFAULT_SETTINGS };
    delete editable.updateCheckCache;
    expect(parseSettingsPatch(editable)).toEqual(editable);
    expect(parseSettingsPatch({ theme: "custom", customTheme: { accent: { r: 1, g: 2, b: 3 } } })).toEqual({
      theme: "custom",
      customTheme: { accent: { r: 1, g: 2, b: 3 } }
    });
    expect(parseSettingsPatch({ sidebarCollapsed: undefined })).toEqual({});
  });

  it("refuses unknown keys and the update checker's own cache", () => {
    expect(() => parseSettingsPatch({ isAdmin: true })).toThrow("Unknown setting: isAdmin.");
    expect(() => parseSettingsPatch({ updateCheckCache: { checkedAt: at, latestVersion: "99.0.0" } })).toThrow(
      "Unknown setting: updateCheckCache."
    );
    expect(() => parseSettingsPatch({ __proto__: { polluted: true }, ["constructor"]: {} })).toThrow(/Unknown setting/u);
  });

  it("refuses values of the wrong type or out of range", () => {
    for (const patch of [
      { autoConnectOnStartup: "yes" },
      { tunDataplaneEnabled: 1 },
      { theme: "neon" },
      { activeGlobalTab: "opensource" },
      { lastConnectedTransport: null },
      { checkEndpoint: 443 },
      { customTheme: { accent: { r: 300, g: 0, b: 0 } } },
      { customTheme: { accent: { r: Number.NaN, g: 0, b: 0 } } },
      { customTheme: { glow: { r: 1, g: 1, b: 1 } } },
      { customTheme: "dark" }
    ]) {
      expect(() => parseSettingsPatch(patch), JSON.stringify(patch)).toThrow();
    }
    for (const value of [null, "theme", [], 3]) {
      expect(() => parseSettingsPatch(value)).toThrow("Settings is invalid.");
    }
  });
});

describe("routing mode and switches", () => {
  it("accepts only the two modes", () => {
    expect(parseRoutingMode("proxy-all")).toBe("proxy-all");
    expect(parseRoutingMode("selected-rules")).toBe("selected-rules");
    expect(() => parseRoutingMode("bogus")).toThrow("Routing mode must be one of: proxy-all, selected-rules.");
    expect(() => parseRoutingMode(undefined)).toThrow();
  });

  it("takes a list switch only as true or false", () => {
    expect(parseBoolean(true, "Blocked in Russia")).toBe(true);
    expect(() => parseBoolean("false", "Blocked in Russia")).toThrow("Blocked in Russia must be true or false.");
  });
});

describe("routing rules", () => {
  it("keeps valid rules and drops fields a rule doesn't have", () => {
    const parsed = parseRoutingRules([{ ...rule(), extra: "x", value: "*.example.com" }, rule({ id: "rule-2", type: "ip", value: "10.0.0.0/8" })]);
    expect(parsed).toEqual([rule({ value: "*.example.com" }), rule({ id: "rule-2", type: "ip", value: "10.0.0.0/8" })]);
    expect(parsed[0]).not.toHaveProperty("extra");
  });

  it("checks new and changed values with the form's validators", () => {
    expect(() => parseRoutingRules([rule({ value: "localhost" })])).toThrow(/at least two labels/u);
    expect(() => parseRoutingRules([rule({ type: "ip", value: "999.1.1.1" })])).toThrow(/IPv4 or IPv6/u);
    expect(() => parseRoutingRules([rule({ type: "process.name", value: "C:\\Windows\\evil.exe" })])).toThrow(/not a path/u);
    expect(() => parseRoutingRules([rule({ type: "regex" as RoutingRule["type"] })])).toThrow(/type must be one of/u);
    expect(() => parseRoutingRules([rule({ enabled: "yes" as unknown as boolean })])).toThrow(/enabled must be true or false/u);
    expect(() => parseRoutingRules([rule({ id: "" })])).toThrow(/id is required/u);
    expect(() => parseRoutingRules("rules")).toThrow("Routing rules must be a list.");
    expect(() => parseRoutingRules(Array.from({ length: 10_001 }, (_, index) => rule({ id: `r${index}` })))).toThrow(/10000 rule limit/u);
  });

  it("lets a saved rule the checks have grown stricter about come back unchanged", () => {
    const legacy = rule({ id: "old", value: "intranet" });
    expect(parseRoutingRules([legacy, rule({ id: "new", value: "example.org" })], [legacy])).toHaveLength(2);
    expect(() => parseRoutingRules([{ ...legacy, value: "intranet2" }], [legacy])).toThrow();
    expect(() => parseRoutingRules([{ ...legacy, type: "process.name" }], [legacy])).not.toThrow();
    expect(() => parseRoutingRules([{ ...legacy, type: "ip" }], [legacy])).toThrow();
  });

  it("takes back a rule saved with a zero-padded prefix, written the way every path reads it", () => {
    // Deleted, then restored with Undo: by then it has left the store, so it
    // is checked like a new rule.
    expect(parseRoutingRules([rule({ id: "old", type: "ip", value: "91.108.4.0/022" })], [])).toEqual([
      rule({ id: "old", type: "ip", value: "91.108.4.0/22" })
    ]);
    expect(parseRoutingRules([rule({ id: "zero", type: "ip", value: "0.0.0.0/00" })])[0]?.value).toBe("0.0.0.0/0");
  });

  it("fills in a missing or garbled timestamp instead of refusing the list", () => {
    const [parsed] = parseRoutingRules([{ ...rule(), createdAt: undefined, updatedAt: "x".repeat(500) }]);
    expect(Number.isFinite(Date.parse(parsed?.createdAt ?? ""))).toBe(true);
    expect(Number.isFinite(Date.parse(parsed?.updatedAt ?? ""))).toBe(true);
  });
});

describe("SSH server input", () => {
  const form = {
    id: undefined,
    name: " Frankfurt-01 ",
    host: "203.0.113.10",
    port: 22,
    username: "root",
    authType: "password",
    password: "secret",
    privateKeyId: undefined,
    expectedServerFingerprint: "",
    keepaliveIntervalSec: 120,
    note: ""
  };

  it("accepts what the server form sends", () => {
    expect(parseUpsertSshConfigInput(form)).toEqual({
      name: "Frankfurt-01",
      host: "203.0.113.10",
      port: 22,
      username: "root",
      authType: "password",
      password: "secret",
      expectedServerFingerprint: "",
      keepaliveIntervalSec: 120,
      note: ""
    });
    expect(parseUpsertSshConfigInput({ ...form, id: "srv-1", authType: "private-key", password: undefined, privateKeyId: "key-1", host: "2001:db8::1" })).toMatchObject({
      id: "srv-1",
      authType: "private-key",
      privateKeyId: "key-1",
      host: "2001:db8::1"
    });
  });

  it("refuses ports, keepalives and sign-in methods the form would not allow", () => {
    for (const patch of [
      { port: 0 },
      { port: 65_536 },
      { port: 22.5 },
      { port: "22" },
      { keepaliveIntervalSec: Number.NaN },
      { keepaliveIntervalSec: 59 },
      { keepaliveIntervalSec: 3601 },
      { keepaliveIntervalSec: Number.POSITIVE_INFINITY },
      { authType: "certificate" },
      { name: "  " },
      { host: "" },
      { host: "ssh://vps.example.net" },
      { host: "root@vps.example.net" },
      { username: "" },
      { username: "two words" },
      { password: 42 },
      { privateKeyId: 7 },
      { note: 1 }
    ]) {
      expect(() => parseUpsertSshConfigInput({ ...form, ...patch }), JSON.stringify(patch)).toThrow();
    }
    expect(() => parseUpsertSshConfigInput(null)).toThrow("SSH server is invalid.");
  });

  it("keeps fields the input doesn't have out of the result", () => {
    expect(parseUpsertSshConfigInput({ ...form, passwordSecretId: "someone-elses-secret" })).not.toHaveProperty("passwordSecretId");
  });
});

describe("import and tunnel check input", () => {
  it("checks the import source", () => {
    expect(parseImportProxyProfilesInput({ text: "vless://a", source: "clipboard" })).toEqual({ text: "vless://a", source: "clipboard" });
    expect(parseImportProxyProfilesInput({ text: "", source: "remote", sourceUrl: "https://list.example/x" })).toEqual({
      text: "",
      source: "remote",
      sourceUrl: "https://list.example/x"
    });
    expect(() => parseImportProxyProfilesInput({ text: "x", source: "bluetooth" })).toThrow(/Import source/u);
    expect(() => parseImportProxyProfilesInput({ text: 1, source: "manual" })).toThrow(/Import text/u);
  });

  it("checks a tunnel check endpoint the way the endpoint dialog does", () => {
    expect(parseCheckEndpointArgument(undefined)).toBeUndefined();
    expect(parseCheckEndpointArgument("  ")).toBeUndefined();
    expect(parseCheckEndpointArgument(" youtube.com:443 ")).toBe("youtube.com:443");
    expect(() => parseCheckEndpointArgument("https://youtube.com")).toThrow(/host:port/u);
    expect(() => parseCheckEndpointArgument("youtube.com")).toThrow(/valid TCP port/u);
    expect(() => parseCheckEndpointArgument(443)).toThrow("Endpoint must be text.");
  });
});
