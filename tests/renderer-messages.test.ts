import { describe, expect, it } from "vitest";
import { describeError, stripIpcPrefix } from "../src/renderer/lib/errors.js";
import {
  classifyReconnectReason,
  extractAttempt,
  formatLocalProxy,
  parseLocalProxy,
  runtimeLocalProxy
} from "../src/renderer/lib/runtime-message.js";
import { createTestRuntime } from "./renderer-fixtures.js";

describe("describeError", () => {
  it("strips the IPC envelope and keeps the raw text as technical details", () => {
    const error = new Error("Error invoking remote method 'shadow-ssh:delete-key': Error: This private key is used by Amsterdam-edge.");
    expect(stripIpcPrefix(error.message)).toBe("This private key is used by Amsterdam-edge.");
    expect(describeError(error, { title: "Couldn't delete key" })).toEqual({
      title: "Couldn't delete key",
      message: "This private key is used by Amsterdam-edge.",
      technical: error.message
    });
  });

  it("turns network failures into plain words", () => {
    const offline = describeError(
      new Error("Error invoking remote method 'shadow-ssh:check-for-updates': Error: net::ERR_INTERNET_DISCONNECTED"),
      { title: "Couldn't check for updates", target: "GitHub" }
    );
    expect(offline.message).toBe("Can't reach GitHub. Check your internet connection, then try again.");
    expect(offline.technical).toContain("ERR_INTERNET_DISCONNECTED");

    expect(describeError(new Error("getaddrinfo ENOTFOUND api.github.com")).message).toBe(
      "Can't find the server. Check the address and your internet connection, then try again."
    );
    expect(describeError(new Error("connect ECONNREFUSED 127.0.0.1:22")).message).toContain("refused the connection");
    expect(describeError(new Error("fetch failed")).message).toContain("Check your internet connection");
    expect(describeError(new Error("Request timed out after 10000 ms")).message).toContain("took too long to answer");
  });

  it("handles non-Error values and adds a full stop", () => {
    expect(describeError("routing apply failed").message).toBe("Routing apply failed.");
    expect(describeError({ code: 5 }).message).toBe('{"code":5}.');
    expect(describeError(new Error("Saved.")).technical).toBeUndefined();
  });
});

describe("reconnect reasons", () => {
  it("treats network changes, wake, clock jumps and the watchdog as routine", () => {
    expect(classifyReconnectReason("Reconnecting after SSH failure: network-changed: network interfaces changed (lost Wi-Fi)", "Frankfurt-01")).toMatchObject({
      kind: "network-change",
      tone: "info",
      likelyStuck: false,
      title: "Your network changed"
    });
    expect(classifyReconnectReason("Reconnecting after SSH failure: system resume")?.kind).toBe("wake");
    expect(classifyReconnectReason("Reconnecting after SSH failure: clock-jump: the process did not run for about 94 s")?.kind).toBe("clock-jump");
    expect(classifyReconnectReason("Reconnecting after SSH failure: supervisor watchdog")?.kind).toBe("watchdog");
    expect(classifyReconnectReason("SSH session lost (keepalive timed out); reconnecting.")).toMatchObject({ kind: "session-lost", technical: "keepalive timed out" });
  });

  it("flags failures that will not fix themselves", () => {
    for (const message of [
      "Reconnect attempt 7 failed: getaddrinfo ENOTFOUND helsinki.example.net",
      "Reconnecting after SSH failure: connect ECONNREFUSED 203.0.113.10:22",
      "Restarting Xray transport after failure: handshake failed: no matching key exchange algorithm"
    ]) {
      expect(classifyReconnectReason(message)).toMatchObject({ kind: "stuck", tone: "warn", likelyStuck: true });
    }
  });

  it("extracts the attempt number with a fallback", () => {
    expect(extractAttempt("Reconnecting to 203.0.113.10:22 (attempt 3).")).toBe(3);
    expect(extractAttempt("Reconnect attempt 7 failed: x")).toBe(7);
    expect(extractAttempt("Reconnecting after SSH failure: x", 2)).toBe(2);
    expect(extractAttempt("Reconnecting", 0)).toBeUndefined();
  });
});

describe("local proxy parsing", () => {
  it("reads SSH and Xray connected messages", () => {
    expect(parseLocalProxy("Connected to Frankfurt-01. HTTP/SOCKS proxy 127.0.0.1:50817, direct-tcpip, and shell channels are live.")).toEqual({
      host: "127.0.0.1",
      httpPort: 50817
    });
    expect(parseLocalProxy("Connected to de-fra-reality. Xray HTTP proxy 127.0.0.1:10809 and SOCKS proxy 127.0.0.1:10808 are live.")).toEqual({
      host: "127.0.0.1",
      httpPort: 10809,
      socksPort: 10808
    });
    expect(parseLocalProxy("Local HTTP/SOCKS proxy is listening on 127.0.0.1:50817.")).toEqual({ host: "127.0.0.1", httpPort: 50817 });
    expect(parseLocalProxy("Disconnected.")).toBeUndefined();
  });

  it("prefers the reported endpoint and formats it for copying", () => {
    const reported = createTestRuntime({ state: "Connected", localProxy: { host: "127.0.0.1", httpPort: 1080 }, message: "HTTP/SOCKS proxy 127.0.0.1:50817" });
    expect(runtimeLocalProxy(reported)).toEqual({ host: "127.0.0.1", httpPort: 1080 });
    expect(formatLocalProxy({ host: "::1", httpPort: 1080 })).toBe("[::1]:1080");
  });
});
