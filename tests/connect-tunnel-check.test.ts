import { describe, expect, it } from "vitest";
import {
  checkMeta,
  endpointError,
  looksLikeWebAddress,
  parseEndpoint,
  presentTunnelCheck,
  probeMethodCopy,
  probeMethodFor,
  reachCommand,
  type TextSegment,
  type TunnelCheckInput
} from "../src/renderer/components/pages/connect/tunnel-check.js";
import type { TunnelCheckResult } from "../src/shared/types.js";

const now = new Date(2026, 9, 6, 12, 10, 0);
const at = new Date(2026, 9, 6, 12, 4, 18).toISOString();

function result(overrides: Partial<TunnelCheckResult> = {}): TunnelCheckResult {
  return {
    endpoint: "youtube.com:443",
    ok: true,
    at,
    message: "Tunnel check succeeded for youtube.com:443 in 190 ms: youtube.com:443 answered the TLS handshake.",
    latencyMs: 184,
    transport: "ssh",
    targetName: "Frankfurt-01",
    ...overrides
  };
}

function input(overrides: Partial<TunnelCheckInput> = {}): TunnelCheckInput {
  return {
    endpoint: "youtube.com:443",
    activeTransport: "ssh",
    connected: true,
    checking: false,
    activeName: "Frankfurt-01",
    now,
    ...overrides
  };
}

const plain = (segments: TextSegment[]): string => segments.map((segment) => segment.text).join("");

describe("Check endpoint", () => {
  it("parses host:port including bracketed IPv6", () => {
    expect(parseEndpoint("youtube.com:443")).toEqual({ host: "youtube.com", port: 443 });
    expect(parseEndpoint("[2001:db8::1]:8443")).toEqual({ host: "2001:db8::1", port: 8443 });
    expect(parseEndpoint("youtube.com")).toBeUndefined();
    expect(parseEndpoint("host:70000")).toBeUndefined();
  });

  it("picks the probe the core uses for each port", () => {
    expect(probeMethodFor("youtube.com:443")).toEqual({ method: "tls", port: 443 });
    expect(probeMethodFor("mail.example.com:993")).toEqual({ method: "tls", port: 993 });
    expect(probeMethodFor("example.com:8080")).toEqual({ method: "http", port: 8080 });
    expect(probeMethodFor("db.example.net:5432")).toEqual({ method: "wait", port: 5432 });
    expect(probeMethodCopy("wait", 5432).text).toBe(
      "Port 5432 gets no probe. The check waits up to 12 s for the server to say something; silence still passes, but the route is not verified end to end."
    );
    expect(probeMethodCopy("http", 8080).label).toBe("HTTP HEAD /");
  });

  it("explains links and keeps the shared validation messages", () => {
    expect(endpointError("https://youtube.com")).toBe(
      "That is a web address, not an endpoint. Enter host:port without https:// or a path, for example youtube.com:443."
    );
    expect(endpointError("youtube.com:443/watch")).toBe("Enter host:port without https:// or a path — for example youtube.com:443.");
    expect(endpointError("")).toBe("Endpoint is required. Use host:port.");
    expect(endpointError("youtube.com")).toBe("Endpoint must use host:port with a valid TCP port.");
    expect(endpointError(" youtube.com:443 ")).toBeUndefined();
    expect(looksLikeWebAddress("user@host:22")).toBe(true);
    expect(looksLikeWebAddress("youtube.com:4")).toBe(false);
  });

  it("suggests a command the server terminal can run", () => {
    expect(reachCommand("youtube.com:443")).toBe("curl -I https://youtube.com");
    expect(reachCommand("example.com:8443")).toBe("curl -I https://example.com:8443");
    expect(reachCommand("example.com:80")).toBe("curl -I http://example.com");
    expect(reachCommand("db.example.net:5432")).toBe("nc -vz db.example.net 5432");
  });
});

describe("Tunnel check presentation", () => {
  it("waits while nothing is connected and never shows a stale result", () => {
    const view = presentTunnelCheck(input({ connected: false, result: result() }));
    expect(view.kind).toBe("waiting");
    expect(view.badge).toBe("Waiting");
    expect(view.meta).toBeUndefined();
  });

  it("shows a manual run with the endpoint in mono", () => {
    const view = presentTunnelCheck(input({ checking: true }));
    expect(view.kind).toBe("checking");
    expect(view.badge).toBe("Checking…");
    expect(view.text.find((segment) => segment.kind === "mono")?.text).toBe("youtube.com:443");
    expect(plain(view.text)).toBe("Sending a test request to youtube.com:443 through the tunnel. This takes up to 12 s.");
  });

  it("asks for a run before there is a result for this tunnel", () => {
    expect(presentTunnelCheck(input()).badge).toBe("Not run yet");
    expect(presentTunnelCheck(input({ result: result({ transport: "xray" }) })).kind).toBe("idle");
  });

  it("reads a pass with its latency and names the tunnel it checked", () => {
    const view = presentTunnelCheck(input({ result: result() }));
    expect(view.badge).toBe("Passed · 184 ms");
    expect(plain(view.text)).toBe("youtube.com:443 answered the TLS handshake through the tunnel.");
    expect(view.meta).toBe("SSH · Frankfurt-01 · today 12:04:18");
  });

  it("keeps the HTTP status line and falls back to the message's timing", () => {
    const view = presentTunnelCheck(
      input({
        endpoint: "example.com:8080",
        result: result({
          endpoint: "example.com:8080",
          latencyMs: undefined,
          message: "Tunnel check succeeded for example.com:8080 in 212 ms: example.com:8080 answered HTTP/1.1 301 Moved Permanently."
        })
      })
    );
    expect(view.badge).toBe("Passed · 212 ms");
    expect(plain(view.text)).toBe("example.com:8080 answered HTTP/1.1 301 Moved Permanently through the tunnel.");
  });

  it("passes a silent port with a note", () => {
    const view = presentTunnelCheck(
      input({ activeTransport: "xray", result: result({ endpoint: "db.example.org:5432", note: true, transport: "xray", targetName: "de-fra-reality" }) })
    );
    expect(view.kind).toBe("note");
    expect(view.badge).toBe("Passed");
    expect(plain(view.text)).toMatch(/^The tunnel opened a connection to db\.example\.org:5432\. The server sent nothing back/u);
    expect(view.meta).toBe("Xray · de-fra-reality · today 12:04:18");
  });

  it("explains a timeout and what to try next", () => {
    const view = presentTunnelCheck(
      input({
        result: result({
          ok: false,
          latencyMs: undefined,
          message:
            "The tunnel opened a connection to youtube.com:443 but nothing came back within 12s. Traffic is entering the tunnel and not reaching the server."
        })
      })
    );
    expect(view.kind).toBe("failed");
    expect(plain(view.text)).toBe("The tunnel opened a connection to youtube.com:443 but nothing came back within 12 s.");
    expect(view.stepsIntro).toBe("Traffic reaches Frankfurt-01 but not the site. Try this:");
    expect(view.steps).toHaveLength(3);
    expect(view.steps?.[1].find((segment) => segment.kind === "code")?.text).toBe("curl -I https://youtube.com");
  });

  it("keeps the raw reason for other failures and offers no terminal step on Xray", () => {
    const view = presentTunnelCheck(
      input({
        activeTransport: "xray",
        result: result({ ok: false, transport: "xray", message: "Upstream SOCKS5 proxy refused youtube.com:443 with code 5" })
      })
    );
    expect(plain(view.text)).toBe("The check to youtube.com:443 failed: Upstream SOCKS5 proxy refused youtube.com:443 with code 5.");
    expect(view.steps?.some((step) => step.some((segment) => segment.kind === "code"))).toBe(false);
  });

  it("formats the scope line without a name when none is known", () => {
    expect(checkMeta(result({ targetName: undefined, transport: undefined }), "xray", undefined, now)).toBe("Xray · today 12:04:18");
  });
});
