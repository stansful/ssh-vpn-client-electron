import { describe, expect, it } from "vitest";
import { presentTunnelCheck, type TextSegment } from "../src/renderer/components/pages/connect/tunnel-check.js";
import type { ProxyProtocol, TunnelCheckResult } from "../src/shared/types.js";

const at = new Date(2026, 9, 6, 12, 4, 18).toISOString();
const timedOut: TunnelCheckResult = {
  endpoint: "youtube.com:443",
  ok: false,
  at,
  message: "The tunnel opened a connection to youtube.com:443 but nothing came back within 12s. Traffic is entering the tunnel and not reaching the server.",
  transport: "xray",
  targetName: "fi-hel-hy2"
};

const plain = (segments: TextSegment[]): string => segments.map((segment) => segment.text).join("");

// Hysteria 2 runs over QUIC: Xray says Connected even when UDP to the server is
// blocked, so a failed tunnel check is the only place to say so.
describe("tunnel check on a Hysteria 2 session", () => {
  const view = (activeProtocol: ProxyProtocol | undefined, result = timedOut) =>
    presentTunnelCheck({ result, endpoint: "youtube.com:443", activeTransport: "xray", connected: true, checking: false, activeName: "fi-hel-hy2", activeProtocol });

  it("adds a UDP step to failed checks", () => {
    const failed = view("hysteria2");
    expect(failed.kind).toBe("failed");
    expect(failed.steps?.map(plain)).toEqual([
      "Run the check again in a minute. The site may be briefly down.",
      "Hysteria 2 needs UDP to reach the server, and Xray shows Connected even when this network blocks it. Try a VLESS, VMess or Trojan profile to rule that out.",
      "If the link’s password (auth), pinSHA256 or obfs password is wrong, it fails the same way.",
      "Change the endpoint to a site you know is up, to rule out the site itself.",
      "Connect through another profile or an SSH server."
    ]);
    const refused = view("hysteria2", { ...timedOut, message: "Upstream SOCKS5 proxy refused youtube.com:443 with code 5" });
    expect(refused.steps?.map(plain)).toContain(
      "Hysteria 2 needs UDP to reach the server, and Xray shows Connected even when this network blocks it. Try a VLESS, VMess or Trojan profile to rule that out."
    );
  });

  it("says the service's UDP hint once, in the steps, not again in the headline", () => {
    // The service appends this to every failed Hysteria 2 check (see xray-service.ts).
    const hint =
      "Hysteria 2 runs over UDP (QUIC): the network may block UDP to the server or its ports, or the link’s password (auth), certificate pin (pinSHA256) or obfs password may be wrong.";
    const failed = view("hysteria2", { ...timedOut, message: `Tunnel check failed for youtube.com:443: Connection closed before the TLS handshake finished. ${hint}` });
    expect(plain(failed.text)).toBe("The check to youtube.com:443 failed: Connection closed before the TLS handshake finished.");
    expect(failed.steps?.map(plain).filter((step) => /UDP/u.test(step))).toHaveLength(1);
    expect(plain(view("hysteria2", { ...timedOut, message: `${timedOut.message} ${hint}` }).text)).toBe(
      "The tunnel opened a connection to youtube.com:443 but nothing came back within 12 s."
    );
    // Another protocol's message is shown as it came, whatever it says.
    expect(plain(view("vless", { ...timedOut, message: `Connection closed. ${hint}` }).text)).toContain(hint);
  });

  it("never promises a reason in the Activity log", () => {
    // Xray logs Hysteria 2 dial failures at [Info], below the app's "warning" level.
    for (const insecure of [false, true]) {
      const failed = presentTunnelCheck({
        result: { ...timedOut, message: "Upstream SOCKS5 proxy refused youtube.com:443 with code 5" },
        endpoint: "youtube.com:443",
        activeTransport: "xray",
        connected: true,
        checking: false,
        activeProtocol: "hysteria2",
        activeInsecureWithoutPin: insecure
      });
      const copy = [plain(failed.text), ...(failed.steps ?? []).map(plain)].join(" ");
      expect(copy).not.toMatch(/Activity log|reason/iu);
      expect(copy).toContain("password (auth)");
    }
  });

  it("names insecure=1 without a pin as the likeliest cause when the profile is marked", () => {
    const marked = presentTunnelCheck({
      result: timedOut,
      endpoint: "youtube.com:443",
      activeTransport: "xray",
      connected: true,
      checking: false,
      activeName: "fi-hel-hy2",
      activeProtocol: "hysteria2",
      activeInsecureWithoutPin: true
    });
    expect(marked.steps?.map(plain)).toEqual([
      "Run the check again in a minute. The site may be briefly down.",
      "This link asks to skip certificate checks (insecure=1), which the bundled Xray can’t do, so a server with a self-signed certificate fails this way. Add the server’s pinSHA256 to the link, add the link again and remove this profile.",
      "Hysteria 2 needs UDP to reach the server, and Xray shows Connected even when this network blocks it. Try a VLESS, VMess or Trojan profile to rule that out.",
      "If the link’s password (auth), pinSHA256 or obfs password is wrong, it fails the same way.",
      "Change the endpoint to a site you know is up, to rule out the site itself.",
      "Connect through another profile or an SSH server."
    ]);
    expect(view("hysteria2").steps?.map(plain).some((step) => /insecure=1/u.test(step))).toBe(false);
  });

  it("leaves other protocols and passed checks alone", () => {
    expect(view("vless").steps).toHaveLength(3);
    expect(view(undefined).steps).toHaveLength(3);
    expect(view("hysteria2", { ...timedOut, ok: true, message: "youtube.com:443 answered the TLS handshake.", latencyMs: 210 }).steps).toBeUndefined();
  });
});
