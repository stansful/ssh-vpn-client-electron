import { describe, expect, it } from "vitest";
import { formatProxyTunnelError } from "../src/core/network/socks5-proxy.js";
import { describeRoutingDecision, RoutingDecisionLog } from "../src/service/local-routing-enforcement.js";
import { persistentDiagnosticMessage, withoutAccountNames } from "../src/main/app/persistent-log.js";

describe("what main.log keeps of service diagnostics", () => {
  it("keeps per-connection routing decisions out of the file", () => {
    const lines = [
      describeRoutingDecision({ host: "news.example", port: 443 }, { shouldProxy: true, processName: "chrome.exe", reason: "process.name" }),
      describeRoutingDecision({ host: "203.0.113.7", port: 8443 }, { shouldProxy: false, reason: "direct-list" }),
      describeRoutingDecision({ host: "2001:db8::1", port: 443 }, { shouldProxy: false, reason: "no-match" })
    ];
    for (const line of lines) {
      expect(persistentDiagnosticMessage(line), line).toBeUndefined();
    }
  });

  it("keeps the decision log's own suppression notes out too", () => {
    const emitted: string[] = [];
    const log = new RoutingDecisionLog((message) => emitted.push(message), { limit: 2, now: () => 0 });
    log.record({ host: "a.example", port: 443 }, { shouldProxy: true, reason: "proxy-all" });
    log.record({ host: "b.example", port: 443 }, { shouldProxy: true, reason: "proxy-all" });
    log.record({ host: "c.example", port: 443 }, { shouldProxy: false, reason: "no-match" });
    expect(emitted).toHaveLength(3);
    expect(emitted[1]).toMatch(/^Further tunnelled routing decisions are suppressed/u);
    for (const line of emitted) {
      expect(persistentDiagnosticMessage(line), line).toBeUndefined();
    }
  });

  it("still drops the proxies' per-connection lines", () => {
    expect(persistentDiagnosticMessage("SOCKS5 CONNECT example.com:443 from 127.0.0.1:53000.")).toBeUndefined();
    expect(persistentDiagnosticMessage("HTTP CONNECT tunnel opened for example.com:443.")).toBeUndefined();
    expect(persistentDiagnosticMessage("SOCKS4 CONNECT example.com:443 from 127.0.0.1:53001.")).toBeUndefined();
    expect(persistentDiagnosticMessage("Further proxy warnings are suppressed for this session.")).toBeUndefined();
  });

  it("keeps Xray's access log out of the file", () => {
    // Xray writes it to stdout at every log level; the bridge forwards each
    // line as "Xray: …".
    for (const line of [
      "Xray: 2026/10/21 04:35:28.663946 from tcp:127.0.0.1:59012 accepted tcp:www.example.com:443 [socks-in >> proxy]",
      "Xray: 2026/10/21 04:35:29 from 127.0.0.1:53210 accepted udp:[2001:db8::1]:443 [socks-in -> direct]",
      "Xray: 2026/10/21 04:35:30 from 127.0.0.1:53211 rejected tcp:blocked.example:443 [http-in >> proxy]"
    ]) {
      expect(persistentDiagnosticMessage(line), line).toBeUndefined();
    }
    // Its warnings stay, with the connection they name taken out.
    expect(
      persistentDiagnosticMessage("Xray: 2026/10/21 04:36:01 [Warning] [3141592] proxy/freedom: failed to open connection to tcp:nas.example.org:445 > dial tcp 10.0.0.5:445: i/o timeout")
    ).toBe("Xray: 2026/10/21 04:36:01 [Warning] [3141592] proxy/freedom: failed to open connection to tcp:<destination> > dial tcp 10.0.0.5:445: i/o timeout");
  });

  it("keeps a failed connection's line without the site or the app", () => {
    const socks = formatProxyTunnelError(
      { protocol: "socks5", target: { host: "www.example.com", port: 443 } },
      "SSH channel open to www.example.com:443 was refused."
    );
    expect(persistentDiagnosticMessage(socks)).toBe("SOCKS5 CONNECT tunnel failed for <destination>: SSH channel open to <destination> was refused.");
    const http = formatProxyTunnelError({ protocol: "http-connect", target: { host: "2001:db8::7", port: 8443 } }, "Timed out waiting for SSH channel 41.");
    expect(persistentDiagnosticMessage(http)).toBe("HTTP CONNECT tunnel failed for <destination>: Timed out waiting for SSH channel 41.");

    // The TUN helper's lines, as its stderr carries them and as an event does.
    expect(
      persistentDiagnosticMessage("dataplane warning: TUN tcp chrome.exe -> 93.184.216.34:443 (www.example.com) (proxy/proxy-all) failed: dial 93.184.216.34:443 for www.example.com: connection refused")
    ).toBe("dataplane warning: TUN tcp <app> -> <destination> (proxy/proxy-all) failed: dial <destination> for <destination>: connection refused");
    expect(persistentDiagnosticMessage("dataplane warning: TUN tcp (unattributed) -> 203.0.113.9:443 (proxy/proxy-all) failed: dial 203.0.113.9:443: timeout")).toBe(
      "dataplane warning: TUN tcp <app> -> <destination> (proxy/proxy-all) failed: dial <destination>: timeout"
    );
    expect(persistentDiagnosticMessage("TUN udp My App.exe -> [2001:db8::1]:443 tunnel failed: no udp")).toBe(
      "TUN udp <app> -> <destination> tunnel failed: no udp"
    );
    expect(
      persistentDiagnosticMessage("dataplane warning: TUN udp (unattributed) -> 192.0.2.1:3478: 8 datagrams over 2s through the tunnel and no reply; the tunnel's server may not pass UDP there, or the destination does not answer.")
    ).toBe("dataplane warning: TUN udp <app> -> <destination>: 8 datagrams over 2s through the tunnel and no reply; the tunnel's server may not pass UDP there, or the destination does not answer.");
  });

  it("writes session lines without the SSH account name", () => {
    expect(
      persistentDiagnosticMessage(
        "Connect requested for root@203.0.113.10:22, auth=password, routing=proxy-all, privateKey=false, passphraseProvided=false."
      )
    ).toBe("Connect requested for 203.0.113.10:22, auth=password, routing=proxy-all, privateKey=false, passphraseProvided=false.");
    expect(persistentDiagnosticMessage("Reconnect attempt 2 (watchdog) for deploy@vps.example.net:2222, auth=private-key.")).toBe(
      "Reconnect attempt 2 (watchdog) for vps.example.net:2222, auth=private-key."
    );
    expect(withoutAccountNames("SSH session established for admin@2001:db8::5:22 (2001:db8::5).")).toBe(
      "SSH session established for 2001:db8::5:22 (2001:db8::5)."
    );
  });

  it("leaves every other line as it is", () => {
    for (const line of [
      "SSH session lost: read ECONNRESET.",
      "Local HTTP/SOCKS proxy is listening on 127.0.0.1:1080.",
      "Mail sent to ops@example.com.",
      "TUN routing could not start: wintun.dll wasn't found."
    ]) {
      expect(persistentDiagnosticMessage(line)).toBe(line);
    }
  });
});
