/**
 * What of a service diagnostic goes into main.log, which outlives the session
 * on disk (5 MiB × 3 files). Activity keeps every line in memory; the file
 * leaves out per-connection traffic - which site each app opened, through the
 * tunnel or not - and the SSH account name, so it doesn't become a browsing
 * history. A connection that failed is still worth a line there, so its line
 * is kept with the site and the app taken out. Returns undefined for a line
 * that stays out of the file.
 */
export function persistentDiagnosticMessage(message: string): string | undefined {
  if (isHighVolumeProxyDiagnostic(message) || isConnectionRoutingDiagnostic(message) || isXrayAccessLine(message)) {
    return undefined;
  }
  return withoutAccountNames(withoutConnectionTargets(message));
}

/** Per-connection lines of the local proxies. */
export function isHighVolumeProxyDiagnostic(message: string): boolean {
  return (
    /^(HTTP CONNECT|HTTP proxy|SOCKS5 CONNECT|SOCKS4 CONNECT) .+ from \S+:\d+\.$/u.test(message) ||
    /^(HTTP CONNECT|HTTP proxy|SOCKS5 CONNECT|SOCKS4 CONNECT) tunnel opened for .+\.$/u.test(message) ||
    /^(HTTP proxy|SOCKS5|SOCKS\/HTTP proxy) socket closed during handshake\.$/u.test(message) ||
    /^(read ECONNRESET|write after end)$/u.test(message) ||
    /^Further proxy (connection diagnostics|warnings) are suppressed for this session\.$/u.test(message)
  );
}

/**
 * RoutingDecisionLog lines (src/service/local-routing-enforcement.ts):
 * "Tunnel egress for host:port from app.exe (reason)." and the notes that
 * further ones are suppressed.
 */
export function isConnectionRoutingDiagnostic(message: string): boolean {
  return (
    /^(Tunnel|Direct) egress for \S+ .*\(.+\)\.$/u.test(message) ||
    /^Further (tunnelled|direct) routing decisions are suppressed for up to \d+s\.$/u.test(message)
  );
}

/**
 * Xray's access log, which it writes to stdout whatever the log level: one
 * "from 127.0.0.1:53210 accepted tcp:www.example.com:443 [socks-in >> proxy]"
 * line per connection, forwarded as "Xray: …".
 */
function isXrayAccessLine(message: string): boolean {
  return /^Xray: .*\bfrom \S+ (?:accepted|rejected) (?:tcp|udp):/u.test(message);
}

const DESTINATION_PLACEHOLDER = "<destination>";

/**
 * Takes the destination, and the app that opened it, out of a line about one
 * connection: a local proxy's "SOCKS5 CONNECT tunnel failed for host:port: …",
 * the TUN helper's "TUN tcp app.exe -> 192.0.2.1:443 (site) (…) failed: …"
 * and its UDP lines, and the "tcp:host:port" Xray names a connection by. The
 * destination is taken out of the rest of the line too, where an error repeats
 * it.
 */
function withoutConnectionTargets(message: string): string {
  const proxy = /^((?:SOCKS5 CONNECT|SOCKS4 CONNECT|HTTP CONNECT|HTTP proxy) tunnel failed for )(.+?):(\d+): (.*)$/su.exec(message);
  if (proxy) {
    const [, lead, host, port, rest] = proxy;
    return `${lead}${DESTINATION_PLACEHOLDER}: ${withoutValues(rest, [`${host}:${port}`, host])}`;
  }
  const tun = /^((?:dataplane (?:error|warning|warn|info): )?TUN (?:tcp|udp) ).+? -> (\[[^\]]+\]:\d+|[\d.]+:\d+)(?: \(([^()\s/]+)\))?(.*)$/su.exec(message);
  if (tun) {
    const [, lead, target, name, rest] = tun;
    const address = target.replace(/:\d+$/u, "").replace(/^\[(.*)\]$/u, "$1");
    return `${lead}<app> -> ${DESTINATION_PLACEHOLDER}${withoutValues(rest, [target, name, address])}`;
  }
  if (message.startsWith("Xray: ")) {
    return message.replace(/\b(tcp|udp):(?:\[[^\]\s]+\]|[^\s:[\]>]+):\d+/gu, `$1:${DESTINATION_PLACEHOLDER}`);
  }
  return message;
}

function withoutValues(text: string, values: ReadonlyArray<string | undefined>): string {
  let result = text;
  for (const value of values) {
    if (value) {
      result = result.split(value).join(DESTINATION_PLACEHOLDER);
    }
  }
  return result;
}

/** "… for root@203.0.113.10:22 …" becomes "… for 203.0.113.10:22 …": the server stays, the account name goes. */
export function withoutAccountNames(message: string): string {
  return message.replace(/(\bfor )[^\s@]+@(?=\S+:\d+)/gu, "$1");
}
