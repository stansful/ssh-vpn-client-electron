/**
 * The port applications are pointed at for the local proxy listener.
 *
 * The listener is rebuilt on every connect, on every reconnect and on every
 * transport switch. Bound to an ephemeral port, each of those hands out a new
 * endpoint. Clients that follow the system proxy re-read it and recover, but
 * clients configured by hand - Telegram's SOCKS5 settings, a shell's
 * ALL_PROXY, a browser profile with a fixed proxy - keep dialling the port
 * that no longer exists, which the user experiences as "it stopped working
 * after I switched transports" rather than as a changed port.
 *
 * Remembering the last bound port keeps that endpoint stable for the lifetime
 * of the process, across both transports. It stays a preference, never a
 * requirement: if the port has been taken in the meantime the proxy falls back
 * to an ephemeral one, because a listener on an unexpected port is still far
 * better than no listener.
 */
let lastBoundLocalProxyPort: number | undefined;

export function preferredLocalProxyPort(): number | undefined {
  return lastBoundLocalProxyPort;
}

export function rememberLocalProxyPort(port: number): void {
  if (Number.isInteger(port) && port > 0 && port <= 65535) {
    lastBoundLocalProxyPort = port;
  }
}

/** Test seam; also used when a listener is retired for good. */
export function forgetLocalProxyPort(): void {
  lastBoundLocalProxyPort = undefined;
}
