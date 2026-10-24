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
  if (isBindablePort(port)) {
    lastBoundLocalProxyPort = port;
  }
}

/** Test seam; also used when a listener is retired for good. */
export function forgetLocalProxyPort(): void {
  lastBoundLocalProxyPort = undefined;
}

/** The ports Xray's own SOCKS and HTTP inbounds last listened on. */
export interface XrayInboundPorts {
  socksPort: number;
  httpPort: number;
}

/**
 * Xray's own inbounds are what the app advertises as the local proxy on the
 * Xray transport, and what a client on macOS or Linux is pointed at by hand.
 * They were reserved afresh on every connect and every automatic restart, so
 * such a client lost the tunnel each time. The same rule as above applies:
 * the last pair is preferred for the lifetime of the process, and a port that
 * has been taken since falls back to an ephemeral one.
 */
let lastBoundXrayInboundPorts: XrayInboundPorts | undefined;

export function preferredXrayInboundPorts(): XrayInboundPorts | undefined {
  return lastBoundXrayInboundPorts ? { ...lastBoundXrayInboundPorts } : undefined;
}

export function rememberXrayInboundPorts(ports: XrayInboundPorts): void {
  if (isBindablePort(ports.socksPort) && isBindablePort(ports.httpPort) && ports.socksPort !== ports.httpPort) {
    lastBoundXrayInboundPorts = { socksPort: ports.socksPort, httpPort: ports.httpPort };
  }
}

/** Test seam; also used when the remembered pair could not be bound. */
export function forgetXrayInboundPorts(): void {
  lastBoundXrayInboundPorts = undefined;
}

function isBindablePort(port: number): boolean {
  return Number.isInteger(port) && port > 0 && port <= 65535;
}
