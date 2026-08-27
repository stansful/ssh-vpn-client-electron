import { generateKeyPairSync, randomBytes } from "node:crypto";
import net from "node:net";
import type { DirectTcpIpChannel, DirectTcpIpTarget } from "./local-tcp-proxy.js";

/** What the far end proved about the tunnel. */
export type TunnelProbeOutcome = "tls" | "tls-alert" | "http" | "bytes" | "unverified";

export interface TunnelProbeResult {
  outcome: TunnelProbeOutcome;
  /** One clause describing the evidence, for the diagnostics line. */
  detail: string;
  /** How long the transport took to report the connection as open. */
  openMs: number;
  /** How long the far end took to answer, when it answered. */
  responseMs?: number;
}

export interface TunnelProbeOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
}

const DEFAULT_PROBE_TIMEOUT_MS = 12_000;
/** Enough for a ServerHello prefix or a status line; the rest is discarded. */
const MAX_PROBE_RESPONSE_BYTES = 1024;

/**
 * Verifies that a tunnel actually carries data to `target`, not merely that
 * something accepted the connection request.
 *
 * This distinction is the whole point. Xray's SOCKS inbound answers a CONNECT
 * as soon as it has picked an outbound, long before that outbound has reached
 * the server, so a check that stopped at the SOCKS reply reported a healthy
 * tunnel while every real connection through it hung. The symptom that reaches
 * the user is indistinguishable from broken routing - selected traffic dies,
 * unselected traffic works - so the check has to be able to tell them apart.
 *
 * Both transports share this so their checks cannot disagree about what
 * "connected" means.
 */
export async function probeTunnelEndpoint(
  openChannel: (signal: AbortSignal) => Promise<DirectTcpIpChannel>,
  target: DirectTcpIpTarget,
  options: TunnelProbeOptions = {}
): Promise<TunnelProbeResult> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS;
  const controller = new AbortController();
  const abortOuter = (): void => controller.abort();
  options.signal?.addEventListener("abort", abortOuter, { once: true });
  const deadline = setTimeout(abortOuter, timeoutMs);
  deadline.unref();

  const startedAt = Date.now();
  try {
    const channel = await openChannel(controller.signal);
    const openMs = Date.now() - startedAt;
    try {
      const probe = buildProbe(target);
      if (probe.request.length > 0) {
        await channel.write(probe.request);
      }
      const respondedAt = Date.now();
      const response = await readFirstResponse(channel, controller.signal);
      if (!response) {
        if (probe.kind === "silent") {
          return {
            outcome: "unverified",
            detail: `${describeTarget(target)} sent nothing, which port ${target.port} is not expected to; the tunnel opened the connection but could not be verified end to end`,
            openMs
          };
        }
        throw new Error(
          `The tunnel opened a connection to ${describeTarget(target)} but nothing came back within ${Math.round(timeoutMs / 1000)}s. Traffic is entering the tunnel and not reaching the server.`
        );
      }
      return {
        ...classifyResponse(response, probe.kind, target),
        openMs,
        responseMs: Date.now() - respondedAt
      };
    } finally {
      await channel.close().catch(() => undefined);
    }
  } finally {
    clearTimeout(deadline);
    options.signal?.removeEventListener("abort", abortOuter);
  }
}

interface Probe {
  kind: "tls" | "http" | "silent";
  request: Buffer;
}

function buildProbe(target: DirectTcpIpTarget): Probe {
  if (isTlsPort(target.port)) {
    return { kind: "tls", request: buildTlsClientHello(target.host) };
  }
  if (isHttpPort(target.port)) {
    return { kind: "http", request: buildHttpHeadRequest(target.host) };
  }
  // An unknown port gets no payload: many services greet first, and sending a
  // guessed protocol to one that does not would produce a confusing failure
  // that says nothing about the tunnel.
  return { kind: "silent", request: Buffer.alloc(0) };
}

function isTlsPort(port: number): boolean {
  return port === 443 || port === 8443 || port === 993 || port === 995;
}

function isHttpPort(port: number): boolean {
  return port === 80 || port === 8080 || port === 8000;
}

function classifyResponse(
  response: Buffer,
  kind: Probe["kind"],
  target: DirectTcpIpTarget
): { outcome: TunnelProbeOutcome; detail: string } {
  const where = describeTarget(target);
  if (response.length >= 2 && response[1] === 0x03) {
    if (response[0] === 0x16) {
      return { outcome: "tls", detail: `${where} answered the TLS handshake` };
    }
    if (response[0] === 0x15) {
      // Still proof: an alert only exists because the ClientHello arrived.
      return { outcome: "tls-alert", detail: `${where} answered with a TLS alert, so the tunnel carries data but the endpoint refused the probe handshake` };
    }
  }
  if (response.subarray(0, 5).toString("latin1") === "HTTP/") {
    const statusLine = response.toString("latin1").split("\r\n", 1)[0];
    return { outcome: "http", detail: `${where} answered ${statusLine.trim()}` };
  }
  if (kind === "tls") {
    // Worth naming rather than passing silently: something on the path is
    // answering in place of the endpoint.
    return {
      outcome: "bytes",
      detail: `${where} answered ${response.length} bytes that are not a TLS record, so the tunnel carries data but something other than the endpoint may be answering`
    };
  }
  return { outcome: "bytes", detail: `${where} answered ${response.length} bytes` };
}

function describeTarget(target: DirectTcpIpTarget): string {
  return `${target.host}:${target.port}`;
}

/** Resolves with the first bytes the far end sends, or undefined if it sends none. */
function readFirstResponse(channel: DirectTcpIpChannel, signal: AbortSignal): Promise<Buffer | undefined> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const unsubscribe: Array<() => void> = [];
    const finish = (error?: Error, data?: Buffer): void => {
      if (settled) {
        return;
      }
      settled = true;
      signal.removeEventListener("abort", onAbort);
      for (const off of unsubscribe) {
        off();
      }
      if (error) {
        reject(error);
      } else {
        resolve(data);
      }
    };
    const onAbort = (): void => finish(undefined, undefined);

    unsubscribe.push(channel.onData((data) => finish(undefined, data.subarray(0, MAX_PROBE_RESPONSE_BYTES))));
    unsubscribe.push(channel.onEnd(() => finish(undefined, undefined)));
    unsubscribe.push(channel.onClose(() => finish(undefined, undefined)));
    unsubscribe.push(channel.onError((error) => finish(error)));
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
    }
  });
}

function buildHttpHeadRequest(host: string): Buffer {
  return Buffer.from(
    `HEAD / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: shadow-ssh-tunnel-check\r\nAccept: */*\r\nConnection: close\r\n\r\n`,
    "utf8"
  );
}

/**
 * A minimal but ordinary TLS 1.2/1.3 ClientHello.
 *
 * Anything the server sends in reply - a ServerHello, a HelloRetryRequest, or
 * even an alert - proves bytes crossed the tunnel in both directions, which is
 * all this check needs to establish. It is written by hand rather than handed
 * to `tls.connect` because the tunnel gives us a channel abstraction, not a
 * socket, and both transports have to be probed the same way.
 */
export function buildTlsClientHello(serverName: string): Buffer {
  const cipherSuites = Buffer.from([
    0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
    0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
    0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35
  ]);
  const extensions: Buffer[] = [];
  const host = serverName.trim().replace(/^\[|\]$/gu, "");
  // SNI must carry a host name; an address literal is not a legal value.
  if (host && !net.isIP(host)) {
    const encodedHost = Buffer.from(host, "utf8");
    extensions.push(
      buildExtension(
        0x0000,
        Buffer.concat([uint16(encodedHost.length + 3), Buffer.from([0x00]), uint16(encodedHost.length), encodedHost])
      )
    );
  }
  extensions.push(buildExtension(0x000b, Buffer.from([0x01, 0x00])));
  extensions.push(buildExtension(0x000a, Buffer.from([0x00, 0x04, 0x00, 0x1d, 0x00, 0x17])));
  extensions.push(
    buildExtension(
      0x000d,
      Buffer.from([0x00, 0x0c, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01])
    )
  );
  extensions.push(buildExtension(0x002b, Buffer.from([0x04, 0x03, 0x04, 0x03, 0x03])));
  // A TLS 1.3 server that is offered no key share has nothing to negotiate
  // with and answers `handshake_failure` instead of a ServerHello. That still
  // proves the tunnel, but it reads like a broken endpoint, so the hello
  // carries a throwaway X25519 share and gets a real handshake back.
  extensions.push(buildExtension(0x0033, buildX25519KeyShare()));
  extensions.push(buildExtension(0x0017, Buffer.alloc(0)));
  extensions.push(buildExtension(0xff01, Buffer.from([0x00])));

  const extensionsBody = Buffer.concat(extensions);
  const sessionId = randomBytes(32);
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    randomBytes(32),
    Buffer.from([sessionId.length]),
    sessionId,
    uint16(cipherSuites.length),
    cipherSuites,
    Buffer.from([0x01, 0x00]),
    uint16(extensionsBody.length),
    extensionsBody
  ]);
  const handshake = Buffer.concat([Buffer.from([0x01]), uint24(body.length), body]);
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), uint16(handshake.length), handshake]);
}

/** One client key share for x25519, discarded as soon as the probe answers. */
function buildX25519KeyShare(): Buffer {
  const spki = generateKeyPairSync("x25519").publicKey.export({ format: "der", type: "spki" });
  const key = spki.subarray(spki.length - 32);
  const entry = Buffer.concat([uint16(0x001d), uint16(key.length), key]);
  return Buffer.concat([uint16(entry.length), entry]);
}

function buildExtension(type: number, body: Buffer): Buffer {
  return Buffer.concat([uint16(type), uint16(body.length), body]);
}

function uint16(value: number): Buffer {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value);
  return buffer;
}

function uint24(value: number): Buffer {
  return Buffer.from([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
}
