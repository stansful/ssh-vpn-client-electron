import type { ProxyProtocol } from "./types.js";

// One place for how each Xray profile protocol is named, so the tray, the
// service's status lines and the renderer can't drift apart. Both maps are
// Records: adding a protocol to ProxyProtocol fails to compile until it has a
// label and a mark here.

const PROTOCOL_LABELS: Record<ProxyProtocol, string> = {
  vless: "VLESS",
  vmess: "VMess",
  trojan: "Trojan",
  hysteria2: "Hysteria 2"
};

/** Two-letter avatar marks. "HY", not "H2": h2 already means HTTP/2 in transport names. */
const PROTOCOL_MARKS: Record<ProxyProtocol, string> = {
  vless: "VL",
  vmess: "VM",
  trojan: "TR",
  hysteria2: "HY"
};

/**
 * Short mark for a Hysteria 2 profile with `insecureWithoutPin` (the link asks
 * to skip certificate checks without a pinSHA256), shared by the tray and the
 * renderer so the mark reads the same everywhere.
 */
export const HYSTERIA2_INSECURE_TAG = "insecure=1";

/** "VLESS", "VMess", "Trojan", "Hysteria 2". */
export function proxyProtocolLabel(protocol: ProxyProtocol): string {
  return PROTOCOL_LABELS[protocol] ?? String(protocol).toUpperCase();
}

/** "VL", "VM", "TR", "HY". */
export function proxyProtocolMark(protocol: ProxyProtocol): string {
  return PROTOCOL_MARKS[protocol] ?? String(protocol).slice(0, 2).toUpperCase();
}
