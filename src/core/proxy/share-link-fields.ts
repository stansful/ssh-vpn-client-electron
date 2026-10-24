/**
 * Field readers for vless://, trojan:// and vmess:// links, shared by the
 * share-link parser, the Xray config builder and the renderer's link preview.
 * Pure, so the preview reads a link exactly as the main process does.
 */

/** A VMess JSON field as text; panels write numbers and booleans as often as strings. */
export function vmessText(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value;
  }
  return typeof value === "number" || typeof value === "boolean" ? String(value) : undefined;
}

/**
 * The `security` of a vless:// or trojan:// link, as text: the parameter when
 * the link has one, else the legacy `tls=1`. A trojan:// link with neither is
 * TLS: the trojan-gfw scheme has no such parameter because Trojan always runs
 * over TLS, and the common clients read it so. Read as "none", it reached a
 * TLS server as plaintext and never connected.
 */
export function uriSecurityText(protocol: string, params: URLSearchParams): string {
  const security = params.get("security");
  if (security !== null) {
    return security;
  }
  const tls = params.get("tls");
  if (tls !== null) {
    return tls === "1" ? "tls" : "none";
  }
  return protocol === "trojan" ? "tls" : "none";
}

/** VMess `tls`: "tls", "reality", "" or "none", and from some panels `true` or `false`. */
export function vmessSecurityText(value: unknown): string {
  if (value === true) {
    return "tls";
  }
  if (value === false || value === null || value === undefined) {
    return "none";
  }
  return typeof value === "string" ? value : String(value);
}

/**
 * Lower case, IPv6 without brackets. This is the form profile fingerprints
 * have always hashed, so it must not change: a different canonical host would
 * make every re-imported link look new and duplicate the profile.
 */
export function canonicalShareLinkHost(value: string): string {
  return value.trim().replace(/^\[/u, "").replace(/\]$/u, "").toLowerCase();
}

/**
 * The address Xray dials: {@link canonicalShareLinkHost}, with an
 * internationalised name in its punycode (ASCII) form.
 *
 * vless:// and trojan:// are not special URL schemes, so WHATWG URL keeps a
 * non-ASCII host percent-encoded (`пример.рф` becomes `%D0%BF…`), which no
 * resolver accepts; a vmess:// payload carries the name as raw Unicode. Read
 * under https:// instead, the host goes through the URL standard's IDNA
 * processing, the same conversion hysteria2-link relies on, and it works alike
 * in Node and in the renderer. ASCII hosts are returned unchanged.
 *
 * Undefined for a host that is not a usable name.
 */
export function shareLinkHostToAscii(value: string): string | undefined {
  const host = canonicalShareLinkHost(value);
  if (!/[\u{80}-\u{10ffff}]|%/u.test(host)) {
    return host;
  }
  // Anything that would end the authority belongs to no host name.
  if (/[\s/?#@:\\[\]]/u.test(host)) {
    return undefined;
  }
  try {
    const ascii = new URL(`https://${host}/`).hostname.toLowerCase();
    return ascii && /^[\x21-\x7e]+$/u.test(ascii) && !ascii.includes("%") ? ascii : undefined;
  } catch {
    return undefined;
  }
}
