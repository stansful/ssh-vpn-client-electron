import type { ParsedProxyProfile } from "../../shared/types.js";
import { parseProxyShareLink } from "./share-link-parser.js";

/** Hysteria 2 panels append this to the #name; it isn't part of the name. */
const SERVER_DESCRIPTION = "?serverDescription=";

/** What a rename is meant to change; every other parsed field must survive it. */
const RENAMED_FIELDS: ReadonlySet<keyof ParsedProxyProfile> = new Set(["name", "rawUri", "fingerprint"]);

/**
 * Returns the share link with its display name replaced by `name`, which must
 * already be normalized: the #fragment for vless, trojan and Hysteria 2 (a
 * "?serverDescription=" tail is kept), "ps" in the base64 JSON for vmess. A
 * link that already carries the name comes back unchanged. Throws when the
 * link can't be read or the rewrite would change anything but the name.
 *
 * The fingerprint hashes the name, so a renamed link reads as another profile:
 * store the original and rewrite only on the way out.
 */
export function withShareLinkName(rawUri: string, name: string): string {
  if (!name.trim()) {
    throw new Error("Profile name is empty.");
  }
  const original = parseProxyShareLink(rawUri);
  if (original.name === name) {
    return rawUri;
  }
  const renamed = original.protocol === "vmess"
    ? withVmessName(rawUri, name)
    : withFragmentName(rawUri, name, original.protocol === "hysteria2");
  assertOnlyNameChanged(original, parseProxyShareLink(renamed), name);
  return renamed;
}

/** vless, trojan and Hysteria 2 all start the fragment at the first "#", as WHATWG URL does. */
function withFragmentName(rawUri: string, name: string, keepDescription: boolean): string {
  const hash = rawUri.indexOf("#");
  const head = hash >= 0 ? rawUri.slice(0, hash) : rawUri;
  const fragment = hash >= 0 ? rawUri.slice(hash + 1) : "";
  const description = keepDescription ? fragment.indexOf(SERVER_DESCRIPTION) : -1;
  const tail = description >= 0 ? fragment.slice(description) : "";
  return `${head}#${encodeURIComponent(name)}${tail}`;
}

/** Re-encodes the payload in the alphabet and padding the link used, keeping the key order. */
function withVmessName(rawUri: string, name: string): string {
  const scheme = /^vmess:\/\//iu.exec(rawUri)?.[0] ?? "vmess://";
  // Read the way the parser reads it: whitespace dropped, either alphabet, padding optional.
  const body = rawUri.slice(scheme.length).replace(/\s+/gu, "");
  const standard = body.replace(/-/gu, "+").replace(/_/gu, "/");
  // The parser has accepted this link, so the payload is a JSON object.
  const payload = JSON.parse(
    Buffer.from(standard.padEnd(Math.ceil(standard.length / 4) * 4, "="), "base64").toString("utf8")
  ) as Record<string, unknown>;

  // Spreading keeps "ps" where it was; a link without one gets it last.
  const encoded = Buffer.from(JSON.stringify({ ...payload, ps: name }), "utf8").toString("base64");
  const alphabet = /[-_]/u.test(body) ? encoded.replace(/\+/gu, "-").replace(/\//gu, "_") : encoded;
  // A body that needed no padding doesn't say whether its encoder pads; most do.
  const padded = body.includes("=") || body.length % 4 === 0;
  return `${scheme}${padded ? alphabet : alphabet.replace(/=+$/u, "")}`;
}

function assertOnlyNameChanged(original: ParsedProxyProfile, renamed: ParsedProxyProfile, name: string): void {
  const keys = new Set([...Object.keys(original), ...Object.keys(renamed)] as Array<keyof ParsedProxyProfile>);
  const changed = [...keys].filter((key) => !RENAMED_FIELDS.has(key) && original[key] !== renamed[key]);
  if (renamed.name !== name || changed.length > 0) {
    throw new Error(`Couldn’t write the name into the ${original.protocol} link.`);
  }
}
