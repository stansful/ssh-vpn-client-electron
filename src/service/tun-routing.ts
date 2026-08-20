import { lookup } from "node:dns/promises";
import net from "node:net";

/** The adapter's name in Windows network settings. */
export const TUN_ADAPTER_NAME = "Shadow SSH";

/**
 * Where the helper records the routing changes it made.
 *
 * It lives beside the PAC files in the app's own data directory rather than
 * next to the executable: a portable build can sit on read-only media, and a
 * journal that cannot be written is a crash that cannot be undone.
 */
export const TUN_ROUTING_JOURNAL_FILE = "tun-routing-journal.json";

/**
 * Bounds how many addresses a hostname may contribute. A host route is added
 * per address, so a pathological DNS answer must not rewrite the routing table
 * at length.
 */
const MAX_PROTECTED_ADDRESSES = 8;

/**
 * Resolves the addresses that must stay off the tunnel adapter.
 *
 * These are the transport's own server: routing it into the tunnel it carries
 * would deadlock the transport. Every address the name resolves to is
 * excluded, not just the one in use, because a reconnect may pick a different
 * record while the adapter is still up.
 *
 * A failure here is not fatal and yields an empty list: the caller then still
 * has the option of running without IPv6 capture, or of falling back to the
 * proxy path, rather than refusing to connect at all.
 */
export async function resolveProtectedAddresses(host: string): Promise<string[]> {
  const trimmed = host.trim();
  if (!trimmed) {
    return [];
  }
  if (net.isIP(trimmed) !== 0) {
    return [trimmed];
  }
  try {
    const answers = await lookup(trimmed, { all: true, verbatim: true });
    const addresses: string[] = [];
    for (const answer of answers) {
      if (!addresses.includes(answer.address)) {
        addresses.push(answer.address);
      }
      if (addresses.length >= MAX_PROTECTED_ADDRESSES) {
        break;
      }
    }
    return addresses;
  } catch {
    return [];
  }
}
