import { lookup } from "node:dns/promises";
import net from "node:net";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { DataplaneStartRequest } from "./local-ipc-protocol.js";

/** The adapter's name in Windows network settings. */
export const TUN_ADAPTER_NAME = "Shadow SSH";

/**
 * Where the native helper is told to look for `wintun.dll`, beyond its own
 * directory.
 *
 * The portable build unpacks itself into a fresh `%TEMP%\<random>` folder on
 * every launch and deletes it on exit. That folder is where the DLL loader
 * looks first - and it is a folder no user can put a file into, because it does
 * not exist until the app starts and is gone before they can open it. A
 * portable build that shipped without the DLL therefore had no way at all to
 * gain one, which is exactly how this looked in the field: the diagnostic named
 * a directory that could not be reached.
 *
 * So the helper is also pointed at the folders a person can actually use.
 */
export const WINTUN_SEARCH_DIRECTORIES_ENV = "SHADOW_SSH_WINTUN_DIRS";

export function wintunSearchDirectories(userDataDirectory?: string): string[] {
  const directories: string[] = [];
  const add = (directory: string | undefined): void => {
    const trimmed = directory?.trim();
    if (trimmed && !directories.includes(trimmed)) {
      directories.push(trimmed);
    }
  };

  // electron-builder's portable target sets this to the folder holding the
  // executable the user actually double-clicked - the one place they would
  // naturally drop the file.
  add(process.env.PORTABLE_EXECUTABLE_DIR);
  add(path.dirname(process.execPath));
  add(userDataDirectory);
  return directories;
}

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


/**
 * How many times a start is attempted before the connection falls back.
 *
 * Bringing the adapter up straight after taking it down is the normal case -
 * a user toggling the tunnel off and on - and it is exactly when Windows has
 * not finished removing the previous adapter or its routes. One attempt turned
 * that race into "the tunnel is unavailable" for the rest of the session, with
 * the app quietly back on the proxy path where process rules do not hold.
 *
 * Kept low because the helper already retries adapter creation itself: this
 * layer only covers a failure further along, and a connect that is going to
 * fall back should not spend half a minute deciding to.
 */
export const TUN_START_ATTEMPTS = 2;
/** Spacing between attempts. Windows needs a moment, not a long one. */
export const TUN_START_RETRY_DELAY_MS = 1_500;

export interface DataplaneStarter {
  start(request: DataplaneStartRequest): Promise<void>;
}

export interface TunStartRetryOptions {
  attempts?: number;
  delayMs?: number;
  /** Reports each failed attempt that will be retried. */
  onRetry?: (attempt: number, attempts: number, error: unknown) => void;
  /** Injection seam for tests. */
  sleep?: (milliseconds: number) => Promise<void>;
}

/**
 * Starts the dataplane, retrying a transient failure a few times.
 *
 * The last error is rethrown, so the caller still reports why it gave up.
 */
export async function startDataplaneWithRetry(
  dataplane: DataplaneStarter,
  request: DataplaneStartRequest,
  options: TunStartRetryOptions = {}
): Promise<void> {
  const attempts = Math.max(1, options.attempts ?? TUN_START_ATTEMPTS);
  const delayMs = options.delayMs ?? TUN_START_RETRY_DELAY_MS;
  const sleep = options.sleep ?? ((milliseconds: number) => delay(milliseconds));

  for (let attempt = 1; ; attempt += 1) {
    try {
      await dataplane.start(request);
      return;
    } catch (error) {
      if (attempt >= attempts) {
        throw error;
      }
      options.onRetry?.(attempt, attempts, error);
      await sleep(delayMs);
    }
  }
}

/** Renders an unknown thrown value for a diagnostic line. */
export function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
