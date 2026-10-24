import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { createServer, type RequestListener, type Server } from "node:http";
import { mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import type { RoutingMode, RoutingRule } from "../../shared/types.js";
import { normalizeRuleValue, validateRoutingRuleValue } from "../../shared/validation.js";
import { normalizeProxyDomain } from "../routing/domain-proxy-list.js";
import { LEARNED_PROCESS_IP_RULE_PREFIX } from "../routing/process-route-domains.js";
import { isLocalDestinationHost, overlapsLocalDestinationRange, parseCidrRange } from "../routing/ip-address.js";

export interface SystemProxyApplyRequest {
  mode: RoutingMode;
  rules: RoutingRule[];
  proxyDomains?: string[];
  directDomains?: string[];
  socksHost: string;
  socksPort: number;
  proxyProtocol?: "mixed" | "http" | "socks";
  forcePacEndpointRotation?: boolean;
}

export interface SystemProxyApplyResult {
  applied: boolean;
  message: string;
}

export interface WindowsSystemProxyOptions {
  pacDirectory?: string;
  pacServerFactory?: (requestListener: RequestListener) => Server;
  /**
   * Receives notices that have no other way out, such as a recovery journal
   * set aside during restore(). apply() reports the same notices in its result
   * message instead, and so does the next apply when this is not set.
   */
  onDiagnostic?: (message: string) => void;
}

/**
 * Restores proxy settings left behind by a previous run.
 *
 * A journal that cannot be read is set aside (renamed next to itself) rather
 * than left to block every later apply. When that leaves nothing to restore,
 * Shadow's own leftovers are removed from the registry instead; if there were
 * none either, this throws with the notice so the caller's failure path
 * reports it once. Otherwise the notice goes to `onDiagnostic`.
 */
export async function recoverWindowsSystemProxy(
  pacDirectories: string[],
  options: { onDiagnostic?: (message: string) => void } = {}
): Promise<boolean> {
  if (process.platform !== "win32") {
    return false;
  }
  const setAside: string[] = [];
  const candidates = (
    await Promise.all(
      [...new Set(pacDirectories)].map(async (directory) => {
        const snapshot = await readUsableProxySnapshot(directory, (message) => setAside.push(message));
        if (!snapshot) {
          return undefined;
        }
        const info = await stat(snapshotPath(directory)).catch(() => undefined);
        return { directory, modifiedAt: info?.mtimeMs ?? Number.MAX_SAFE_INTEGER };
      })
    )
  )
    .filter((candidate): candidate is { directory: string; modifiedAt: number } => Boolean(candidate))
    .sort((left, right) => left.modifiedAt - right.modifiedAt);
  const original = candidates[0];
  if (!original) {
    if (setAside.length > 0) {
      // What the journal held is lost, but whatever Shadow itself left in the
      // registry is recognisable, and leaving it would keep Windows pointing
      // at a proxy that is gone - and the next connect would save it as the
      // user's own setting, to be put back at every disconnect.
      if (await clearAppOwnedProxyValues()) {
        for (const message of setAside) {
          options.onDiagnostic?.(message);
        }
        options.onDiagnostic?.("Shadow's own leftover proxy settings were removed from the Windows registry.");
        return true;
      }
      throw new Error(setAside.join(" "));
    }
    return false;
  }

  // If a transport switch crashed after an earlier restore failed, a later
  // journal may describe an already-modified localhost proxy. Invalidate newer
  // journals before restoring the original state: if cleanup itself fails, the
  // oldest journal remains intact for a safe retry on the next startup.
  for (const candidate of candidates.slice(1)) {
    await rm(snapshotPath(candidate.directory), { force: true });
    await rm(path.join(candidate.directory, "shadow-ssh-routing.pac"), { force: true });
  }
  await new WindowsSystemProxyManager({ pacDirectory: original.directory, onDiagnostic: options.onDiagnostic }).restore();
  for (const message of setAside) {
    options.onDiagnostic?.(message);
  }
  return true;
}

/**
 * Puts back, at once and without yielding, the proxy settings a journal holds:
 * for the moment Windows ends the session, after which the process may be
 * ended at any instant and the asynchronous path would be cut off with the
 * registry still pointing at a listener about to die. The journals are read as
 * startup recovery reads them - the oldest describes the user's settings - and
 * the registry is written with reg.exe. WinINet is not told to reload; nothing
 * that reads it outlives the session. The journals and PAC files are left in
 * place: this runs outside the manager's queue, so an apply already under way
 * can still write Shadow's values after it, and the journal is what lets
 * startup recovery put the user's settings back then. The queued restore of
 * the quit that follows removes them, as it always does. Returns whether the
 * settings were restored; never throws.
 */
export function restoreWindowsSystemProxyNow(pacDirectories: string[]): boolean {
  if (process.platform !== "win32") {
    return false;
  }
  const candidates: Array<{ directory: string; snapshot: ProxySnapshot; modifiedAt: number }> = [];
  for (const directory of new Set(pacDirectories)) {
    try {
      const info = statSync(snapshotPath(directory));
      if (info.size > MAX_PROXY_SNAPSHOT_BYTES) {
        continue;
      }
      candidates.push({ directory, snapshot: parseProxySnapshotText(readFileSync(snapshotPath(directory), "utf8")), modifiedAt: info.mtimeMs });
    } catch {
      // No journal, or one startup recovery will set aside.
    }
  }
  const original = candidates.sort((left, right) => left.modifiedAt - right.modifiedAt)[0];
  if (!original) {
    return false;
  }
  const { snapshot } = original;
  const restored = [
    restoreValueNow("ProxyEnable", snapshot.proxyEnable, "REG_DWORD"),
    restoreValueNow("ProxyServer", snapshot.proxyServer, snapshotStringType(snapshot, "proxyServer")),
    restoreValueNow("ProxyOverride", snapshot.proxyOverride, snapshotStringType(snapshot, "proxyOverride")),
    restoreValueNow("AutoConfigURL", snapshot.autoConfigUrl, snapshotStringType(snapshot, "autoConfigUrl")),
    restoreValueNow("AutoDetect", snapshot.autoDetect, "REG_DWORD")
  ].every(Boolean);
  return restored;
}

/**
 * Gives the proxy back for a quit that could not wait for the transports.
 * The quit gave up on a transport change still under way, which can end in
 * an apply that writes Shadow's values after this - it runs outside the
 * manager's queue - so, as at the end of the session
 * (restoreWindowsSystemProxyNow), the journals and PAC files are left in
 * place: with them, startup recovery puts the user's settings back if that
 * happens. Removing them, as a full restore does, left nothing that could.
 * Unlike the end of the session the user's session goes on, so WinINet is
 * told to reload. With no journal to read, what can only be Shadow's is
 * removed from the registry instead. Returns whether anything was put back.
 */
export async function restoreWindowsSystemProxyBeforeQuit(pacDirectories: string[]): Promise<boolean> {
  if (process.platform !== "win32") {
    return false;
  }
  if (restoreWindowsSystemProxyNow(pacDirectories)) {
    await refreshWindowsProxy();
    return true;
  }
  return clearAppOwnedProxyValues();
}

/**
 * Removes from the live registry what can only be Shadow's: its PAC URL, and
 * a loopback static proxy that sits beside the bypass entries Shadow writes.
 * For when the journal that described the user's own settings is unusable;
 * a user's own local proxy - Fiddler, say - has no such entries and is kept.
 */
async function clearAppOwnedProxyValues(): Promise<boolean> {
  const current = await readProxySnapshot();
  let changed = false;
  if (current.autoConfigUrl !== undefined && isShadowPacUrl(current.autoConfigUrl)) {
    await regDeleteValue("AutoConfigURL");
    changed = true;
  }
  if (isShadowStaticProxy(current.proxyServer, current.proxyOverride)) {
    await regAddDword("ProxyEnable", "0");
    await regDeleteValue("ProxyServer");
    const userOverride = withoutLocalOverrideEntries(current.proxyOverride);
    if (userOverride) {
      await regAddString("ProxyOverride", userOverride, snapshotStringType(current, "proxyOverride"));
    } else {
      await regDeleteValue("ProxyOverride");
    }
    changed = true;
  }
  if (changed) {
    await refreshWindowsProxy();
  }
  return changed;
}

type ProxySnapshotStringField = "proxyServer" | "proxyOverride" | "autoConfigUrl";

interface ProxySnapshot {
  proxyEnable?: string;
  proxyServer?: string;
  proxyOverride?: string;
  autoConfigUrl?: string;
  autoDetect?: string;
  /** String values stored as REG_EXPAND_SZ, restored with that type. */
  expandStrings?: ProxySnapshotStringField[];
}

const PROXY_SNAPSHOT_STRING_FIELDS: readonly ProxySnapshotStringField[] = ["proxyServer", "proxyOverride", "autoConfigUrl"];

/**
 * WinINet bypass entries for names that stay out of the tunnel when no rule
 * names them: `<local>` (names without a dot), localhost and `.local` names.
 * The static proxy writes them as the whole override, so intranet names stay
 * direct as they do on the PAC, Xray and TUN paths. The user's own entries
 * are not kept beside them - the journal puts them back on disconnect - since
 * the PAC path ignores them: a leftover of another proxy tool such as
 * `10.*;192.168.*`, or `*.corp.example`, would otherwise send hosts direct
 * on one path that the other tunnels, and past the listener and its rules.
 *
 * WinINet applies the override before the proxy sees the connection, so a
 * user rule for such a name - `corp.local`, or an IP rule for the local
 * network that a single-label name resolves into - could not win over it as
 * it does everywhere else (step 2 of the shared order, ahead of the local
 * network). While such a rule exists the entries it needs are left out (see
 * staticProxyOverride): those names then reach the listener behind the
 * setting - the SSH listener, the local enforcer or Xray - which keeps the
 * ones no rule names direct itself. Without one they stay, so intranet names
 * take no detour through the loopback listener and Windows still counts the
 * sites that bypass the proxy as its Local intranet zone.
 *
 * The local and private address ranges are left to the proxy behind the
 * setting - the SSH listener and Xray's routing both send them direct unless
 * a user rule names them - since WinINet has no way to write them: an
 * override entry is a wildcard on the host as written, so `10.*` would also
 * bypass the tunnel for public names such as 10.cdn.example.com or 127.net.
 * An IP rule for a private range therefore wins on this path too.
 */
const LOCAL_PROXY_OVERRIDE_ENTRIES: readonly string[] = ["<local>", "localhost", "*.local", "[::1]"];

/** The ProxyOverride the static proxy writes while no user rule names the local network. */
export const STATIC_PROXY_OVERRIDE = LOCAL_PROXY_OVERRIDE_ENTRIES.join(";");

/**
 * The ProxyOverride the static proxy writes for these rules: every entry of
 * LOCAL_PROXY_OVERRIDE_ENTRIES a user rule does not need gone. An IP rule
 * that overlaps a local range - `10.0.0.0/8`, `0.0.0.0/0` - can select a
 * single-label or `.local` name by the address it resolves to, so it takes
 * `<local>` and `*.local` out; a domain rule for a `.local` name takes out
 * `*.local` (no domain rule can name a single-label one). Loopback stays.
 */
export function staticProxyOverride(rules: readonly RoutingRule[]): string {
  let localIpRule = false;
  let localDomainRule = false;
  for (const rule of rules) {
    if (!rule.enabled || !validateRoutingRuleValue(rule.type, rule.value).ok) {
      continue;
    }
    const value = normalizeRuleValue(rule.type, rule.value);
    if (rule.type === "ip" && overlapsLocalDestinationRange(value)) {
      localIpRule = true;
    } else if (rule.type === "domain" && isLocalDestinationHost(value.startsWith("*.") ? value.slice(2) : value)) {
      localDomainRule = true;
    }
  }
  return LOCAL_PROXY_OVERRIDE_ENTRIES.filter((entry) =>
    entry === "<local>" ? !localIpRule : entry === "*.local" ? !localIpRule && !localDomainRule : true
  ).join(";");
}

/** Every ProxyOverride staticProxyOverride can write, as sets of lower-case entries. */
const STATIC_PROXY_OVERRIDE_FORMS: readonly ReadonlySet<string>[] = [
  LOCAL_PROXY_OVERRIDE_ENTRIES,
  LOCAL_PROXY_OVERRIDE_ENTRIES.filter((entry) => entry !== "*.local"),
  LOCAL_PROXY_OVERRIDE_ENTRIES.filter((entry) => entry !== "*.local" && entry !== "<local>")
].map((entries) => new Set(entries.map((entry) => entry.toLowerCase())));

const PROXY_SNAPSHOT_VERSION = 1;
const MAX_PROXY_SNAPSHOT_BYTES = 256 * 1024;
const MAX_PROXY_REGISTRY_STRING_LENGTH = 64 * 1024;
const MAX_SERVED_PAC_VERSIONS = 8;
const MAX_RETAINED_PAC_ENDPOINTS = 4;

export class WindowsSystemProxyManager {
  private snapshot: ProxySnapshot | undefined;
  private readonly pacDirectory: string;
  private readonly pacPath: string;
  private readonly pacServerFactory: (requestListener: RequestListener) => Server;
  private pacServer: Server | undefined;
  private readonly retainedPacServers = new Set<Server>();
  private readonly currentPacFallbackServers = new Set<Server>();
  private pacContent = "";
  private publishedPacContent = "";
  private readonly pacVersions = new Map<string, string>();
  private registeredPacUrl: string | undefined;
  private registryPacUrl: string | undefined;
  private pendingPacNotificationUrl: string | undefined;
  private registeredStaticProxy: string | undefined;
  private proxyStateDirty = false;
  private operationQueue: Promise<void> = Promise.resolve();
  private readonly onDiagnostic: ((message: string) => void) | undefined;
  /** Set-aside journal notices not yet reported through apply()'s result. */
  private journalNotices: string[] = [];

  constructor(options: WindowsSystemProxyOptions = {}) {
    this.pacDirectory = options.pacDirectory ?? defaultPacDirectory();
    this.pacPath = path.join(this.pacDirectory, "shadow-ssh-routing.pac");
    this.pacServerFactory = options.pacServerFactory ?? createServer;
    this.onDiagnostic = options.onDiagnostic;
  }

  apply(request: SystemProxyApplyRequest): Promise<SystemProxyApplyResult> {
    return this.enqueueOperation(async () => {
      try {
        const result = await this.applyInternal(request);
        this.proxyStateDirty = false;
        // A set-aside journal is reported once, with the first apply that
        // succeeds after it; a failed apply keeps the notice for the next.
        const notices = this.journalNotices;
        this.journalNotices = [];
        return notices.length > 0 ? { ...result, message: [...notices, result.message].join(" ") } : result;
      } catch (error) {
        this.proxyStateDirty = true;
        throw error;
      }
    });
  }

  private async applyInternal(request: SystemProxyApplyRequest): Promise<SystemProxyApplyResult> {
    if (process.platform !== "win32") {
      return { applied: false, message: "System proxy was not changed because this platform is not Windows." };
    }
    assertLocalProxyEndpoint(request.socksHost, request.socksPort);

    await this.restorePersistedSnapshot();
    if (!this.snapshot) {
      const snapshot = withoutAppOwnedProxyValues(await readProxySnapshot(), request.socksHost, request.socksPort);
      await persistProxySnapshot(this.pacDirectory, snapshot);
      this.snapshot = snapshot;
    }

    const proxyDomains = normalizeProxyDomains(request.proxyDomains);
    const directDomains = normalizeProxyDomains(request.directDomains);
    if (request.mode === "proxy-all" && directDomains.length === 0) {
      const staticProxy = buildWindowsProxyServer(request.socksHost, request.socksPort, request.proxyProtocol ?? "mixed");
      const proxyOverride = staticProxyOverride(request.rules);
      // The override follows the rules, so a rule for the local network
      // rewrites it even where the proxy itself stays.
      const registration = `${staticProxy}\n${proxyOverride}`;
      if (this.proxyStateDirty || this.registeredStaticProxy !== registration || Boolean(this.pacServer)) {
        this.registeredStaticProxy = undefined;
        await regAddDword("ProxyEnable", "1");
        await regAddString("ProxyServer", staticProxy);
        await regDeleteValue("AutoConfigURL");
        // Only the local names that stay out of the tunnel (see
        // LOCAL_PROXY_OVERRIDE_ENTRIES for why the user's own entries are not
        // kept, and staticProxyOverride for the rules that take entries
        // out). The persisted snapshot restores the exact prior value on
        // disconnect.
        await regAddString("ProxyOverride", proxyOverride);
        this.registryPacUrl = undefined;
        this.pendingPacNotificationUrl = undefined;
        await regAddDword("AutoDetect", "0");
        await refreshWindowsProxy();
        this.registeredStaticProxy = registration;
      }
      // Keep the old PAC endpoint alive until WinINet has successfully switched
      // to the static proxy. A registry failure must not leave AutoConfigURL
      // pointing at a listener we already stopped.
      await this.stopPacServer();
      this.registeredPacUrl = undefined;
      return { applied: true, message: `Windows system proxy enabled at ${request.socksHost}:${request.socksPort}.` };
    }

    const pac = buildProxyPac(request.rules, request.socksHost, request.socksPort, request.proxyProtocol ?? "mixed", {
      proxyDomains,
      directDomains,
      mode: request.mode
    });
    const pacChanged = pac !== this.pacContent;
    if (pacChanged) {
      await mkdir(this.pacDirectory, { recursive: true, mode: 0o700 });
      await writeFile(this.pacPath, pac, { encoding: "utf8", mode: 0o600 });
    }
    const forcePacEndpointRotation = request.forcePacEndpointRotation === true;
    const retriedPublishedEndpoint = forcePacEndpointRotation
      ? await this.retryPendingPacNotification()
      : false;
    const reusingRetriedEndpoint = retriedPublishedEndpoint && !pacChanged;
    const pacEndpoint = await this.startPacServer(pac, forcePacEndpointRotation && !reusingRetriedEndpoint);
    // Process routing intentionally uses the same plain path as the original
    // compatibility implementation. The newly allocated port makes the URL
    // unique and avoids PAC caches that ignore query parameters. Stable
    // domain/IP routing keeps immutable content hashes on one listener.
    const pacUrl = forcePacEndpointRotation ? pacEndpoint.baseUrl : versionPacUrl(pacEndpoint.baseUrl, pacEndpoint.version);
    try {
      if (this.proxyStateDirty || this.registeredPacUrl !== pacUrl) {
        const revisingActivePac =
          !forcePacEndpointRotation &&
          !this.proxyStateDirty &&
          this.registeredPacUrl !== undefined &&
          this.registeredStaticProxy === undefined;
        if (!revisingActivePac) {
          await regAddDword("ProxyEnable", "0");
          await regDeleteValue("ProxyServer");
          await regAddDword("AutoDetect", "0");
        }
        await regAddString("AutoConfigURL", pacUrl);
        this.registryPacUrl = pacUrl;
        await refreshWindowsProxy();
        this.registeredStaticProxy = undefined;
        this.registeredPacUrl = pacUrl;
      } else if (pacChanged) {
        // A SHA-256 URL version normally changes together with the PAC content.
        // Keep this notification as a collision-safe fallback without restarting
        // the listener that is already serving the current in-memory PAC.
        await notifyWindowsProxyChanged();
      }
    } catch (error) {
      if (forcePacEndpointRotation && this.registryPacUrl === pacUrl) {
        this.pendingPacNotificationUrl = pacUrl;
      }
      await this.finishPacEndpointRotation(pacEndpoint, pacUrl, false);
      throw error;
    }
    this.pendingPacNotificationUrl = undefined;
    this.publishedPacContent = pac;
    await this.finishPacEndpointRotation(pacEndpoint, pacUrl, true);
    const proxyListMessage = proxyDomains.length > 0 ? ` with ${proxyDomains.length} proxy-list domains` : "";
    const directListMessage = directDomains.length > 0 ? ` and ${directDomains.length} direct-list domains` : "";
    return { applied: true, message: `Windows PAC routing enabled for ${request.mode}${proxyListMessage}${directListMessage} through ${request.socksHost}:${request.socksPort} at ${pacUrl}.` };
  }

  restore(): Promise<void> {
    return this.enqueueOperation(async () => {
      try {
        await this.restoreInternal();
        this.proxyStateDirty = false;
      } catch (error) {
        this.proxyStateDirty = true;
        throw error;
      }
    });
  }

  private async restoreInternal(): Promise<void> {
    if (process.platform !== "win32") {
      await this.stopPacServer();
      this.proxyStateDirty = false;
      return;
    }

    // Without a diagnostics sink the notice waits for the next apply's result.
    const snapshot = this.snapshot ?? (await readUsableProxySnapshot(this.pacDirectory, (message) => {
      if (this.onDiagnostic) {
        this.onDiagnostic(message);
      } else {
        this.journalNotices.push(message);
      }
    }));
    if (!snapshot) {
      await this.stopPacServer();
      this.proxyStateDirty = false;
      return;
    }

    // Restore and publish the user's registry state while the current PAC is
    // still reachable. Only then retire the PAC endpoint and remove the crash
    // journal. Failed registry writes leave both PAC and snapshot available.
    await restoreValue("ProxyEnable", snapshot.proxyEnable, "REG_DWORD");
    await restoreValue("ProxyServer", snapshot.proxyServer, snapshotStringType(snapshot, "proxyServer"));
    await restoreValue("ProxyOverride", snapshot.proxyOverride, snapshotStringType(snapshot, "proxyOverride"));
    await restoreValue("AutoConfigURL", snapshot.autoConfigUrl, snapshotStringType(snapshot, "autoConfigUrl"));
    this.registryPacUrl = undefined;
    this.pendingPacNotificationUrl = undefined;
    await restoreValue("AutoDetect", snapshot.autoDetect, "REG_DWORD");
    await refreshWindowsProxy();
    await this.stopPacServer();
    this.snapshot = undefined;
    this.registeredPacUrl = undefined;
    this.registryPacUrl = undefined;
    this.pendingPacNotificationUrl = undefined;
    this.registeredStaticProxy = undefined;
    this.proxyStateDirty = false;
    await rm(this.pacPath, { force: true });
    await rm(snapshotPath(this.pacDirectory), { force: true });
  }

  private async restorePersistedSnapshot(): Promise<void> {
    if (this.snapshot) {
      return;
    }
    // An unreadable journal used to fail every apply until someone deleted it
    // by hand. It is set aside instead: what it described is lost either way,
    // and the settings read next become the ones to restore.
    const snapshot = await readUsableProxySnapshot(this.pacDirectory, (message) => this.journalNotices.push(message));
    if (!snapshot) {
      return;
    }
    await this.restoreInternal();
  }

  private enqueueOperation<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.operationQueue.then(operation);
    // Keep subsequent apply/restore requests ordered even when one operation
    // fails. Registry edits and PAC listener lifecycle must never overlap.
    this.operationQueue = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  private async startPacServer(
    pac: string,
    forceNewEndpoint = false
  ): Promise<{
    baseUrl: string;
    version: string;
    server: Server;
    previousServer?: Server;
    previousPacContent?: string;
  }> {
    const previousPacContent = this.pacContent;
    this.pacContent = pac;
    const version = pacVersion(pac);
    this.rememberPacVersion(version, pac);
    if (this.pacServer && !forceNewEndpoint) {
      const currentAddress = this.pacServer.address();
      if (isAddressInfo(currentAddress)) {
        return {
          baseUrl: `http://127.0.0.1:${currentAddress.port}/shadow-ssh-routing.pac`,
          version,
          server: this.pacServer
        };
      }
      await this.stopPacServer();
      this.pacContent = pac;
      this.rememberPacVersion(version, pac);
    }
    const previousServer = forceNewEndpoint ? this.pacServer : undefined;
    const endpointPacContent = forceNewEndpoint ? pac : undefined;
    const serverHolder: { value?: Server } = {};
    const server = this.pacServerFactory((request, response) => {
      let requestUrl: URL;
      try {
        requestUrl = new URL(request.url ?? "", "http://127.0.0.1");
      } catch {
        response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
        response.end("Bad request");
        return;
      }
      if (requestUrl.pathname !== "/shadow-ssh-routing.pac") {
        response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        response.end("Not found");
        return;
      }
      const requestedVersion = requestUrl.searchParams.get("v");
      // The actively registered version is always retained. An unusually
      // stale WinINet client may request an older successfully published URL
      // after the bounded history was evicted; serving the current PAC is
      // safer than letting that client fall back to DIRECT on a 404.
      const requestedPac = requestedVersion
        ? this.pacVersions.get(requestedVersion) ?? this.pacContent
        : serverHolder.value !== undefined && this.currentPacFallbackServers.has(serverHolder.value)
          ? this.publishedPacContent || this.pacContent
          : endpointPacContent ?? this.pacContent;
      response.writeHead(200, {
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Content-Type": "application/x-ns-proxy-autoconfig; charset=utf-8",
        Pragma: "no-cache"
      });
      response.end(requestedPac);
    });
    serverHolder.value = server;
    server.on("clientError", (_error, socket) => {
      socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    });

    // A post-listen server error must not become an unhandled EventEmitter
    // error that terminates Electron while the user's registry still points at
    // this PAC URL. Queue a best-effort full restore; if it fails, the persisted
    // snapshot remains available for startup recovery.
    server.on("error", () => {
      void this.enqueueOperation(async () => {
        if (this.pacServer !== server) {
          return;
        }
        try {
          await this.restoreInternal();
          this.proxyStateDirty = false;
        } catch (error) {
          this.proxyStateDirty = true;
          throw error;
        }
      }).catch(() => undefined);
    });

    try {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", () => {
          server.off("error", reject);
          resolve();
        });
      });
    } catch (error) {
      await closeServer(server);
      this.pacContent = previousPacContent;
      throw error;
    }

    const address = server.address();
    if (!isAddressInfo(address)) {
      await closeServer(server);
      this.pacContent = previousPacContent;
      throw new Error("PAC server did not bind a TCP address.");
    }
    this.pacServer = server;
    return {
      baseUrl: `http://127.0.0.1:${address.port}/shadow-ssh-routing.pac`,
      version,
      server,
      previousServer,
      previousPacContent: previousServer ? previousPacContent : undefined
    };
  }

  private async finishPacEndpointRotation(
    endpoint: { server: Server; previousServer?: Server; previousPacContent?: string },
    pacUrl: string,
    succeeded: boolean
  ): Promise<void> {
    const previousServer = endpoint.previousServer;
    if (succeeded) {
      if (previousServer && previousServer !== endpoint.server) {
        this.retainedPacServers.add(previousServer);
      }
      await this.publishRetainedPacServers(endpoint.server);
      return;
    }

    if (!previousServer || previousServer === endpoint.server) {
      return;
    }

    if (this.registryPacUrl === pacUrl) {
      // AutoConfigURL was published, but the WinINet broadcast failed. Some
      // processes can still hold the previous PAC URL in memory, while newly
      // created sessions can already read the new URL from the registry. Keep
      // both endpoints reachable until a later apply succeeds or restore()
      // retires all app-owned listeners.
      this.retainedPacServers.add(previousServer);
      return;
    }

    if (this.pacServer === endpoint.server) {
      this.pacServer = previousServer;
    }
    await closeServer(endpoint.server);
    const registryVersion = pacVersionFromUrl(this.registryPacUrl);
    this.pacContent = endpoint.previousPacContent ??
      (registryVersion ? this.pacVersions.get(registryVersion) : undefined) ??
      this.pacContent;
  }

  private async retryPendingPacNotification(): Promise<boolean> {
    const pendingUrl = this.pendingPacNotificationUrl;
    const server = this.pacServer;
    if (!pendingUrl || pendingUrl !== this.registryPacUrl || !server || !isAddressInfo(server.address())) {
      return false;
    }

    // Do not allocate another listener while publication of the current one is
    // unresolved. Reassert the complete per-user proxy state and retry the
    // broadcast first; only a successful retry may retire the endpoint still
    // cached by older WinINet sessions or proceed to publish newer PAC content.
    await regAddDword("ProxyEnable", "0");
    await regDeleteValue("ProxyServer");
    await regAddDword("AutoDetect", "0");
    await regAddString("AutoConfigURL", pendingUrl);
    this.registryPacUrl = pendingUrl;
    await refreshWindowsProxy();
    this.registeredStaticProxy = undefined;
    this.registeredPacUrl = pendingUrl;
    this.pendingPacNotificationUrl = undefined;
    this.proxyStateDirty = false;
    this.publishedPacContent = this.pacContent;
    await this.publishRetainedPacServers(server);
    return true;
  }

  private rememberPacVersion(version: string, pac: string): void {
    this.pacVersions.delete(version);
    this.pacVersions.set(version, pac);
    const registeredVersion = pacVersionFromUrl(this.registeredPacUrl);
    const registryVersion = pacVersionFromUrl(this.registryPacUrl);
    while (this.pacVersions.size > MAX_SERVED_PAC_VERSIONS) {
      const removable = [...this.pacVersions.keys()].find(
        (candidate) => candidate !== version && candidate !== registeredVersion && candidate !== registryVersion
      );
      if (!removable) {
        break;
      }
      this.pacVersions.delete(removable);
    }
  }

  private async stopPacServer(): Promise<void> {
    const server = this.pacServer;
    this.pacServer = undefined;
    const servers = new Set(this.retainedPacServers);
    this.retainedPacServers.clear();
    this.currentPacFallbackServers.clear();
    if (server) {
      servers.add(server);
    }
    await Promise.all([...servers].map(closeServer));
    this.pacContent = "";
    this.publishedPacContent = "";
    this.pacVersions.clear();
    this.registeredPacUrl = undefined;
    this.pendingPacNotificationUrl = undefined;
  }

  private async publishRetainedPacServers(activeServer: Server): Promise<void> {
    this.retainedPacServers.delete(activeServer);
    this.currentPacFallbackServers.delete(activeServer);
    for (const server of this.retainedPacServers) {
      this.currentPacFallbackServers.add(server);
    }

    const retained = [...this.retainedPacServers];
    const expired = retained.slice(0, Math.max(0, retained.length - MAX_RETAINED_PAC_ENDPOINTS));
    for (const server of expired) {
      this.retainedPacServers.delete(server);
      this.currentPacFallbackServers.delete(server);
    }
    await Promise.all(expired.map(closeServer));
  }
}

export function buildProxyPac(
  rules: RoutingRule[],
  socksHost: string,
  socksPort: number,
  proxyProtocol: "mixed" | "http" | "socks" = "mixed",
  options: { proxyDomains?: string[]; directDomains?: string[]; mode?: RoutingMode } = {}
): string {
  const proxy = buildPacProxyReturn(socksHost, socksPort, proxyProtocol);
  const validRules = rules.filter((rule) => rule.enabled && validateRoutingRuleValue(rule.type, rule.value).ok);
  const domainRules = validRules.filter((rule) => rule.type === "domain").map((rule) => normalizeDomainRule(rule.value));
  const directListDomains = normalizeProxyDomains(options.directDomains).map(normalizeSuffixDomain);
  const proxyListDomains = normalizeProxyDomains(options.proxyDomains).map(normalizeSuffixDomain);
  // A plain rule covers the domain and its subdomains, exactly like a curated
  // proxy-list entry. Matching only the literal host made custom rules miss
  // `www.` and every API/CDN subdomain, so they appeared to do nothing.
  const plainDomainRules = domainRules.filter((rule) => !rule.startsWith("*.")).map((rule) => rule);
  const wildcardDomainRules = domainRules.filter((rule) => rule.startsWith("*.")).map((rule) => rule.slice(2));
  const parsedIpRules = validRules.flatMap((rule) => {
    if (rule.type !== "ip") {
      return [];
    }
    const value = rule.value.trim();
    const range = parseCidrRange(value);
    if (!range) {
      return [];
    }
    return [{
      range,
      rule: value,
      learned: rule.id.startsWith(LEARNED_PROCESS_IP_RULE_PREFIX)
    }];
  });
  // Every exact rule gets a zero-DNS literal fast path. Hostname matching still
  // includes learned process IPs as a generic fallback for applications using
  // DoH or a resolver that never populates the Windows DNS cache. The generated
  // PAC memoizes that lookup per hostname, so repeated media requests do not
  // synchronously resolve the same CDN host on every proxy decision.
  const dnsIpRules = parsedIpRules;
  const exactIpRules = parsedIpRules
    .filter(({ range }) => range.prefixLength === (range.version === 4 ? 32 : 128))
    .map(({ range }) => range.version === 4 ? ipv4BigIntToDotted(range.network) : ipv6BigIntToString(range.network));
  // An address process discovery learned stands for a process rule. The PAC
  // cannot tell which application asks, so it cannot hold step 4 of the shared
  // order: as a user rule (step 2) the address pulled every application's
  // traffic to a direct-list site on it into the tunnel. It is checked after
  // the direct list instead - the one place the PAC ranks process evidence
  // differently from the TUN adapter and the routing listener, which put the
  // process rule first - and only for a host neither the local network nor
  // the direct list keeps out. A literal address is on neither, so the fast
  // path above serves both kinds.
  const exactResolvedAddress = ({ range }: (typeof dnsIpRules)[number]): string =>
    range.version === 4 ? ipv4BigIntToDotted(range.network) : ipv6BigIntToString(range.network);
  const isExactRule = ({ range }: (typeof dnsIpRules)[number]): boolean =>
    range.prefixLength === (range.version === 4 ? 32 : 128);
  const resolvedExactIpRules = dnsIpRules.filter((rule) => !rule.learned && isExactRule(rule)).map(exactResolvedAddress);
  const learnedResolvedExactIpRules = dnsIpRules.filter((rule) => rule.learned && isExactRule(rule)).map(exactResolvedAddress);
  const ipChecks = dnsIpRules.filter((rule) => !rule.learned).flatMap(({ rule }) => buildIpChecks(rule));
  const learnedIpChecks = dnsIpRules.filter((rule) => rule.learned && !isExactRule(rule)).flatMap(({ rule }) => buildIpChecks(rule));
  const mode = options.mode ?? "selected-rules";
  // A lookup only ever turns DIRECT into PROXY - an IP rule outranks the
  // local network and the direct list - so it runs last, for the hosts that
  // would otherwise go direct, and only when IP rules exist. In proxy-all
  // those are the local and direct-list hosts alone.
  const resolvesHosts = dnsIpRules.length > 0;
  const needsIpv4Dns = resolvesHosts && dnsIpRules.some(({ range }) => range.version === 4);
  const needsExtendedDns = resolvesHosts;
  const literalIpCheck = exactIpRules.length > 0 ? "hasOwn(proxyExactIps, hostNoBrackets)" : "";
  const userRuleCheck = [
    "matchesDomainOrParent(hostNoBrackets, proxyRuleDomains)",
    "matchesSubdomain(hostNoBrackets, proxyWildcardDomains)",
    literalIpCheck
  ].filter(Boolean).join(" || ");
  const exactIpCheck = resolvedExactIpRules.length > 0
    ? "hasOwn(proxyResolvedExactIps, resolvedHost) || resolvedHasOwn(resolvedHosts, proxyResolvedExactIps)"
    : "";
  const resolvedIpCheck = [exactIpCheck, ...ipChecks].filter(Boolean).join(" || ");
  const learnedExactIpCheck = learnedResolvedExactIpRules.length > 0
    ? "hasOwn(learnedResolvedExactIps, resolvedHost) || resolvedHasOwn(resolvedHosts, learnedResolvedExactIps)"
    : "";
  const learnedResolvedIpCheck = [learnedExactIpCheck, ...learnedIpChecks].filter(Boolean).join(" || ");
  // A host the rules have not claimed: proxy-all proxies it unless the local
  // network or the direct list keeps it out; split routing proxies it only
  // from the proxy list, and both win over the proxy list there too.
  const unclaimedProxyRule = mode === "proxy-all"
    ? `  if (!direct) { return ${JSON.stringify(proxy)}; }`
    : `  if (!direct && matchesDomainOrParent(hostNoBrackets, proxyListDomains)) { return ${JSON.stringify(proxy)}; }`;
  const postDnsProxyRules = resolvesHosts
    ? [
        ...(resolvedIpCheck ? [`  if (${resolvedIpCheck}) { return ${JSON.stringify(proxy)}; }`] : []),
        ...(learnedResolvedIpCheck ? [`  if (!direct && (${learnedResolvedIpCheck})) { return ${JSON.stringify(proxy)}; }`] : [])
      ]
    : [];

  return [
    "// Shadow routing PAC. Generated by the desktop client.",
    `var directDomains = ${domainLookupLiteral(directListDomains)};`,
    `var proxyListDomains = ${domainLookupLiteral(proxyListDomains)};`,
    `var proxyRuleDomains = ${domainLookupLiteral(plainDomainRules)};`,
    `var proxyWildcardDomains = ${domainLookupLiteral(wildcardDomainRules)};`,
    `var proxyExactIps = ${domainLookupLiteral(exactIpRules)};`,
    `var proxyResolvedExactIps = ${domainLookupLiteral(resolvedExactIpRules)};`,
    ...(learnedResolvedExactIpRules.length > 0 ? [`var learnedResolvedExactIps = ${domainLookupLiteral(learnedResolvedExactIpRules)};`] : []),
    ...(needsExtendedDns
      ? [
          "var resolvedHostCache = {};",
          "var resolvedHostCacheOrder = [];",
          "var resolvedHostCacheLimit = 256;"
        ]
      : []),
    // The shared routing order: the user's rules (a rule for a private range
    // or a .local name included), then local destinations, then the direct
    // list, then proxy-all or the proxy list. An IP rule matched through DNS
    // belongs with the rules, but is checked last: it can only turn a DIRECT
    // answer into PROXY, so only those hosts pay for the lookup. A learned
    // process address comes after the local network and the direct list.
    "function FindProxyForURL(url, host) {",
    "  host = String(host || \"\").toLowerCase();",
    "  var hostNoBrackets = host.replace(/^\\[/, \"\").replace(/\\]$/, \"\");",
    `  if (${userRuleCheck}) { return ${JSON.stringify(proxy)}; }`,
    "  var direct = isLocalDestination(hostNoBrackets) || matchesDomainOrParent(hostNoBrackets, directDomains);",
    unclaimedProxyRule,
    ...(postDnsProxyRules.length > 0
      ? [
          needsExtendedDns ? "  var resolvedHosts = resolveHosts(hostNoBrackets);" : "  var resolvedHosts = [];",
          needsIpv4Dns ? "  var resolvedHost = firstIpv4OrHost(resolvedHosts, hostNoBrackets);" : "  var resolvedHost = hostNoBrackets;",
          ...postDnsProxyRules
        ]
      : []),
    "  return \"DIRECT\";",
    "}",
    "function hasOwn(map, key) {",
    "  return Object.prototype.hasOwnProperty.call(map, key);",
    "}",
    // Never resolves: literal addresses and names are judged as written, the
    // same way the listener and Xray judge them.
    "function isLocalDestination(host) {",
    "  var name = host.replace(/\\.$/, \"\");",
    "  if (!name) { return false; }",
    "  var ipv4 = /^(\\d{1,3})\\.(\\d{1,3})\\.\\d{1,3}\\.\\d{1,3}$/.exec(name);",
    "  if (ipv4) { return isLocalIpv4(Number(ipv4[1]), Number(ipv4[2])); }",
    "  if (name.indexOf(\":\") >= 0) { return isLocalIpv6(name); }",
    "  return name.indexOf(\".\") < 0 || /\\.local$/.test(name);",
    "}",
    "function isLocalIpv4(first, second) {",
    "  return first === 0 || first === 10 || first === 127 ||",
    "    (first === 100 && second >= 64 && second <= 127) ||",
    "    (first === 169 && second === 254) ||",
    "    (first === 172 && second >= 16 && second <= 31) ||",
    "    (first === 192 && second === 168);",
    "}",
    "function isLocalIpv6(host) {",
    "  var mapped = /^::ffff:(\\d{1,3})\\.(\\d{1,3})\\.\\d{1,3}\\.\\d{1,3}$/.exec(host);",
    "  if (mapped) { return isLocalIpv4(Number(mapped[1]), Number(mapped[2])); }",
    "  var mappedHex = /^::ffff:([0-9a-f]{1,4}):[0-9a-f]{1,4}$/.exec(host);",
    "  if (mappedHex) {",
    "    var high = parseInt(mappedHex[1], 16);",
    "    return isLocalIpv4(Math.floor(high / 256), high % 256);",
    "  }",
    "  return host === \"::1\" || /^fe[89ab][0-9a-f]:/.test(host) || /^f[cd][0-9a-f]{2}:/.test(host);",
    "}",
    "function matchesDomainOrParent(host, map) {",
    "  var candidate = host;",
    "  while (candidate) {",
    "    if (hasOwn(map, candidate)) { return true; }",
    "    var dot = candidate.indexOf(\".\");",
    "    if (dot < 0) { return false; }",
    "    candidate = candidate.slice(dot + 1);",
    "  }",
    "  return false;",
    "}",
    "function matchesSubdomain(host, map) {",
    "  var dot = host.indexOf(\".\");",
    "  while (dot >= 0) {",
    "    host = host.slice(dot + 1);",
    "    if (hasOwn(map, host)) { return true; }",
    "    dot = host.indexOf(\".\");",
    "  }",
    "  return false;",
    "}",
    ...(needsExtendedDns
      ? [
          "function resolveHosts(host) {",
          "  var cacheKey = \"$\" + host;",
          "  if (hasOwn(resolvedHostCache, cacheKey)) { return resolvedHostCache[cacheKey]; }",
          "  var entries = resolveHostsUncached(host);",
          "  if (entries.length === 1 && entries[0] === host) { return entries; }",
          "  if (resolvedHostCacheOrder.length >= resolvedHostCacheLimit) {",
          "    var expiredKey = resolvedHostCacheOrder.shift();",
          "    if (expiredKey) { delete resolvedHostCache[expiredKey]; }",
          "  }",
          "  resolvedHostCache[cacheKey] = entries;",
          "  resolvedHostCacheOrder.push(cacheKey);",
          "  return entries;",
          "}",
          "function resolveHostsUncached(host) {",
          "  var values = \"\";",
          "  try {",
          "    values = typeof dnsResolveEx === \"function\" ? String(dnsResolveEx(host) || \"\").toLowerCase() : \"\";",
          "  } catch (e) { values = \"\"; }",
          "  var entries = splitResolvedHosts(values);",
          "  if (entries.length === 0) {",
          "    try {",
          "      var fallback = typeof dnsResolve === \"function\" ? dnsResolve(host) : \"\";",
          "      if (fallback) { entries.push(String(fallback).toLowerCase()); }",
          "    } catch (e) {}",
          "  }",
          "  if (entries.length === 0) { entries.push(host); }",
          "  return entries;",
          "}",
          "function splitResolvedHosts(values) {",
          "  var rawEntries = String(values || \"\").split(/[;,\\s]+/);",
          "  var entries = [];",
          "  for (var index = 0; index < rawEntries.length; index += 1) {",
          "    if (rawEntries[index]) { entries.push(rawEntries[index]); }",
          "  }",
          "  return entries;",
          "}",
          ...(needsIpv4Dns
            ? [
                "function firstIpv4OrHost(entries, host) {",
                "  for (var index = 0; index < entries.length; index += 1) {",
                "    if (/^\\d{1,3}(?:\\.\\d{1,3}){3}$/.test(entries[index])) { return entries[index]; }",
                "  }",
                "  return host;",
                "}"
              ]
            : []),
          "function resolvedHasOwn(entries, map) {",
          "  for (var index = 0; index < entries.length; index += 1) {",
          "    if (hasOwn(map, entries[index])) { return true; }",
          "  }",
          "  return false;",
          "}",
          "function resolvedIsInNetEx(entries, range) {",
          "  if (typeof isInNetEx !== \"function\") { return false; }",
          "  for (var index = 0; index < entries.length; index += 1) {",
          "    if (isInNetEx(entries[index], range)) { return true; }",
          "  }",
          "  return false;",
          "}"
        ]
      : []),
    ""
  ].join("\n");
}

async function readProxySnapshot(): Promise<ProxySnapshot> {
  const proxyServer = await regQueryTypedValue("ProxyServer");
  const proxyOverride = await regQueryTypedValue("ProxyOverride");
  const autoConfigUrl = await regQueryTypedValue("AutoConfigURL");
  const expandStrings = PROXY_SNAPSHOT_STRING_FIELDS.filter(
    (field) => ({ proxyServer, proxyOverride, autoConfigUrl })[field]?.type === "REG_EXPAND_SZ"
  );
  return {
    proxyEnable: await regQueryValue("ProxyEnable"),
    proxyServer: proxyServer?.value,
    proxyOverride: proxyOverride?.value,
    autoConfigUrl: autoConfigUrl?.value,
    autoDetect: await regQueryValue("AutoDetect"),
    ...(expandStrings.length > 0 ? { expandStrings } : {})
  };
}

/**
 * Drops values that are Shadow's own leftovers rather than the user's: a
 * crash, or a journal set aside as unreadable, can leave Shadow's PAC URL or
 * its static proxy in the registry, and taking those as the settings to
 * restore would leave Windows pointing at a dead local proxy after
 * disconnect. Shadow's PAC path is unique to it; a static proxy is Shadow's
 * when it names the listener Shadow is about to register, which nothing else
 * can be serving.
 */
function withoutAppOwnedProxyValues(snapshot: ProxySnapshot, socksHost: string, socksPort: number): ProxySnapshot {
  const ownStaticProxies = new Set(
    (["mixed", "socks"] as const).map((protocol) => buildWindowsProxyServer(socksHost, socksPort, protocol).toLowerCase())
  );
  // A static proxy Shadow left on another port - its listener's port is not
  // kept across launches - is recognised by the bypass entries it appended.
  const leftoverStaticProxy = isShadowStaticProxy(snapshot.proxyServer, snapshot.proxyOverride);
  const ownStaticProxy = leftoverStaticProxy ||
    (snapshot.proxyServer !== undefined && ownStaticProxies.has(snapshot.proxyServer.trim().toLowerCase()));
  const ownPacUrl = snapshot.autoConfigUrl !== undefined && isShadowPacUrl(snapshot.autoConfigUrl);
  if (!ownStaticProxy && !ownPacUrl) {
    return snapshot;
  }
  const userOverride = leftoverStaticProxy ? withoutLocalOverrideEntries(snapshot.proxyOverride) : snapshot.proxyOverride;
  const expandStrings = snapshot.expandStrings?.filter(
    (field) =>
      !(ownStaticProxy && field === "proxyServer") &&
      !(ownPacUrl && field === "autoConfigUrl") &&
      !(userOverride === undefined && field === "proxyOverride")
  );
  return {
    ...snapshot,
    ...(ownStaticProxy ? { proxyServer: undefined, proxyEnable: snapshot.proxyEnable === undefined ? undefined : "0" } : {}),
    ...(leftoverStaticProxy ? { proxyOverride: userOverride } : {}),
    ...(ownPacUrl ? { autoConfigUrl: undefined } : {}),
    expandStrings: expandStrings && expandStrings.length > 0 ? expandStrings : undefined
  };
}

/**
 * A loopback static proxy in the form Shadow writes, on any port, beside an
 * override that carries every bypass entry Shadow writes - or that is exactly
 * one of the shorter ones it writes for a rule naming the local network.
 * Either alone could be the user's; both together are Shadow's.
 */
function isShadowStaticProxy(proxyServer: string | undefined, proxyOverride: string | undefined): boolean {
  if (!proxyServer || !proxyOverride) {
    return false;
  }
  const value = proxyServer.trim().toLowerCase();
  const match = /^(?:http=([^;]+);https=\1|socks=([^;]+))$/u.exec(value);
  const endpoint = match?.[1] ?? match?.[2];
  if (!endpoint || !/^(?:127\.0\.0\.1|localhost|\[::1\]):\d{1,5}$/u.test(endpoint)) {
    return false;
  }
  const entries = new Set(proxyOverride.split(";").map((entry) => entry.trim().toLowerCase()).filter(Boolean));
  return (
    LOCAL_PROXY_OVERRIDE_ENTRIES.every((entry) => entries.has(entry.toLowerCase())) ||
    STATIC_PROXY_OVERRIDE_FORMS.some((form) => form.size === entries.size && [...form].every((entry) => entries.has(entry)))
  );
}

/** The override without the bypass entries Shadow writes; undefined when nothing else is left. */
function withoutLocalOverrideEntries(proxyOverride: string | undefined): string | undefined {
  const local = new Set(LOCAL_PROXY_OVERRIDE_ENTRIES.map((entry) => entry.toLowerCase()));
  const remaining = (proxyOverride ?? "")
    .split(";")
    .map((entry) => entry.trim())
    .filter((entry) => entry && !local.has(entry.toLowerCase()));
  return remaining.length > 0 ? remaining.join(";") : undefined;
}

function isShadowPacUrl(value: string): boolean {
  try {
    const url = new URL(value.trim());
    const host = url.hostname.replace(/^\[|\]$/gu, "");
    return url.protocol === "http:" &&
      (host === "127.0.0.1" || host === "localhost" || host === "::1") &&
      url.pathname === "/shadow-ssh-routing.pac";
  } catch {
    return false;
  }
}

function snapshotStringType(snapshot: ProxySnapshot, field: ProxySnapshotStringField): "REG_SZ" | "REG_EXPAND_SZ" {
  return snapshot.expandStrings?.includes(field) ? "REG_EXPAND_SZ" : "REG_SZ";
}

async function restoreValue(name: string, value: string | undefined, type: "REG_DWORD" | "REG_SZ" | "REG_EXPAND_SZ"): Promise<void> {
  if (value === undefined) {
    await regDeleteValue(name);
    return;
  }
  if (type === "REG_DWORD") {
    await regAddDword(name, value);
  } else {
    await regAddString(name, value, type);
  }
}

/** restoreValue, synchronously and without failing: true when the value is as the snapshot says. */
function restoreValueNow(name: string, value: string | undefined, type: "REG_DWORD" | "REG_SZ" | "REG_EXPAND_SZ"): boolean {
  const key = internetSettingsKey();
  const options = { windowsHide: true, timeout: 5_000, stdio: "ignore" as const };
  try {
    if (value === undefined) {
      try {
        execFileSync("reg.exe", ["delete", key, "/v", name, "/f"], options);
      } catch {
        // Most likely not there, which is what was wanted.
      }
      return true;
    }
    const data = type === "REG_DWORD" ? (value.startsWith("0x") ? value : Number(value).toString()) : value;
    execFileSync("reg.exe", ["add", key, "/v", name, "/t", type, "/d", data, "/f"], options);
    return true;
  } catch {
    return false;
  }
}

async function regQueryValue(name: string): Promise<string | undefined> {
  return (await regQueryTypedValue(name))?.value;
}

async function regQueryTypedValue(
  name: string
): Promise<{ value: string; type: "REG_SZ" | "REG_EXPAND_SZ" | "REG_DWORD" } | undefined> {
  const result = await execFileSafe("reg.exe", ["query", internetSettingsKey(), "/v", name]);
  if (result.exitCode !== 0) {
    // `reg query /v` uses the same nonzero exit code for a missing value and
    // broader failures. Confirm that the parent key itself is readable before
    // treating this as the normal "value absent" case.
    const keyResult = await execFileSafe("reg.exe", ["query", internetSettingsKey()]);
    if (keyResult.exitCode !== 0) {
      throw commandFailure("reg.exe", ["query", internetSettingsKey(), "/v", name], result);
    }
    return undefined;
  }
  // An empty string value prints nothing after its type, and REG_EXPAND_SZ is
  // what some deployment tools write for AutoConfigURL.
  const match = result.stdout.match(
    new RegExp(`^[ \\t]*${escapeRegExp(name)}[ \\t]+REG_(EXPAND_SZ|SZ|DWORD)(?:[ \\t]+([^\\r\\n]*))?[ \\t]*\\r?$`, "imu")
  );
  if (!match) {
    throw new Error(`reg.exe returned an unsupported value format for ${name}.`);
  }
  const type = `REG_${match[1].toUpperCase()}` as "REG_SZ" | "REG_EXPAND_SZ" | "REG_DWORD";
  const value = (match[2] ?? "").trim();
  if (type === "REG_DWORD" && !value) {
    throw new Error(`reg.exe returned an unsupported value format for ${name}.`);
  }
  return { value, type };
}

async function regAddString(name: string, value: string, type: "REG_SZ" | "REG_EXPAND_SZ" = "REG_SZ"): Promise<void> {
  await execFileChecked("reg.exe", ["add", internetSettingsKey(), "/v", name, "/t", type, "/d", value, "/f"]);
}

async function regAddDword(name: string, value: string): Promise<void> {
  const normalized = value.startsWith("0x") ? value : Number(value).toString();
  await execFileChecked("reg.exe", ["add", internetSettingsKey(), "/v", name, "/t", "REG_DWORD", "/d", normalized, "/f"]);
}

async function regDeleteValue(name: string): Promise<void> {
  if ((await regQueryValue(name)) === undefined) {
    return;
  }
  await execFileChecked("reg.exe", ["delete", internetSettingsKey(), "/v", name, "/f"]);
}

async function refreshWindowsProxy(): Promise<void> {
  // The app snapshots and owns only the current user's WinINet settings.
  // Importing those values into machine-wide WinHTTP would overwrite state we
  // cannot restore reliably (especially when Electron is elevated). Chromium
  // and the supported client path consume WinINet/PAC directly.
  await notifyWindowsProxyChanged();
}

async function notifyWindowsProxyChanged(): Promise<void> {
  await execFileChecked("powershell.exe", [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    [
      "$ErrorActionPreference='Stop'",
      "Add-Type -Namespace ShadowSsh -Name WinInet -MemberDefinition '[System.Runtime.InteropServices.DllImport(\"wininet.dll\", SetLastError=true)] public static extern bool InternetSetOption(System.IntPtr hInternet, int dwOption, System.IntPtr lpBuffer, int dwBufferLength);'",
      "$settingsChanged=[ShadowSsh.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)",
      "$settingsRefreshed=[ShadowSsh.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)",
      "$instancesNotified=[ShadowSsh.WinInet]::InternetSetOption([IntPtr]::Zero, 95, [IntPtr]::Zero, 0)",
      "if (-not ($settingsChanged -and $settingsRefreshed -and $instancesNotified)) { throw 'WinINet proxy refresh failed.' }"
    ].join("; ")
  ]);
}

async function execFileChecked(command: string, args: string[]): Promise<void> {
  const result = await execFileSafe(command, args);
  if (result.exitCode !== 0) {
    throw commandFailure(command, args, result);
  }
}

async function execFileSafe(command: string, args: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(command, args, {
      windowsHide: true,
      timeout: 15_000,
      maxBuffer: 1024 * 1024
    }, (error, stdout, stderr) => {
      const errorCode = (error as NodeJS.ErrnoException | null)?.code;
      resolve({
        exitCode: typeof errorCode === "number" ? errorCode : error ? 1 : 0,
        stdout,
        stderr: stderr || (error ? error.message : "")
      });
    });
  });
}

function commandFailure(
  command: string,
  args: string[],
  result: { exitCode: number; stdout: string; stderr: string }
): Error {
  return new Error(`${command} ${args.join(" ")} failed: ${result.stderr || result.stdout || `exit ${result.exitCode}`}`.trim());
}

function internetSettingsKey(): string {
  return "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
}

function defaultPacDirectory(): string {
  const appData = process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming");
  // The data folder keeps the pre-rename system name (see appSystemName in main.ts).
  const userData = process.env.SHADOW_SSH_USER_DATA_DIR || path.join(appData, "Shadow SSH");
  return path.join(userData, "routing");
}

function buildWindowsProxyServer(host: string, port: number, proxyProtocol: "mixed" | "http" | "socks"): string {
  const endpoint = formatProxyEndpoint(host, port);
  if (proxyProtocol === "socks") {
    return `socks=${endpoint}`;
  }
  // WinINet cannot spell "SOCKS5" in this string: Chrome and Firefox both read
  // a bare `socks=` entry as SOCKS4. Chrome then prefers that entry over the
  // http/https ones for ws:// and wss:// (RFC 6455 4.1.3), so advertising it
  // turned every WebSocket handshake into a SOCKS4 greeting - which the mixed
  // listener rejected at the first byte, breaking WebSocket applications
  // (conferencing signalling above all) whether or not they were routed.
  // The mixed listener answers HTTP CONNECT for every scheme, and CONNECT also
  // preserves the host name that domain and process rules are matched on.
  return `http=${endpoint};https=${endpoint}`;
}

function buildPacProxyReturn(host: string, port: number, proxyProtocol: "mixed" | "http" | "socks"): string {
  const endpoint = formatProxyEndpoint(host, port);
  if (proxyProtocol === "socks") {
    return `SOCKS5 ${endpoint}`;
  }
  // The mixed listener accepts HTTP CONNECT itself. Retrying the same failed
  // destination through SOCKS5 (and then unsupported SOCKS4) only multiplies a
  // remote connect timeout without adding a real fallback path.
  return `PROXY ${endpoint}`;
}

function assertLocalProxyEndpoint(host: string, port: number): void {
  const normalizedHost = host.trim().toLowerCase().replace(/^\[|\]$/gu, "");
  if (normalizedHost !== "127.0.0.1" && normalizedHost !== "localhost" && normalizedHost !== "::1") {
    throw new Error("Windows system proxy endpoint must be loopback-only.");
  }
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("Windows system proxy port must be between 1 and 65535.");
  }
}

function formatProxyEndpoint(host: string, port: number): string {
  const normalizedHost = host.trim().replace(/^\[|\]$/gu, "");
  return `${normalizedHost.includes(":") ? `[${normalizedHost}]` : normalizedHost}:${port}`;
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(forceTimer);
      resolve();
    };
    const forceTimer = setTimeout(() => {
      // PAC responses are small and stateless, so forcing lingering keep-alive
      // clients closed is safe and keeps proxy restoration/shutdown bounded.
      server.closeAllConnections();
      finish();
    }, 1_000);
    forceTimer.unref();
    server.close((error) => {
      if (error && (error as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING") {
        server.closeAllConnections();
      }
      finish();
    });
    server.closeIdleConnections();
  });
}

function isAddressInfo(address: ReturnType<Server["address"]>): address is AddressInfo {
  return typeof address === "object" && address !== null && typeof address.port === "number";
}

function normalizeDomainRule(value: string): string {
  return value.trim().toLowerCase();
}

function normalizeProxyDomains(domains: string[] | undefined): string[] {
  if (!Array.isArray(domains)) {
    return [];
  }
  return [...new Set(domains.map(normalizeProxyDomain).filter((domain): domain is string => domain !== undefined))];
}

function normalizeSuffixDomain(domain: string): string {
  return domain.replace(/^\*?\./u, "");
}

function domainLookupLiteral(domains: string[]): string {
  return JSON.stringify(Object.fromEntries([...new Set(domains.filter(Boolean))].map((domain) => [domain, 1])));
}

function pacVersion(pac: string): string {
  return createHash("sha256").update(pac, "utf8").digest("hex");
}

function versionPacUrl(baseUrl: string, version: string): string {
  const url = new URL(baseUrl);
  url.searchParams.set("v", version);
  return url.toString();
}

function pacVersionFromUrl(url: string | undefined): string | undefined {
  if (!url) {
    return undefined;
  }
  try {
    return new URL(url).searchParams.get("v") ?? undefined;
  } catch {
    return undefined;
  }
}

function buildIpChecks(rule: string): string[] {
  const range = parseCidrRange(rule);
  if (!range) {
    return [];
  }

  if (range.version === 4) {
    const networkIp = ipv4BigIntToDotted(range.network);
    if (range.prefixLength === 32) {
      return [];
    }
    return [
      `(isInNet(resolvedHost, ${JSON.stringify(networkIp)}, ${JSON.stringify(prefixToMask(range.prefixLength))}) || resolvedIsInNetEx(resolvedHosts, ${JSON.stringify(`${networkIp}/${range.prefixLength}`)}))`
    ];
  }

  const canonicalRange = `${ipv6BigIntToString(range.network)}/${range.prefixLength}`;
  if (range.prefixLength === 128) {
    // The exact-IP map is the fast path. isInNetEx retains an address-aware
    // fallback for PAC engines that return an equivalent IPv6 spelling.
    return [`resolvedIsInNetEx(resolvedHosts, ${JSON.stringify(canonicalRange)})`];
  }
  return [
    `resolvedIsInNetEx(resolvedHosts, ${JSON.stringify(canonicalRange)})`
  ];
}

function prefixToMask(prefixLength: number): string {
  if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 32) {
    return "255.255.255.255";
  }
  const mask = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0;
  return [24, 16, 8, 0].map((shift) => (mask >>> shift) & 0xff).join(".");
}

function ipv4BigIntToDotted(value: bigint): string {
  return [24, 16, 8, 0].map((shift) => Number((value >> BigInt(shift)) & 0xffn)).join(".");
}

function ipv6BigIntToString(value: bigint): string {
  const groups = Array.from({ length: 8 }, (_unused, index) =>
    Number((value >> BigInt((7 - index) * 16)) & 0xffffn).toString(16)
  );
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < groups.length;) {
    if (groups[index] !== "0") {
      index += 1;
      continue;
    }
    let end = index + 1;
    while (end < groups.length && groups[end] === "0") {
      end += 1;
    }
    if (end - index > bestLength && end - index >= 2) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  if (bestStart < 0) {
    return groups.join(":");
  }
  const left = groups.slice(0, bestStart).join(":");
  const right = groups.slice(bestStart + bestLength).join(":");
  return `${left}::${right}`;
}

async function persistProxySnapshot(directory: string, snapshot: ProxySnapshot): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const destination = snapshotPath(directory);
  const temporary = `${destination}.${process.pid}.${Date.now()}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify({ journalVersion: PROXY_SNAPSHOT_VERSION, ...snapshot }, null, 2)}\n`, "utf8");
    // The journal must reach stable storage before any registry mutation. A
    // successful write buffered only in userspace/OS cache is insufficient for
    // power-loss recovery.
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
  try {
    await handle.close();
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
  try {
    await rename(temporary, destination);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

/** The journal exists but its content cannot be used; I/O failures are not this. */
class ProxyJournalUnreadableError extends Error {}

async function readPersistedProxySnapshot(directory: string): Promise<ProxySnapshot | undefined> {
  const source = snapshotPath(directory);
  let info;
  try {
    info = await stat(source);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  if (info.size > MAX_PROXY_SNAPSHOT_BYTES) {
    throw new ProxyJournalUnreadableError(`Windows proxy recovery journal exceeds ${MAX_PROXY_SNAPSHOT_BYTES} bytes.`);
  }

  return parseProxySnapshotText(await readFile(source, "utf8"));
}

function parseProxySnapshotText(text: string): ProxySnapshot {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new ProxyJournalUnreadableError(`Windows proxy recovery journal is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!isRecord(parsed) || Array.isArray(parsed)) {
    throw new ProxyJournalUnreadableError("Windows proxy recovery journal must contain an object.");
  }
  if (parsed.journalVersion !== undefined && parsed.journalVersion !== PROXY_SNAPSHOT_VERSION) {
    throw new ProxyJournalUnreadableError(`Unsupported Windows proxy recovery journal version ${String(parsed.journalVersion)}.`);
  }
  if (parsed.journalVersion === undefined) {
    const legacyKeys = new Set(["proxyEnable", "proxyServer", "proxyOverride", "autoConfigUrl", "autoDetect"]);
    if (Object.keys(parsed).some((key) => !legacyKeys.has(key))) {
      throw new ProxyJournalUnreadableError("Legacy Windows proxy recovery journal contains unknown fields.");
    }
  }
  const expandStrings = readSnapshotExpandStrings(parsed);
  return {
    proxyEnable: readSnapshotDword(parsed, "proxyEnable"),
    proxyServer: readSnapshotString(parsed, "proxyServer"),
    proxyOverride: readSnapshotString(parsed, "proxyOverride"),
    autoConfigUrl: readSnapshotString(parsed, "autoConfigUrl"),
    autoDetect: readSnapshotDword(parsed, "autoDetect"),
    ...(expandStrings ? { expandStrings } : {})
  };
}

/**
 * Reads the journal, setting an unreadable one aside instead of failing.
 *
 * A downgrade (a newer journal version) or an outside edit used to make every
 * apply, restore and startup recovery throw until the file was deleted by
 * hand, which left routing permanently off. The file is renamed next to itself
 * so it can still be inspected, `onSetAside` gets a notice for the log, and the
 * caller carries on as if there were no journal.
 */
async function readUsableProxySnapshot(
  directory: string,
  onSetAside: (message: string) => void
): Promise<ProxySnapshot | undefined> {
  try {
    return await readPersistedProxySnapshot(directory);
  } catch (error) {
    if (!(error instanceof ProxyJournalUnreadableError)) {
      throw error;
    }
    const stamp = new Date().toISOString().replace(/[:.]/gu, "-");
    const name = `windows-proxy-snapshot.unreadable-${stamp}.json`;
    await rename(snapshotPath(directory), path.join(directory, name));
    onSetAside(
      `Windows proxy recovery journal could not be used (${error.message.replace(/\.$/u, "")}), so it was set aside as ${name}. ` +
        "The proxy settings it held could not be restored; the current Windows proxy settings are kept instead."
    );
    return undefined;
  }
}

function readSnapshotString(snapshot: Record<string, unknown>, name: string): string | undefined {
  const value = snapshot[name];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || value.length > MAX_PROXY_REGISTRY_STRING_LENGTH) {
    throw new ProxyJournalUnreadableError(`Windows proxy recovery journal field ${name} is invalid.`);
  }
  return value;
}

function readSnapshotDword(snapshot: Record<string, unknown>, name: string): string | undefined {
  const value = readSnapshotString(snapshot, name);
  if (value === undefined) {
    return undefined;
  }
  if (!/^(?:0x[0-9a-f]+|\d+)$/iu.test(value)) {
    throw new ProxyJournalUnreadableError(`Windows proxy recovery journal field ${name} is not a DWORD.`);
  }
  const numeric = BigInt(value);
  if (numeric < 0n || numeric > 0xffff_ffffn) {
    throw new ProxyJournalUnreadableError(`Windows proxy recovery journal field ${name} is outside the DWORD range.`);
  }
  return value;
}

function readSnapshotExpandStrings(snapshot: Record<string, unknown>): ProxySnapshotStringField[] | undefined {
  const value = snapshot.expandStrings;
  if (value === undefined) {
    return undefined;
  }
  if (
    !Array.isArray(value) ||
    !value.every((field) => typeof field === "string" && (PROXY_SNAPSHOT_STRING_FIELDS as readonly string[]).includes(field))
  ) {
    throw new ProxyJournalUnreadableError("Windows proxy recovery journal field expandStrings is invalid.");
  }
  return value.length > 0 ? [...new Set(value as ProxySnapshotStringField[])] : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function snapshotPath(directory: string): string {
  return path.join(directory, "windows-proxy-snapshot.json");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
