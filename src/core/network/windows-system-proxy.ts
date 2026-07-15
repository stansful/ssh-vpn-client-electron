import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer, type RequestListener, type Server } from "node:http";
import { mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import type { RoutingMode, RoutingRule } from "../../shared/types.js";
import { validateRoutingRuleValue } from "../../shared/validation.js";
import { normalizeProxyDomain } from "../routing/domain-proxy-list.js";
import { parseCidrRange } from "../routing/ip-address.js";

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
}

export async function recoverWindowsSystemProxy(pacDirectories: string[]): Promise<boolean> {
  if (process.platform !== "win32") {
    return false;
  }
  const candidates = (
    await Promise.all(
      [...new Set(pacDirectories)].map(async (directory) => {
        const snapshot = await readPersistedProxySnapshot(directory);
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
  await new WindowsSystemProxyManager({ pacDirectory: original.directory }).restore();
  return true;
}

interface ProxySnapshot {
  proxyEnable?: string;
  proxyServer?: string;
  proxyOverride?: string;
  autoConfigUrl?: string;
  autoDetect?: string;
}

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

  constructor(options: WindowsSystemProxyOptions = {}) {
    this.pacDirectory = options.pacDirectory ?? defaultPacDirectory();
    this.pacPath = path.join(this.pacDirectory, "shadow-ssh-routing.pac");
    this.pacServerFactory = options.pacServerFactory ?? createServer;
  }

  apply(request: SystemProxyApplyRequest): Promise<SystemProxyApplyResult> {
    return this.enqueueOperation(async () => {
      try {
        const result = await this.applyInternal(request);
        this.proxyStateDirty = false;
        return result;
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
      const snapshot = await readProxySnapshot();
      await persistProxySnapshot(this.pacDirectory, snapshot);
      this.snapshot = snapshot;
    }

    const proxyDomains = normalizeProxyDomains(request.proxyDomains);
    const directDomains = normalizeProxyDomains(request.directDomains);
    if (request.mode === "proxy-all" && directDomains.length === 0) {
      const staticProxy = buildWindowsProxyServer(request.socksHost, request.socksPort, request.proxyProtocol ?? "mixed");
      if (this.proxyStateDirty || this.registeredStaticProxy !== staticProxy || Boolean(this.pacServer)) {
        this.registeredStaticProxy = undefined;
        await regAddDword("ProxyEnable", "1");
        await regAddString("ProxyServer", staticProxy);
        await regDeleteValue("AutoConfigURL");
        // ProxyOverride belongs to the previous user configuration. Leaving a
        // broad value such as `*` active would silently bypass Shadow's static
        // proxy-all endpoint even though ProxyEnable and ProxyServer are set.
        // The persisted snapshot restores the exact prior value on disconnect.
        await regDeleteValue("ProxyOverride");
        this.registryPacUrl = undefined;
        this.pendingPacNotificationUrl = undefined;
        await regAddDword("AutoDetect", "0");
        await refreshWindowsProxy();
        this.registeredStaticProxy = staticProxy;
      }
      // Keep the old PAC endpoint alive until WinINet has successfully switched
      // to the static proxy. A registry failure must not leave AutoConfigURL
      // pointing at a listener we already stopped.
      await this.stopPacServer();
      this.registeredPacUrl = undefined;
      return { applied: true, message: `Windows system HTTP/SOCKS proxy enabled at ${request.socksHost}:${request.socksPort}.` };
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

    const snapshot = this.snapshot ?? (await readPersistedProxySnapshot(this.pacDirectory));
    if (!snapshot) {
      await this.stopPacServer();
      this.proxyStateDirty = false;
      return;
    }

    // Restore and publish the user's registry state while the current PAC is
    // still reachable. Only then retire the PAC endpoint and remove the crash
    // journal. Failed registry writes leave both PAC and snapshot available.
    await restoreValue("ProxyEnable", snapshot.proxyEnable, "REG_DWORD");
    await restoreValue("ProxyServer", snapshot.proxyServer, "REG_SZ");
    await restoreValue("ProxyOverride", snapshot.proxyOverride, "REG_SZ");
    await restoreValue("AutoConfigURL", snapshot.autoConfigUrl, "REG_SZ");
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
    const snapshot = await readPersistedProxySnapshot(this.pacDirectory);
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
  const exactDomainRules = domainRules.filter((rule) => !rule.startsWith("*.")).map((rule) => rule);
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
      rule: value
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
  const resolvedExactIpRules = dnsIpRules
    .filter(({ range }) => range.prefixLength === (range.version === 4 ? 32 : 128))
    .map(({ range }) => range.version === 4 ? ipv4BigIntToDotted(range.network) : ipv6BigIntToString(range.network));
  const ipChecks = dnsIpRules.flatMap(({ rule }) => buildIpChecks(rule));
  const mode = options.mode ?? "selected-rules";
  const needsIpv4Dns = mode !== "proxy-all" && dnsIpRules.some(({ range }) => range.version === 4);
  const needsExtendedDns = mode !== "proxy-all" && dnsIpRules.length > 0;
  const domainCheck = [
    "hasOwn(proxyExactDomains, hostNoBrackets)",
    "matchesSubdomain(hostNoBrackets, proxyWildcardDomains)",
    "matchesDomainOrParent(hostNoBrackets, proxyListDomains)"
  ].join(" || ");
  const literalIpCheck = exactIpRules.length > 0 ? "hasOwn(proxyExactIps, hostNoBrackets)" : "";
  const exactIpCheck = resolvedExactIpRules.length > 0
    ? "hasOwn(proxyResolvedExactIps, resolvedHost) || resolvedHasOwn(resolvedHosts, proxyResolvedExactIps)"
    : "";
  const resolvedIpCheck = [exactIpCheck, ...ipChecks].filter(Boolean).join(" || ");
  const preDnsCheck = [domainCheck, literalIpCheck].filter(Boolean).join(" || ");
  const preDnsProxyRule = mode === "proxy-all"
    ? `  return ${JSON.stringify(proxy)};`
    : `  if (${preDnsCheck}) { return ${JSON.stringify(proxy)}; }`;
  const postDnsProxyRule = mode !== "proxy-all" && resolvedIpCheck
    ? `  if (${resolvedIpCheck}) { return ${JSON.stringify(proxy)}; }`
    : undefined;

  return [
    "// Shadow SSH routing PAC. Generated by the desktop client.",
    `var directDomains = ${domainLookupLiteral(directListDomains)};`,
    `var proxyListDomains = ${domainLookupLiteral(proxyListDomains)};`,
    `var proxyExactDomains = ${domainLookupLiteral(exactDomainRules)};`,
    `var proxyWildcardDomains = ${domainLookupLiteral(wildcardDomainRules)};`,
    `var proxyExactIps = ${domainLookupLiteral(exactIpRules)};`,
    `var proxyResolvedExactIps = ${domainLookupLiteral(resolvedExactIpRules)};`,
    ...(needsExtendedDns
      ? [
          "var resolvedHostCache = {};",
          "var resolvedHostCacheOrder = [];",
          "var resolvedHostCacheLimit = 256;"
        ]
      : []),
    "function FindProxyForURL(url, host) {",
    "  host = String(host || \"\").toLowerCase();",
    "  var hostNoBrackets = host.replace(/^\\[/, \"\").replace(/\\]$/, \"\");",
    "  if (matchesDomainOrParent(hostNoBrackets, directDomains)) { return \"DIRECT\"; }",
    preDnsProxyRule,
    needsExtendedDns ? "  var resolvedHosts = resolveHosts(hostNoBrackets);" : "  var resolvedHosts = [];",
    needsIpv4Dns ? "  var resolvedHost = firstIpv4OrHost(resolvedHosts, hostNoBrackets);" : "  var resolvedHost = hostNoBrackets;",
    ...(postDnsProxyRule ? [postDnsProxyRule] : []),
    "  return \"DIRECT\";",
    "}",
    "function hasOwn(map, key) {",
    "  return Object.prototype.hasOwnProperty.call(map, key);",
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
  return {
    proxyEnable: await regQueryValue("ProxyEnable"),
    proxyServer: await regQueryValue("ProxyServer"),
    proxyOverride: await regQueryValue("ProxyOverride"),
    autoConfigUrl: await regQueryValue("AutoConfigURL"),
    autoDetect: await regQueryValue("AutoDetect")
  };
}

async function restoreValue(name: string, value: string | undefined, type: "REG_DWORD" | "REG_SZ"): Promise<void> {
  if (value === undefined) {
    await regDeleteValue(name);
    return;
  }
  if (type === "REG_DWORD") {
    await regAddDword(name, value);
  } else {
    await regAddString(name, value);
  }
}

async function regQueryValue(name: string): Promise<string | undefined> {
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
  const match = result.stdout.match(new RegExp(`${escapeRegExp(name)}\\s+REG_(?:SZ|DWORD)\\s+(.+)`, "iu"));
  if (!match) {
    throw new Error(`reg.exe returned an unsupported value format for ${name}.`);
  }
  return match[1].trim();
}

async function regAddString(name: string, value: string): Promise<void> {
  await execFileChecked("reg.exe", ["add", internetSettingsKey(), "/v", name, "/t", "REG_SZ", "/d", value, "/f"]);
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
  const userData = process.env.SHADOW_SSH_USER_DATA_DIR || path.join(appData, "Shadow SSH");
  return path.join(userData, "routing");
}

function buildWindowsProxyServer(host: string, port: number, proxyProtocol: "mixed" | "http" | "socks"): string {
  const endpoint = formatProxyEndpoint(host, port);
  if (proxyProtocol === "http") {
    return `http=${endpoint};https=${endpoint}`;
  }
  if (proxyProtocol === "socks") {
    return `socks=${endpoint}`;
  }
  return `http=${endpoint};https=${endpoint};socks=${endpoint}`;
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
    throw new Error(`Windows proxy recovery journal exceeds ${MAX_PROXY_SNAPSHOT_BYTES} bytes.`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(source, "utf8"));
  } catch (error) {
    throw new Error(`Windows proxy recovery journal is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!isRecord(parsed) || Array.isArray(parsed)) {
    throw new Error("Windows proxy recovery journal must contain an object.");
  }
  if (parsed.journalVersion !== undefined && parsed.journalVersion !== PROXY_SNAPSHOT_VERSION) {
    throw new Error(`Unsupported Windows proxy recovery journal version ${String(parsed.journalVersion)}.`);
  }
  if (parsed.journalVersion === undefined) {
    const legacyKeys = new Set(["proxyEnable", "proxyServer", "proxyOverride", "autoConfigUrl", "autoDetect"]);
    if (Object.keys(parsed).some((key) => !legacyKeys.has(key))) {
      throw new Error("Legacy Windows proxy recovery journal contains unknown fields.");
    }
  }
  return {
    proxyEnable: readSnapshotDword(parsed, "proxyEnable"),
    proxyServer: readSnapshotString(parsed, "proxyServer"),
    proxyOverride: readSnapshotString(parsed, "proxyOverride"),
    autoConfigUrl: readSnapshotString(parsed, "autoConfigUrl"),
    autoDetect: readSnapshotDword(parsed, "autoDetect")
  };
}

function readSnapshotString(snapshot: Record<string, unknown>, name: string): string | undefined {
  const value = snapshot[name];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || value.length > MAX_PROXY_REGISTRY_STRING_LENGTH) {
    throw new Error(`Windows proxy recovery journal field ${name} is invalid.`);
  }
  return value;
}

function readSnapshotDword(snapshot: Record<string, unknown>, name: string): string | undefined {
  const value = readSnapshotString(snapshot, name);
  if (value === undefined) {
    return undefined;
  }
  if (!/^(?:0x[0-9a-f]+|\d+)$/iu.test(value)) {
    throw new Error(`Windows proxy recovery journal field ${name} is not a DWORD.`);
  }
  const numeric = BigInt(value);
  if (numeric < 0n || numeric > 0xffff_ffffn) {
    throw new Error(`Windows proxy recovery journal field ${name} is outside the DWORD range.`);
  }
  return value;
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
