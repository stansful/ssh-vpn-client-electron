import { execFile } from "node:child_process";
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

export class WindowsSystemProxyManager {
  private snapshot: ProxySnapshot | undefined;
  private readonly pacDirectory: string;
  private readonly pacPath: string;
  private readonly pacServerFactory: (requestListener: RequestListener) => Server;
  private pacServer: Server | undefined;
  private pacContent = "";
  private registeredPacUrl: string | undefined;
  private registeredStaticProxy: string | undefined;
  private operationQueue: Promise<void> = Promise.resolve();

  constructor(options: WindowsSystemProxyOptions = {}) {
    this.pacDirectory = options.pacDirectory ?? defaultPacDirectory();
    this.pacPath = path.join(this.pacDirectory, "shadow-ssh-routing.pac");
    this.pacServerFactory = options.pacServerFactory ?? createServer;
  }

  apply(request: SystemProxyApplyRequest): Promise<SystemProxyApplyResult> {
    return this.enqueueOperation(() => this.applyInternal(request));
  }

  private async applyInternal(request: SystemProxyApplyRequest): Promise<SystemProxyApplyResult> {
    if (process.platform !== "win32") {
      return { applied: false, message: "System proxy was not changed because this platform is not Windows." };
    }
    assertLocalProxyEndpoint(request.socksHost, request.socksPort);

    await this.restorePersistedSnapshot();
    if (!this.snapshot) {
      this.snapshot = await readProxySnapshot();
      await persistProxySnapshot(this.pacDirectory, this.snapshot);
    }

    const proxyDomains = normalizeProxyDomains(request.proxyDomains);
    const directDomains = normalizeProxyDomains(request.directDomains);
    if (request.mode === "proxy-all" && directDomains.length === 0) {
      const staticProxy = buildWindowsProxyServer(request.socksHost, request.socksPort, request.proxyProtocol ?? "mixed");
      if (this.registeredStaticProxy !== staticProxy || Boolean(this.pacServer)) {
        this.registeredStaticProxy = undefined;
        await regAddDword("ProxyEnable", "1");
        await regAddString("ProxyServer", staticProxy);
        await regDeleteValue("AutoConfigURL");
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
    const pacUrl = await this.startPacServer(pac);
    if (this.registeredPacUrl !== pacUrl) {
      this.registeredStaticProxy = undefined;
      await regAddDword("ProxyEnable", "0");
      await regDeleteValue("ProxyServer");
      await regAddDword("AutoDetect", "0");
      await regAddString("AutoConfigURL", pacUrl);
      await refreshWindowsProxy();
      this.registeredPacUrl = pacUrl;
    } else if (pacChanged) {
      // The PAC server and URL remain stable. Only invalidate WinINet's PAC
      // cache; restarting the listener and importing registry state through
      // netsh every 30 seconds caused avoidable connection/setup latency.
      await notifyWindowsProxyChanged();
    }
    const proxyListMessage = proxyDomains.length > 0 ? ` with ${proxyDomains.length} proxy-list domains` : "";
    const directListMessage = directDomains.length > 0 ? ` and ${directDomains.length} direct-list domains` : "";
    return { applied: true, message: `Windows PAC routing enabled for ${request.mode}${proxyListMessage}${directListMessage} through ${request.socksHost}:${request.socksPort} at ${pacUrl}.` };
  }

  restore(): Promise<void> {
    return this.enqueueOperation(() => this.restoreInternal());
  }

  private async restoreInternal(): Promise<void> {
    if (process.platform !== "win32") {
      await this.stopPacServer();
      return;
    }

    const snapshot = this.snapshot ?? (await readPersistedProxySnapshot(this.pacDirectory));
    if (!snapshot) {
      await this.stopPacServer();
      return;
    }

    // Restore and publish the user's registry state while the current PAC is
    // still reachable. Only then retire the PAC endpoint and remove the crash
    // journal. Failed registry writes leave both PAC and snapshot available.
    await restoreValue("ProxyEnable", snapshot.proxyEnable, "REG_DWORD");
    await restoreValue("ProxyServer", snapshot.proxyServer, "REG_SZ");
    await restoreValue("ProxyOverride", snapshot.proxyOverride, "REG_SZ");
    await restoreValue("AutoConfigURL", snapshot.autoConfigUrl, "REG_SZ");
    await restoreValue("AutoDetect", snapshot.autoDetect, "REG_DWORD");
    await refreshWindowsProxy();
    await this.stopPacServer();
    this.snapshot = undefined;
    this.registeredPacUrl = undefined;
    this.registeredStaticProxy = undefined;
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

  private async startPacServer(pac: string): Promise<string> {
    this.pacContent = pac;
    if (this.pacServer) {
      const currentAddress = this.pacServer.address();
      if (isAddressInfo(currentAddress)) {
        return `http://127.0.0.1:${currentAddress.port}/shadow-ssh-routing.pac`;
      }
      await this.stopPacServer();
      this.pacContent = pac;
    }
    const server = this.pacServerFactory((request, response) => {
      const requestPath = (request.url ?? "").split("?")[0];
      if (requestPath !== "/shadow-ssh-routing.pac") {
        response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        response.end("Not found");
        return;
      }
      response.writeHead(200, {
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Content-Type": "application/x-ns-proxy-autoconfig; charset=utf-8",
        Pragma: "no-cache"
      });
      response.end(this.pacContent);
    });
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
        await this.restoreInternal();
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
      throw error;
    }

    const address = server.address();
    if (!isAddressInfo(address)) {
      await closeServer(server);
      throw new Error("PAC server did not bind a TCP address.");
    }
    this.pacServer = server;
    return `http://127.0.0.1:${address.port}/shadow-ssh-routing.pac`;
  }

  private async stopPacServer(): Promise<void> {
    const server = this.pacServer;
    if (!server) {
      return;
    }
    this.pacServer = undefined;
    await closeServer(server);
    this.pacContent = "";
    this.registeredPacUrl = undefined;
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
  const ipRules = validRules.filter((rule) => rule.type === "ip").map((rule) => rule.value.trim());
  const directListDomains = normalizeProxyDomains(options.directDomains).map(normalizeSuffixDomain);
  const proxyListDomains = normalizeProxyDomains(options.proxyDomains).map(normalizeSuffixDomain);
  const exactDomainRules = domainRules.filter((rule) => !rule.startsWith("*.")).map((rule) => rule);
  const wildcardDomainRules = domainRules.filter((rule) => rule.startsWith("*.")).map((rule) => rule.slice(2));
  const ipChecks = ipRules.flatMap((rule) => buildIpChecks(rule));
  const parsedIpRules = ipRules.map(parseCidrRange).filter((range): range is NonNullable<ReturnType<typeof parseCidrRange>> => Boolean(range));
  const needsIpv4Dns = parsedIpRules.some((range) => range.version === 4);
  const needsIpv6Dns = parsedIpRules.some((range) => range.version === 6);
  const domainCheck = [
    "hasOwn(proxyExactDomains, hostNoBrackets)",
    "matchesSubdomain(hostNoBrackets, proxyWildcardDomains)",
    "matchesDomainOrParent(hostNoBrackets, proxyListDomains)"
  ].join(" || ");
  const checks = [domainCheck, ...ipChecks].filter(Boolean);

  const mode = options.mode ?? "selected-rules";
  const proxyRule = mode === "proxy-all"
    ? `  return ${JSON.stringify(proxy)};`
    : checks.length > 0
      ? `  if (${checks.join(" || ")}) { return ${JSON.stringify(proxy)}; }`
      : "  if (false) { return \"DIRECT\"; }";

  return [
    "// Shadow SSH routing PAC. Generated by the desktop client.",
    `var directDomains = ${domainLookupLiteral(directListDomains)};`,
    `var proxyListDomains = ${domainLookupLiteral(proxyListDomains)};`,
    `var proxyExactDomains = ${domainLookupLiteral(exactDomainRules)};`,
    `var proxyWildcardDomains = ${domainLookupLiteral(wildcardDomainRules)};`,
    "function FindProxyForURL(url, host) {",
    "  host = String(host || \"\").toLowerCase();",
    "  var hostNoBrackets = host.replace(/^\\[/, \"\").replace(/\\]$/, \"\");",
    "  if (matchesDomainOrParent(hostNoBrackets, directDomains)) { return \"DIRECT\"; }",
    needsIpv4Dns ? "  var resolvedHost = resolveIpv4(hostNoBrackets);" : "  var resolvedHost = hostNoBrackets;",
    needsIpv6Dns ? "  var resolvedHostEx = resolveAll(hostNoBrackets);" : "  var resolvedHostEx = \"\";",
    proxyRule,
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
    ...(needsIpv4Dns
      ? [
          "function resolveIpv4(host) {",
          "  try {",
          "    var value = dnsResolve(host);",
          "    return value ? String(value).toLowerCase() : host;",
          "  } catch (e) { return host; }",
          "}"
        ]
      : []),
    ...(needsIpv6Dns
      ? [
          "function resolveAll(host) {",
          "  try {",
          "    var value = typeof dnsResolveEx === \"function\" ? String(dnsResolveEx(host) || \"\").toLowerCase() : \"\";",
          "    return value || host;",
          "  } catch (e) { return host; }",
          "}",
          "function resolvedContains(values, expected) {",
          "  var entries = String(values || \"\").split(/[;,\\s]+/);",
          "  for (var index = 0; index < entries.length; index += 1) {",
          "    if (entries[index] == expected) { return true; }",
          "  }",
          "  return false;",
          "}",
          "function resolvedIsInNetEx(values, range) {",
          "  if (typeof isInNetEx !== \"function\") { return false; }",
          "  var entries = String(values || \"\").split(/[;,\\s]+/);",
          "  for (var index = 0; index < entries.length; index += 1) {",
          "    if (entries[index] && isInNetEx(entries[index], range)) { return true; }",
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
      "if (-not ($settingsChanged -and $settingsRefreshed)) { throw 'WinINet proxy refresh failed.' }"
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
  if (proxyProtocol === "http") {
    return `PROXY ${endpoint}`;
  }
  if (proxyProtocol === "socks") {
    return `SOCKS5 ${endpoint}; SOCKS ${endpoint}`;
  }
  return `PROXY ${endpoint}; SOCKS5 ${endpoint}; SOCKS ${endpoint}`;
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

function buildIpChecks(rule: string): string[] {
  const range = parseCidrRange(rule);
  if (!range) {
    return [];
  }

  const [ip] = rule.split("/");
  const normalizedIp = (ip ?? "").trim().toLowerCase();
  if (range.version === 4) {
    const networkIp = ipv4BigIntToDotted(range.network);
    const directChecks = [
      `hostNoBrackets == ${JSON.stringify(normalizedIp)}`,
      `resolvedHost == ${JSON.stringify(normalizedIp)}`
    ];
    if (range.prefixLength === 32) {
      return [`(${directChecks.join(" || ")})`];
    }
    return [
      `isInNet(resolvedHost, ${JSON.stringify(networkIp)}, ${JSON.stringify(prefixToMask(range.prefixLength))})`
    ];
  }

  const ipv6Checks = [
    `hostNoBrackets == ${JSON.stringify(normalizedIp)}`,
    `resolvedContains(resolvedHostEx, ${JSON.stringify(normalizedIp)})`
  ];
  const canonicalRange = `${ipv6BigIntToString(range.network)}/${range.prefixLength}`;
  if (range.prefixLength === 128) {
    // Text equality is only a fast path: equivalent IPv6 spellings can differ
    // through zero compression or leading zeroes. isInNetEx performs the
    // address-aware /128 comparison for both literal and resolved hosts.
    return [
      `(${ipv6Checks.join(" || ")} || resolvedIsInNetEx(resolvedHostEx, ${JSON.stringify(canonicalRange)}))`
    ];
  }
  return [
    `resolvedIsInNetEx(resolvedHostEx, ${JSON.stringify(canonicalRange)})`
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
