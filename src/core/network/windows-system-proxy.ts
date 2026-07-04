import { execFile } from "node:child_process";
import { createServer, type Server } from "node:http";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import type { RoutingMode, RoutingRule } from "../../shared/types.js";
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
}

interface ProxySnapshot {
  proxyEnable?: string;
  proxyServer?: string;
  proxyOverride?: string;
  autoConfigUrl?: string;
  autoDetect?: string;
}

export class WindowsSystemProxyManager {
  private snapshot: ProxySnapshot | undefined;
  private readonly pacDirectory: string;
  private readonly pacPath: string;
  private pacServer: Server | undefined;

  constructor(options: WindowsSystemProxyOptions = {}) {
    this.pacDirectory = options.pacDirectory ?? defaultPacDirectory();
    this.pacPath = path.join(this.pacDirectory, "shadow-ssh-routing.pac");
  }

  async apply(request: SystemProxyApplyRequest): Promise<SystemProxyApplyResult> {
    if (process.platform !== "win32") {
      return { applied: false, message: "System proxy was not changed because this platform is not Windows." };
    }

    await this.restorePersistedSnapshot();
    this.snapshot ??= await readProxySnapshot();
    await persistProxySnapshot(this.pacDirectory, this.snapshot);

    const proxyDomains = normalizeProxyDomains(request.proxyDomains);
    const directDomains = normalizeProxyDomains(request.directDomains);
    if (request.mode === "proxy-all" && directDomains.length === 0) {
      await this.stopPacServer();
      await regAddDword("ProxyEnable", "1");
      await regAddString("ProxyServer", buildWindowsProxyServer(request.socksHost, request.socksPort, request.proxyProtocol ?? "mixed"));
      await regDeleteValue("AutoConfigURL");
      await regAddDword("AutoDetect", "0");
      await refreshWindowsProxy();
      return { applied: true, message: `Windows system HTTP/SOCKS proxy enabled at ${request.socksHost}:${request.socksPort}.` };
    }

    const pac = buildProxyPac(request.rules, request.socksHost, request.socksPort, request.proxyProtocol ?? "mixed", {
      proxyDomains,
      directDomains,
      mode: request.mode
    });
    await mkdir(this.pacDirectory, { recursive: true });
    await writeFile(this.pacPath, pac, "utf8");
    const pacUrl = await this.startPacServer(pac);
    await regAddDword("ProxyEnable", "0");
    await regDeleteValue("ProxyServer");
    await regAddDword("AutoDetect", "0");
    await regAddString("AutoConfigURL", pacUrl);
    await refreshWindowsProxy();
    const proxyListMessage = proxyDomains.length > 0 ? ` with ${proxyDomains.length} proxy-list domains` : "";
    const directListMessage = directDomains.length > 0 ? ` and ${directDomains.length} direct-list domains` : "";
    return { applied: true, message: `Windows PAC routing enabled for ${request.mode}${proxyListMessage}${directListMessage} through ${request.socksHost}:${request.socksPort} at ${pacUrl}.` };
  }

  async restore(): Promise<void> {
    await this.stopPacServer();
    if (process.platform !== "win32") {
      return;
    }

    const snapshot = this.snapshot ?? (await readPersistedProxySnapshot(this.pacDirectory));
    if (!snapshot) {
      return;
    }

    await restoreValue("ProxyEnable", snapshot.proxyEnable, "REG_DWORD");
    await restoreValue("ProxyServer", snapshot.proxyServer, "REG_SZ");
    await restoreValue("ProxyOverride", snapshot.proxyOverride, "REG_SZ");
    await restoreValue("AutoConfigURL", snapshot.autoConfigUrl, "REG_SZ");
    await restoreValue("AutoDetect", snapshot.autoDetect, "REG_DWORD");
    await refreshWindowsProxy();
    this.snapshot = undefined;
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
    await this.restore();
  }

  private async startPacServer(pac: string): Promise<string> {
    await this.stopPacServer();
    const server = createServer((request, response) => {
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
      response.end(pac);
    });
    server.on("clientError", (_error, socket) => {
      socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });

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
  const domainRules = rules.filter((rule) => rule.enabled && rule.type === "domain").map((rule) => normalizeDomainRule(rule.value));
  const ipRules = rules.filter((rule) => rule.enabled && rule.type === "ip").map((rule) => rule.value.trim()).filter(Boolean);
  const directListChecks = normalizeProxyDomains(options.directDomains).flatMap((domain) => buildDomainProxyChecks(domain));
  const proxyListChecks = normalizeProxyDomains(options.proxyDomains).flatMap((domain) => buildDomainProxyChecks(domain));

  const domainChecks = domainRules.flatMap((rule) => {
    if (rule.startsWith("*.")) {
      const suffix = rule.slice(1);
      return [`dnsDomainIs(hostNoBrackets, ${JSON.stringify(suffix)})`];
    }
    return [`hostNoBrackets == ${JSON.stringify(rule)}`, `dnsDomainIs(hostNoBrackets, ${JSON.stringify(`.${rule}`)})`];
  });
  const ipChecks = ipRules.flatMap((rule) => buildIpChecks(rule));
  const checks = [...proxyListChecks, ...domainChecks, ...ipChecks].filter(Boolean);

  const mode = options.mode ?? "selected-rules";
  const proxyRule = mode === "proxy-all"
    ? `  return ${JSON.stringify(proxy)};`
    : checks.length > 0
      ? `  if (${checks.join(" || ")}) { return ${JSON.stringify(proxy)}; }`
      : "  if (false) { return \"DIRECT\"; }";

  return [
    "// Shadow SSH routing PAC. Generated by the desktop client.",
    "function FindProxyForURL(url, host) {",
    "  host = String(host || \"\").toLowerCase();",
    "  var hostNoBrackets = host.replace(/^\\[/, \"\").replace(/\\]$/, \"\");",
    "  var resolvedHost = hostNoBrackets;",
    "  try {",
    "    var dnsHost = dnsResolve(hostNoBrackets);",
    "    if (dnsHost) { resolvedHost = String(dnsHost).toLowerCase(); }",
    "  } catch (e) {}",
    "  var resolvedHostEx = \"\";",
    "  try {",
    "    if (typeof dnsResolveEx === \"function\") { resolvedHostEx = String(dnsResolveEx(hostNoBrackets) || \"\").toLowerCase(); }",
    "  } catch (e) {}",
    directListChecks.length > 0 ? `  if (${directListChecks.join(" || ")}) { return "DIRECT"; }` : "  if (false) { return \"DIRECT\"; }",
    proxyRule,
    "  return \"DIRECT\";",
    "}",
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
    return undefined;
  }
  const match = result.stdout.match(new RegExp(`${escapeRegExp(name)}\\s+REG_(?:SZ|DWORD)\\s+(.+)`, "iu"));
  if (!match) {
    return undefined;
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
  await execFileSafe("reg.exe", ["delete", internetSettingsKey(), "/v", name, "/f"]);
}

async function refreshWindowsProxy(): Promise<void> {
  await execFileSafe("netsh.exe", ["winhttp", "import", "proxy", "source=ie"]);
  await execFileSafe("powershell.exe", [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    [
      "$ErrorActionPreference='SilentlyContinue'",
      "Add-Type -Namespace ShadowSsh -Name WinInet -MemberDefinition '[System.Runtime.InteropServices.DllImport(\"wininet.dll\", SetLastError=true)] public static extern bool InternetSetOption(System.IntPtr hInternet, int dwOption, System.IntPtr lpBuffer, int dwBufferLength);'",
      "[ShadowSsh.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null",
      "[ShadowSsh.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null"
    ].join("; ")
  ]);
}

async function execFileChecked(command: string, args: string[]): Promise<void> {
  const result = await execFileSafe(command, args);
  if (result.exitCode !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.stderr || result.stdout}`.trim());
  }
}

async function execFileSafe(command: string, args: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(command, args, { windowsHide: true }, (error, stdout, stderr) => {
      const errorCode = (error as NodeJS.ErrnoException | null)?.code;
      resolve({
        exitCode: typeof errorCode === "number" ? errorCode : error ? 1 : 0,
        stdout,
        stderr
      });
    });
  });
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
  const endpoint = `${host}:${port}`;
  if (proxyProtocol === "http") {
    return `http=${endpoint};https=${endpoint}`;
  }
  if (proxyProtocol === "socks") {
    return `socks=${endpoint}`;
  }
  return `http=${endpoint};https=${endpoint};socks=${endpoint}`;
}

function buildPacProxyReturn(host: string, port: number, proxyProtocol: "mixed" | "http" | "socks"): string {
  const endpoint = `${host}:${port}`;
  if (proxyProtocol === "http") {
    return `PROXY ${endpoint}`;
  }
  if (proxyProtocol === "socks") {
    return `SOCKS5 ${endpoint}; SOCKS ${endpoint}`;
  }
  return `PROXY ${endpoint}; SOCKS5 ${endpoint}; SOCKS ${endpoint}`;
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
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
  return [...new Set(domains.map((domain) => domain.trim().toLowerCase()).filter(Boolean))];
}

function buildDomainProxyChecks(domain: string): string[] {
  if (domain.startsWith(".")) {
    const root = domain.slice(1);
    return [`hostNoBrackets == ${JSON.stringify(root)}`, `dnsDomainIs(hostNoBrackets, ${JSON.stringify(domain)})`];
  }
  if (domain.startsWith("*.")) {
    const suffix = domain.slice(1);
    const root = suffix.slice(1);
    return [`hostNoBrackets == ${JSON.stringify(root)}`, `dnsDomainIs(hostNoBrackets, ${JSON.stringify(suffix)})`];
  }
  return [`hostNoBrackets == ${JSON.stringify(domain)}`, `dnsDomainIs(hostNoBrackets, ${JSON.stringify(`.${domain}`)})`];
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
      `resolvedHost == ${JSON.stringify(normalizedIp)}`,
      `resolvedHostEx.indexOf(${JSON.stringify(normalizedIp)}) >= 0`
    ];
    if (range.prefixLength === 32) {
      return [`(${directChecks.join(" || ")})`];
    }
    return [
      `isInNet(hostNoBrackets, ${JSON.stringify(networkIp)}, ${JSON.stringify(prefixToMask(range.prefixLength))})`,
      `isInNet(resolvedHost, ${JSON.stringify(networkIp)}, ${JSON.stringify(prefixToMask(range.prefixLength))})`
    ];
  }

  const ipv6Checks = [
    `hostNoBrackets == ${JSON.stringify(normalizedIp)}`,
    `resolvedHost == ${JSON.stringify(normalizedIp)}`,
    `resolvedHostEx.indexOf(${JSON.stringify(normalizedIp)}) >= 0`
  ];
  if (range.prefixLength === 128) {
    return [`(${ipv6Checks.join(" || ")})`];
  }
  return [
    `(typeof isInNetEx === "function" && (isInNetEx(hostNoBrackets, ${JSON.stringify(`${normalizedIp}/${range.prefixLength}`)}) || isInNetEx(resolvedHost, ${JSON.stringify(`${normalizedIp}/${range.prefixLength}`)})))`
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

async function persistProxySnapshot(directory: string, snapshot: ProxySnapshot): Promise<void> {
  await mkdir(directory, { recursive: true });
  await writeFile(snapshotPath(directory), `${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
}

async function readPersistedProxySnapshot(directory: string): Promise<ProxySnapshot | undefined> {
  try {
    const parsed = JSON.parse(await readFile(snapshotPath(directory), "utf8")) as Partial<ProxySnapshot>;
    return {
      proxyEnable: typeof parsed.proxyEnable === "string" ? parsed.proxyEnable : undefined,
      proxyServer: typeof parsed.proxyServer === "string" ? parsed.proxyServer : undefined,
      proxyOverride: typeof parsed.proxyOverride === "string" ? parsed.proxyOverride : undefined,
      autoConfigUrl: typeof parsed.autoConfigUrl === "string" ? parsed.autoConfigUrl : undefined,
      autoDetect: typeof parsed.autoDetect === "string" ? parsed.autoDetect : undefined
    };
  } catch {
    return undefined;
  }
}

function snapshotPath(directory: string): string {
  return path.join(directory, "windows-proxy-snapshot.json");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
