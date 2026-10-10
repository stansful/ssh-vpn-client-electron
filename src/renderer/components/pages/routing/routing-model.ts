import { normalizeProxyDomain } from "../../../../core/routing/domain-proxy-list.js";
import {
  isValidIpv4,
  isValidIpv6,
  normalizeRuleValue,
  validateDomainPattern,
  validateRoutingRuleValue
} from "../../../../shared/validation.js";
import type {
  ConnectionState,
  DesktopPlatform,
  RoutingDirectList,
  RoutingMode,
  RoutingProxyList,
  RoutingRule,
  RoutingRuleType,
  TunStatus
} from "../../../../shared/types.js";
import { formatCount, formatDay, formatTime, plural } from "../../../lib/format.js";
import { stripIpcPrefix } from "../../../lib/errors.js";
import type { RoutingTab } from "../../../types.js";

export const TAB_RULE_TYPE: Record<RoutingTab, RoutingRuleType> = {
  domains: "domain",
  ips: "ip",
  apps: "process.name"
};

/** Rules render 200 at a time; "Show more" adds the next 200. */
export const RULE_PAGE_SIZE = 200;
/** The running-apps picker shows the first 80 matches. */
export const MAX_PROCESS_CHIPS = 80;

export type ListKind = "proxy" | "direct";
export type DomainList = Pick<RoutingProxyList | RoutingDirectList, "enabled" | "domains" | "updatedAt">;

const LIST_NAMES: Record<ListKind, string> = { proxy: "Blocked in Russia", direct: "Russian services" };

/** Where both lists come from (itdoginfo/allow-domains on GitHub). */
export const LIST_SOURCE_LABEL = "itdoginfo/allow-domains · Russia";

export function listName(kind: ListKind): string {
  return LIST_NAMES[kind];
}

/** Rules and lists only steer system traffic on Windows; elsewhere apps must use the local proxy. */
export function steersSystemTraffic(platform: DesktopPlatform): boolean {
  return platform === "windows" || platform === "unknown";
}

/** A session exists (or is being built), so routing changes reach it right away. */
export function isLiveSession(state: ConnectionState): boolean {
  return state === "Connecting" || state === "Connected" || state === "Reconnecting";
}

export interface ConnectionBadge {
  tone: "neutral" | "ok" | "busy" | "warn" | "danger";
  text: string;
  spinner: boolean;
}

/** The badge on the Mode card: what the active tunnel is doing, or that routing blocks Connect. */
export function connectionBadge(input: {
  state: ConnectionState;
  preview: boolean;
  platform: DesktopPlatform;
  targetName?: string;
  blocked: boolean;
}): ConnectionBadge {
  const suffix = input.targetName ? ` · ${input.targetName}` : "";
  switch (input.state) {
    case "Connected":
      if (input.preview) {
        return { tone: "warn", text: `Preview only${suffix}`, spinner: false };
      }
      return { tone: "ok", text: `${steersSystemTraffic(input.platform) ? "Protected" : "Proxy ready"}${suffix}`, spinner: false };
    case "Connecting":
      return { tone: "busy", text: "Connecting…", spinner: true };
    case "Reconnecting":
      return { tone: "busy", text: "Reconnecting…", spinner: true };
    case "Disconnecting":
      return { tone: "busy", text: "Disconnecting…", spinner: true };
    case "Error":
      return { tone: "danger", text: "Needs attention", spinner: false };
    default:
      return input.blocked ? { tone: "warn", text: "Blocked by routing", spinner: false } : { tone: "neutral", text: "Not connected", spinner: false };
  }
}

/* ---------- Per-tab copy ---------- */

export interface TabCopy {
  type: RoutingRuleType;
  one: string;
  many: string;
  tag: string;
  addLabel: string;
  placeholder: string;
  hint: string;
  search: string;
  listLabel: string;
  emptyTitle: string;
  emptyText: string;
}

export function tabCopy(tab: RoutingTab, platform: DesktopPlatform): TabCopy {
  if (tab === "ips") {
    return {
      type: "ip",
      one: "IP rule",
      many: "IP rules",
      tag: "IP",
      addLabel: "Add an IP address or range",
      placeholder: "8.8.8.8 or 2a00:1450::/32",
      hint: "One address or a CIDR range, IPv4 or IPv6.",
      search: "Search IPs",
      listLabel: "IP rules",
      emptyTitle: "No IP rules yet",
      emptyText: "Add an address or a range above, like 8.8.8.8 or 10.0.0.0/8."
    };
  }
  if (tab === "apps") {
    const hint =
      platform === "macos"
        ? "The app name as macOS reports it. Names with brackets aren’t supported."
        : platform === "linux"
          ? "The process name as Linux reports it. Names with brackets aren’t supported."
          : "File name only, not a path. chrome and chrome.exe match the same app.";
    return {
      type: "process.name",
      one: "app rule",
      many: "app rules",
      tag: "App",
      addLabel: "Add an app",
      placeholder: platform === "macos" ? "Telegram" : platform === "linux" ? "telegram-desktop" : "telegram.exe",
      hint,
      search: "Search apps",
      listLabel: "App rules",
      emptyTitle: "No app rules yet",
      emptyText: platform === "windows" || platform === "unknown"
        ? "Pick a running app or type its file name above."
        : "Pick a running app or type its name above."
    };
  }
  return {
    type: "domain",
    one: "domain",
    many: "domains",
    tag: "Domain",
    addLabel: "Add a domain",
    placeholder: "youtube.com or *.youtube.com",
    hint: "youtube.com also covers its subdomains. *.youtube.com covers subdomains only.",
    search: "Search domains",
    listLabel: "Domain rules",
    emptyTitle: "No domains yet",
    emptyText: "Add a site above, or turn on Blocked in Russia to cover about 2,000 sites at once."
  };
}

/* ---------- Targets ---------- */

export interface RoutingTargets {
  domains: number;
  ips: number;
  apps: number;
  /** 1 when Blocked in Russia is on and holds at least one usable domain. */
  lists: number;
  total: number;
}

/**
 * What Split tunnel can send through the tunnel. Counts only enabled rules
 * that are valid and an enabled proxy list with a usable domain — the same
 * test the main process uses to block Connect — so the number on screen never
 * says "targets" while Connect is blocked.
 */
export function countTargets(rules: readonly RoutingRule[], proxyList: Pick<RoutingProxyList, "enabled" | "domains">): RoutingTargets {
  let domains = 0;
  let ips = 0;
  let apps = 0;
  for (const rule of rules) {
    if (!rule.enabled || !validateRoutingRuleValue(rule.type, rule.value).ok) {
      continue;
    }
    if (rule.type === "domain") {
      domains += 1;
    } else if (rule.type === "ip") {
      ips += 1;
    } else if (rule.type === "process.name") {
      apps += 1;
    }
  }
  const lists = proxyList.enabled && proxyList.domains.some((domain) => normalizeProxyDomain(domain) !== undefined) ? 1 : 0;
  return { domains, ips, apps, lists, total: domains + ips + apps + lists };
}

/**
 * A change that would leave a running Split tunnel without targets. The main
 * process disconnects in that case, so the page asks first.
 */
export function wouldCutLastTarget(mode: RoutingMode, live: boolean, before: RoutingTargets, after: RoutingTargets): boolean {
  return mode === "selected-rules" && live && before.total > 0 && after.total === 0;
}

/** Changes on their way that the saved state doesn't show yet. */
export interface PendingRoutingChanges {
  /** Rules playing their delete animation, removed when it ends. */
  deletingRuleIds: ReadonlySet<string>;
  /** The Blocked in Russia list is being turned off (its reply waits for routing to be re-applied). */
  proxyListTurningOff: boolean;
}

/**
 * `wouldCutLastTarget` with the pending changes counted as done, so two quick
 * changes can't each pass the guard and together leave nothing to route.
 */
export function cutsLastTargetWithPending(
  mode: RoutingMode,
  live: boolean,
  current: { rules: readonly RoutingRule[]; proxyList: RoutingProxyList },
  next: { rules: readonly RoutingRule[]; proxyList?: RoutingProxyList },
  pending: PendingRoutingChanges
): boolean {
  const settled = (rules: readonly RoutingRule[]): RoutingRule[] => rules.filter((rule) => !pending.deletingRuleIds.has(rule.id));
  const proxyList = pending.proxyListTurningOff ? { ...current.proxyList, enabled: false } : current.proxyList;
  return wouldCutLastTarget(
    mode,
    live,
    countTargets(settled(current.rules), proxyList),
    countTargets(settled(next.rules), next.proxyList ?? proxyList)
  );
}

export interface SummaryCopy {
  tone: "" | "warn" | "muted";
  title: string;
  sub: string;
}

export function summaryCopy(mode: RoutingMode, targets: RoutingTargets): SummaryCopy {
  const split = mode === "selected-rules";
  if (split && targets.total === 0) {
    return {
      tone: "warn",
      title: "Nothing to route yet",
      sub: "Add a rule below or turn on Blocked in Russia. Russian services doesn’t count: it only keeps sites direct."
    };
  }
  const one = targets.total === 1;
  if (split) {
    return { tone: "", title: one ? "target goes through the tunnel" : "targets go through the tunnel", sub: "Everything else stays direct." };
  }
  return {
    tone: "muted",
    title: one ? "target saved for Split tunnel" : "targets saved for Split tunnel",
    sub: "Not used right now: in Full tunnel everything already goes through."
  };
}

/* ---------- Rule rows ---------- */

export function ruleMeta(rule: Pick<RoutingRule, "type" | "value">): string {
  if (!validateRoutingRuleValue(rule.type, rule.value).ok) {
    return "Not a valid rule, so it’s skipped";
  }
  if (rule.type === "domain") {
    return rule.value.startsWith("*.") ? "Subdomains only" : "Includes subdomains";
  }
  if (rule.type === "ip") {
    const v6 = rule.value.includes(":");
    const prefix = rule.value.includes("/") ? rule.value.split("/")[1] : "";
    const single = !prefix || prefix === (v6 ? "128" : "32");
    return `${v6 ? "IPv6" : "IPv4"} ${single ? "address" : "range"}`;
  }
  return "Every connection from this app";
}

/** "9 domains · 8 on", or "3 of 9 domains match" while searching. */
export function rulesHeading(copy: Pick<TabCopy, "one" | "many">, inTab: number, enabledInTab: number, shown: number, query: string): string {
  if (query.trim()) {
    return `${formatCount(shown)} of ${plural(inTab, copy.one, copy.many)} ${shown === 1 ? "matches" : "match"}`;
  }
  return `${plural(inTab, copy.one, copy.many)} · ${formatCount(enabledInTab)} on`;
}

export function filterRules(rules: readonly RoutingRule[], type: RoutingRuleType, query: string): RoutingRule[] {
  const needle = query.trim().toLowerCase();
  return rules.filter((rule) => rule.type === type && (!needle || rule.value.toLowerCase().includes(needle)));
}

/* ---------- Adding a rule ---------- */

export type DraftResult = { value: string; error?: undefined } | { error: string; value?: undefined };

const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const APP_NAME = /^[a-z0-9._+\- ]+$/u;

/**
 * Checks what someone typed in the add row and says how to fix it. Accepted
 * values always pass the shared validator the main process applies.
 */
export function validateRuleDraft(type: RoutingRuleType, raw: string, platform: DesktopPlatform): DraftResult {
  if (type === "domain") {
    return validateDomainDraft(raw);
  }
  if (type === "ip") {
    return validateIpDraft(raw);
  }
  return validateAppDraft(raw, platform);
}

function validateDomainDraft(raw: string): DraftResult {
  let value = raw.trim().toLowerCase();
  if (!value) {
    return { error: "Enter a domain, like youtube.com." };
  }
  if (value.length > 253) {
    return { error: "Domain is too long. Use 253 characters or fewer." };
  }
  if (value.includes("://") || value.includes("/")) {
    return { error: "Enter just the domain, without https:// or a path." };
  }
  if (/:\d*$/u.test(value)) {
    return { error: "Enter just the domain, without a port." };
  }
  if (isValidIpv4(value) || isValidIpv6(value)) {
    return { error: "That’s an IP address. Add it on the IPs tab." };
  }
  if (value.startsWith(".")) {
    return { error: "Leave out the leading dot: youtube.com already covers its subdomains." };
  }
  // A trailing dot is the fully qualified form of the same name.
  value = value.replace(/\.$/u, "");
  const body = value.startsWith("*.") ? value.slice(2) : value;
  if (body.includes("*")) {
    return { error: "A * works only at the start, as in *.youtube.com." };
  }
  const labels = body.split(".");
  if (labels.length < 2) {
    return { error: "Use the full domain with at least two parts, like youtube.com." };
  }
  if (labels.some((label) => !DOMAIN_LABEL.test(label))) {
    return { error: "Use Latin letters, numbers and inner hyphens only. For other scripts, paste the xn-- form." };
  }
  return validateDomainPattern(value).ok ? { value } : { error: "Enter a domain, like youtube.com." };
}

function validateIpDraft(raw: string): DraftResult {
  const value = raw.trim();
  if (!value) {
    return { error: "Enter an IP address or range, like 8.8.8.8 or 10.0.0.0/8." };
  }
  if (value.includes("://")) {
    return { error: "Enter just the address, without http:// or a path." };
  }
  const parts = value.split("/");
  if (parts.length > 2) {
    return { error: "CIDR may contain only one slash." };
  }
  const address = parts[0] ?? "";
  const v4 = isValidIpv4(address);
  const v6 = !v4 && isValidIpv6(address);
  if (!v4 && !v6) {
    if (parts.length === 1 && /[a-z]/iu.test(address.split(".").pop() ?? "") && validateDomainPattern(address).ok) {
      return { error: "That’s a domain. Add it on the Domains tab." };
    }
    return { error: "IP address must be valid IPv4 or IPv6." };
  }
  if (parts.length === 2) {
    const prefix = parts[1] ?? "";
    if (!/^\d+$/u.test(prefix)) {
      return { error: "CIDR prefix must be a number." };
    }
    const max = v4 ? 32 : 128;
    if (Number(prefix) > max) {
      return { error: `CIDR prefix must be between 0 and ${max}.` };
    }
  }
  return { value: v6 ? value.toLowerCase() : value };
}

function validateAppDraft(raw: string, platform: DesktopPlatform): DraftResult {
  const windows = platform === "windows" || platform === "unknown";
  const value = normalizeRuleValue("process.name", raw);
  if (!value) {
    return { error: windows ? "Enter an app file name, like telegram.exe." : "Enter an app name, like Telegram." };
  }
  if (value.length > 260) {
    return { error: "App name is too long. Use 260 characters or fewer." };
  }
  if (/[\\/]/u.test(value)) {
    return { error: windows ? "Use the file name only, not a path, like chrome.exe." : "Use the app name only, not a path, like Telegram." };
  }
  if (!APP_NAME.test(value)) {
    return { error: "App names can use Latin letters, numbers, spaces and . _ + - only." };
  }
  return { value };
}

/** Compares values the way routing matches them: chrome = chrome.exe on Windows, 8.8.8.8 = 8.8.8.8/32. */
export function ruleMatchKey(type: RoutingRuleType, value: string, platform: DesktopPlatform): string {
  const lower = value.trim().toLowerCase();
  if (type === "process.name") {
    return platform === "windows" || platform === "unknown" ? lower.replace(/\.exe$/u, "") : lower;
  }
  if (type === "ip") {
    return lower.replace(/\/(32|128)$/u, (match, prefix: string) => (prefix === (lower.includes(":") ? "128" : "32") ? "" : match));
  }
  return lower;
}

export function findDuplicateRule(rules: readonly RoutingRule[], type: RoutingRuleType, value: string, platform: DesktopPlatform): RoutingRule | undefined {
  const key = ruleMatchKey(type, value, platform);
  return rules.find((rule) => rule.type === type && ruleMatchKey(type, rule.value, platform) === key);
}

export function duplicateMessage(value: string, existing: RoutingRule): string {
  if (existing.value === value) {
    return existing.enabled
      ? `${value} is already in your rules.`
      : `${value} is already in your rules but turned off. Turn it on in the list below.`;
  }
  return `${value} is already in your rules as ${existing.value}.`;
}

/* ---------- Domain lists ---------- */

export type ListBusy = "downloading" | "refreshing" | "turning-on" | "turning-off";

export function listMetaText(list: DomainList, busy: ListBusy | undefined, now: Date = new Date()): string {
  switch (busy) {
    case "downloading":
      return "Downloading from GitHub… up to 15 s";
    case "refreshing":
      return "Refreshing from GitHub… up to 15 s";
    case "turning-on":
      return "Turning on…";
    case "turning-off":
      return "Turning off…";
    default:
      break;
  }
  const count = list.domains.length;
  if (count === 0) {
    return "Not downloaded yet · downloads when you turn it on";
  }
  const refreshed = list.updatedAt ? ` · refreshed ${formatDay(list.updatedAt, now)} ${formatTime(list.updatedAt)}` : "";
  return `${plural(count, "domain")}${refreshed}`;
}

const NETWORK_NOTE = " Lists download directly, not through the tunnel, so this fails if GitHub is blocked on your network, even while connected.";

export interface ListErrorCopy {
  title: string;
  text: string;
}

/** Inline copy for a failed list download, from the raw error the main process threw. */
export function describeListError(error: string, kind: ListKind, list: DomainList): ListErrorCopy {
  const name = listName(kind);
  const hasData = list.domains.length > 0;
  const raw = stripIpcPrefix(error);
  let reason: string;
  const status = /download failed:\s*(\d{3})\s*(.*)$/iu.exec(raw);
  if (/timed out|\btimeout\b|ETIMEDOUT|ERR_TIMED_OUT/iu.test(raw)) {
    reason = `GitHub didn’t answer within 15 s.${NETWORK_NOTE}`;
  } else if (/fetch failed|ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ECONNRESET|ENETUNREACH|net::ERR_|socket hang up/iu.test(raw)) {
    reason = `Shadow couldn’t reach GitHub.${NETWORK_NOTE}`;
  } else if (status) {
    const text = status[2]?.trim();
    reason = `GitHub answered ${status[1]}${text ? ` ${text}` : ""}. Try again in a few minutes.`;
  } else if (/larger than the allowed limit/iu.test(raw)) {
    reason = "The download was larger than the 2 MB limit for a list.";
  } else if (/returned no domains/iu.test(raw)) {
    reason = "The download didn’t contain any domains.";
  } else if (/larger than \d+ entries/iu.test(raw)) {
    reason = "The list has more than 20,000 domains, the most Shadow can use.";
  } else {
    reason = sentence(raw || "The download failed.");
  }
  const outcome = hasData ? (list.enabled ? " Your current copy stays in use." : " Your current copy is kept.") : " The list stays off.";
  return {
    title: hasData ? `Couldn’t refresh ${name}` : `Couldn’t download ${name}`,
    text: `${reason}${outcome}`
  };
}

function sentence(text: string): string {
  const trimmed = text.trim();
  const first = trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  return /[.!?…]$/u.test(first) ? first : `${first}.`;
}

export interface DomainRow {
  domain: string;
  /** Text before, inside and after the first match of the query. */
  pre: string;
  hit: string;
  post: string;
  /** A leading dot covers the whole zone. */
  zone: boolean;
}

export function filterDomains(domains: readonly string[], query: string): DomainRow[] {
  const needle = query.trim().toLowerCase();
  const rows: DomainRow[] = [];
  for (const domain of domains) {
    const index = needle ? domain.indexOf(needle) : -1;
    if (needle && index < 0) {
      continue;
    }
    rows.push({
      domain,
      pre: index >= 0 ? domain.slice(0, index) : domain,
      hit: index >= 0 ? domain.slice(index, index + needle.length) : "",
      post: index >= 0 ? domain.slice(index + needle.length) : "",
      zone: domain.startsWith(".")
    });
  }
  return rows;
}

/* ---------- TUN (Windows) ---------- */

export interface TunView {
  tone: "off" | "ok" | "warn";
  title: string;
  sub: string;
  dllOk: boolean;
  adminOk: boolean;
  /** Label of the checklist disclosure. */
  howLabel: string;
}

const NOT_ADMIN = "Shadow isn’t running as administrator";
const NO_WINTUN = "wintun.dll wasn’t found";
const FALLBACK = "App rules fall back to the Windows proxy, so apps that ignore it go direct.";

export function presentTun(tun: TunStatus, live: boolean): TunView {
  const dllOk = tun.wintunFound;
  const adminOk = tun.elevated;
  const howLabel = dllOk && adminOk ? "Requirements" : "How to enable";
  const base = { dllOk, adminOk, howLabel };
  if (!tun.enabled) {
    return { ...base, tone: "off", title: "Off", sub: "App rules use the Windows proxy, which some apps ignore." };
  }
  if (tun.active) {
    return { ...base, tone: "ok", title: "Active this session", sub: "Network adapter “Shadow SSH” is carrying app traffic." };
  }
  if (!adminOk) {
    return { ...base, tone: "warn", title: `Not active: ${NOT_ADMIN}`, sub: FALLBACK };
  }
  if (!dllOk) {
    return { ...base, tone: "warn", title: `Not active: ${NO_WINTUN}`, sub: FALLBACK };
  }
  if (tun.lastFailure && live && !tun.appliesOnNextConnect) {
    return { ...base, tone: "warn", title: "Not active this session", sub: `The TUN adapter couldn’t start. ${FALLBACK}` };
  }
  return {
    ...base,
    tone: "ok",
    title: live && tun.appliesOnNextConnect ? "Ready · starts when you reconnect" : "Ready · starts when you connect",
    sub: "wintun.dll is in place and Shadow runs as administrator."
  };
}

/* ---------- Running apps ---------- */

export interface ProcessChip {
  name: string;
  /** Already covered by an app rule. */
  added: boolean;
}

export function processChips(
  names: readonly string[],
  query: string,
  appRules: readonly RoutingRule[],
  platform: DesktopPlatform
): { chips: ProcessChip[]; matches: number } {
  const needle = query.trim().toLowerCase();
  const added = new Set(appRules.map((rule) => ruleMatchKey("process.name", rule.value, platform)));
  const matching = needle ? names.filter((name) => name.toLowerCase().includes(needle)) : [...names];
  return {
    matches: matching.length,
    chips: matching.slice(0, MAX_PROCESS_CHIPS).map((name) => ({ name, added: added.has(ruleMatchKey("process.name", name, platform)) }))
  };
}

export function processFootText(total: number, matches: number, query: string): string {
  if (query.trim()) {
    if (matches > MAX_PROCESS_CHIPS) {
      return `Showing ${MAX_PROCESS_CHIPS} of ${formatCount(matches)} matches · refine your search`;
    }
    return `${plural(matches, "match", "matches")} among ${plural(total, "running app")}`;
  }
  if (total > MAX_PROCESS_CHIPS) {
    return `Showing ${MAX_PROCESS_CHIPS} of ${formatCount(total)} · refine your search`;
  }
  return plural(total, "running app");
}
