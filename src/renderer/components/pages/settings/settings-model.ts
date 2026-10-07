import { DEFAULT_CUSTOM_THEME } from "../../../../shared/defaults.js";
import type {
  AppSettings,
  AppSnapshot,
  AppStore,
  AppUpdateDownload,
  AppUpdateInfo,
  CustomTheme,
  DesktopPlatform,
  RoutingMode,
  RuntimeArch
} from "../../../../shared/types.js";
import { describeError, errorText } from "../../../lib/errors.js";
import { formatBytes, formatWhen } from "../../../lib/format.js";
import { ACCENT_INK_DARK, contrastRatio, hexToRgb, parseHex, rgbToHex, sameColor, THEME_BASES, type ResolvedTheme } from "../../../lib/theme.js";
import type { SettingsSection } from "../../../types.js";

/* ---------- Sections ---------- */

/** Local navigation order (also the order of the cards). */
export const SETTINGS_SECTIONS: readonly SettingsSection[] = ["general", "notifications", "appearance", "diagnostics", "updates", "about"];

export const SECTION_LABELS: Record<SettingsSection, string> = {
  general: "General",
  notifications: "Notifications",
  appearance: "Appearance",
  diagnostics: "Diagnostics",
  updates: "Updates",
  about: "About"
};

export function sectionElementId(section: SettingsSection): string {
  return `st-${section}`;
}

/**
 * Scroll spy: the section whose top has passed `threshold` px below the top of
 * the scroll area; the last one once the area is scrolled to the bottom (short
 * last sections never reach the threshold).
 */
export function activeSectionAt<T extends string>(sections: ReadonlyArray<{ id: T; top: number }>, threshold: number, atBottom: boolean): T | undefined {
  if (sections.length === 0) {
    return undefined;
  }
  if (atBottom) {
    return sections[sections.length - 1].id;
  }
  let active = sections[0].id;
  for (const section of sections) {
    if (section.top <= threshold) {
      active = section.id;
    }
  }
  return active;
}

/* ---------- Optimistic settings ---------- */

/** The snapshot with a settings patch applied (optimistic UI while the save runs). */
export function withSettingsPatch(snapshot: AppSnapshot, patch: Partial<AppSettings>): AppSnapshot {
  return { ...snapshot, store: { ...snapshot.store, settings: { ...snapshot.store.settings, ...patch } } };
}

/* ---------- Platform copy ---------- */

export interface PlatformCopy {
  /** "tray" or "menu bar". */
  trayWord: string;
  /** "Windows", "macOS" or "your desktop". */
  osName: string;
  trayTitle: string;
  trayDescription: string;
  freeMemoryDescription: string;
  freeMemoryWhy: string;
  /** Launch at sign-in is a Windows feature. */
  signInAvailable: boolean;
  signInDescription: string;
  /** Only Windows downloads updates inside the app. */
  updatesInApp: boolean;
  notificationsSub: string;
  notificationsHint: string;
  stillRunningTitle: string;
  stillRunningLabel: string;
  stillRunningWhy: string;
  updateNotificationDescription: string;
  successHint: string;
  /** File manager name for "Show in folder" feedback. */
  fileManager: string;
}

export function platformCopy(platform: DesktopPlatform): PlatformCopy {
  const windows = platform === "windows";
  const mac = platform === "macos";
  const trayWord = mac ? "menu bar" : "tray";
  const osName = windows ? "Windows" : mac ? "macOS" : "your desktop";
  return {
    trayWord,
    osName,
    trayTitle: `Keep running in the ${trayWord} when you close the window`,
    trayDescription: mac
      ? "Closing the window hides it and the tunnel keeps running. When off, the window closes but Shadow SSH stays open in the Dock."
      : "Closing the window hides Shadow SSH in the tray and the tunnel keeps running. When off, closing the window quits the app and disconnects.",
    freeMemoryDescription: `After 30 seconds hidden in the ${trayWord}, the window is unloaded to save memory. The tunnel keeps running; unsaved form edits are discarded.`,
    freeMemoryWhy: `Turn on “Keep running in the ${trayWord}” to use this.`,
    signInAvailable: windows,
    signInDescription: windows
      ? "Starts with Windows straight to the tray, without opening the window. It runs without administrator rights, so TUN stays off: quit from the tray and run Shadow SSH as administrator when you need it."
      : "Available on Windows only.",
    updatesInApp: windows,
    notificationsSub: windows
      ? "Windows shows these when something happens while Shadow SSH is out of sight."
      : mac
        ? "macOS shows these when something happens while Shadow SSH is out of sight."
        : "Your desktop shows these when something happens while Shadow SSH is out of sight.",
    notificationsHint: windows
      ? "Windows Focus assist and its own notification settings still apply on top of these."
      : mac
        ? "macOS Focus and its own notification settings still apply on top of these."
        : "Your desktop’s do-not-disturb mode and its own notification settings still apply on top of these.",
    stillRunningTitle: `Still running in the ${trayWord}`,
    stillRunningLabel: `Tell me once that Shadow SSH keeps running in the ${trayWord}`,
    stillRunningWhy: `Turn on “Keep running in the ${trayWord}” in General to use this.`,
    updateNotificationDescription: windows ? "When a new version is ready to run." : "Updates download inside the app on Windows only.",
    successHint: `${windows ? "Protected" : "Proxy ready"} state and passed checks.`,
    fileManager: windows ? "File Explorer" : mac ? "Finder" : "Your file manager"
  };
}

export interface SecretsCopy {
  title: string;
  hint: string;
}

/** About → Secrets, from `environment.secretsBackend`. */
export function secretsCopy(backend: string): SecretsCopy {
  switch (backend) {
    case "Windows DPAPI":
      return {
        title: "Encrypted with Windows DPAPI",
        hint: "Passwords, private keys and Xray links can be read only by your Windows account on this PC. Copied to another PC, they become unreadable."
      };
    case "macOS Keychain":
      return {
        title: "Encrypted with the macOS Keychain",
        hint: "Passwords, private keys and Xray links can be read only by your macOS account. Resetting the Keychain makes them unreadable."
      };
    case "Linux keyring":
      return {
        title: "Encrypted with the system keyring",
        hint: "Without a keyring (common on minimal desktops), Shadow SSH can’t save passwords, keys or Xray links."
      };
    case "unavailable":
    case "":
      return {
        title: "No secure storage found",
        hint: "Without a system keyring, Shadow SSH can’t save passwords, keys or Xray links."
      };
    default:
      return { title: `Encrypted with ${backend}`, hint: "Passwords, private keys and Xray links are stored encrypted on this computer." };
  }
}

/* ---------- General ---------- */

/** "SSH · Frankfurt-01" — what auto-connect would start, from the last used transport. */
export function autoConnectTarget(store: Pick<AppStore, "settings" | "sshConfigs" | "proxyProfiles" | "selectedConfigId" | "selectedProxyProfileId">): { label: string; selected: boolean } {
  if (store.settings.lastConnectedTransport === "xray") {
    const profile = store.proxyProfiles.find((item) => item.id === store.selectedProxyProfileId);
    return profile ? { label: `Xray · ${profile.name}`, selected: true } : { label: "Xray", selected: false };
  }
  const config = store.sshConfigs.find((item) => item.id === store.selectedConfigId);
  return config ? { label: `SSH · ${config.name}`, selected: true } : { label: "SSH", selected: false };
}

export function routingModeLabel(mode: RoutingMode): string {
  return mode === "selected-rules" ? "Split tunnel" : "Full tunnel";
}

/* ---------- Diagnostics ---------- */

export interface DiagnosticsPresentation {
  historyOn: boolean;
  liveOn: boolean;
  fileOn: boolean;
  /** History is on but both recorders are off. */
  nothingRecorded: boolean;
  badge: { text: string; tone: "outline" | "warn" | "ok" };
}

export function presentDiagnostics(settings: Pick<AppSettings, "loggingEnabled" | "diagnosticsLoggingEnabled" | "fileLoggingEnabled">): DiagnosticsPresentation {
  const historyOn = settings.loggingEnabled;
  const liveOn = historyOn && settings.diagnosticsLoggingEnabled;
  const fileOn = historyOn && settings.fileLoggingEnabled;
  const nothingRecorded = historyOn && !liveOn && !fileOn;
  return {
    historyOn,
    liveOn,
    fileOn,
    nothingRecorded,
    badge: !historyOn
      ? { text: "Off", tone: "outline" }
      : nothingRecorded
        ? { text: "Nothing recorded", tone: "warn" }
        : { text: "Recording", tone: "ok" }
  };
}

/** Turning history back on brings both recorders back, as people expect from a master switch. */
export function historyPatch(on: boolean): Partial<AppSettings> {
  return on ? { loggingEnabled: true, diagnosticsLoggingEnabled: true, fileLoggingEnabled: true } : { loggingEnabled: false };
}

/** Path of main.log as the main process reports it, else derived from the log folder. */
export function logFilePath(snapshot: Pick<AppSnapshot, "logFilePaths" | "environment">): string {
  const reported = snapshot.logFilePaths.find((item) => /main\.log$/u.test(item)) ?? snapshot.logFilePaths[0];
  if (reported) {
    return reported;
  }
  const directory = snapshot.environment.logDirectory;
  const separator = snapshot.environment.platform === "windows" ? "\\" : "/";
  return directory ? `${directory.replace(/[\\/]+$/u, "")}${separator}main.log` : "main.log";
}

/* ---------- Colours ---------- */

export type SignalKey = "accent" | "success" | "danger";
export type PaletteKey = "background" | "surface" | "text" | "muted" | "border";
export type ColourKey = SignalKey | PaletteKey;

export interface ColourFieldSpec<K extends ColourKey> {
  key: K;
  name: string;
  hint: string;
}

export function signalFieldSpecs(successHint: string): Array<ColourFieldSpec<SignalKey>> {
  return [
    { key: "accent", name: "Accent", hint: "Buttons, focus rings and selection." },
    { key: "success", name: "Success", hint: successHint },
    { key: "danger", name: "Danger", hint: "Errors and destructive actions." }
  ];
}

export const PALETTE_FIELD_SPECS: ReadonlyArray<ColourFieldSpec<PaletteKey>> = [
  { key: "background", name: "Background", hint: "Window and page ground." },
  { key: "surface", name: "Surface", hint: "Cards, panels and dialogs." },
  { key: "text", name: "Text", hint: "Titles and body copy." },
  { key: "muted", name: "Muted text", hint: "Hints, captions and times." },
  { key: "border", name: "Borders", hint: "Dividers and field outlines." }
];

export const HEX_FIELD_ERROR = "Use 6 HEX digits, like #F6A019";

/** "#F6A019" from user input ("f6a019", "#fa1"); undefined when it isn't a HEX colour. */
export function normalizeHexInput(raw: string): string | undefined {
  const parsed = parseHex(raw);
  return parsed ? rgbToHex(parsed) : undefined;
}

const THEME_SIGNAL: Record<"success" | "danger", "ok" | "danger"> = { success: "ok", danger: "danger" };

/**
 * The colour a field shows. Success and Danger follow the theme's own shade
 * while they are stored as the defaults.
 */
export function colourHex(theme: CustomTheme, key: ColourKey, resolved: ResolvedTheme): string {
  if ((key === "success" || key === "danger") && sameColor(theme[key], DEFAULT_CUSTOM_THEME[key])) {
    return THEME_BASES[resolved][THEME_SIGNAL[key]];
  }
  return rgbToHex(theme[key]);
}

/**
 * Stores a picked colour. Picking the theme's own Success/Danger shade stores
 * the default again, so it keeps following the theme instead of pinning one shade.
 */
export function withColour(theme: CustomTheme, key: ColourKey, hex: string, resolved: ResolvedTheme): CustomTheme {
  if ((key === "success" || key === "danger") && hex.toUpperCase() === THEME_BASES[resolved][THEME_SIGNAL[key]]) {
    return { ...theme, [key]: { ...DEFAULT_CUSTOM_THEME[key] } };
  }
  return { ...theme, [key]: hexToRgb(hex) };
}

const COLOUR_KEYS: readonly ColourKey[] = ["accent", "success", "danger", "background", "surface", "text", "muted", "border"];

/** Reset to defaults has nothing to do. */
export function coloursAreDefault(theme: CustomTheme): boolean {
  return COLOUR_KEYS.every((key) => sameColor(theme[key], DEFAULT_CUSTOM_THEME[key]));
}

export type ContrastVerdict = "passes" | "large text only" | "too low";

export interface ContrastCheck {
  id: string;
  label: string;
  ratio: number;
  /** "4.6:1". */
  value: string;
  verdict: ContrastVerdict;
  tone: "ok" | "warn" | "danger";
}

/** WCAG AA: 4.5 for body text, 3 for large text. */
export function contrastVerdict(ratio: number): { verdict: ContrastVerdict; tone: ContrastCheck["tone"] } {
  if (ratio >= 4.5) {
    return { verdict: "passes", tone: "ok" };
  }
  if (ratio >= 3) {
    return { verdict: "large text only", tone: "warn" };
  }
  return { verdict: "too low", tone: "danger" };
}

/**
 * Contrast of the colours in use: the Custom palette, or the built-in theme
 * (the button label is whichever of dark ink or white reads better).
 */
export function contrastChecks(theme: CustomTheme, mode: AppSettings["theme"], resolved: ResolvedTheme): { checks: ContrastCheck[]; note: string } {
  const custom = mode === "custom";
  const base = THEME_BASES[resolved];
  const colours = custom
    ? { bg: rgbToHex(theme.background), surface: rgbToHex(theme.surface), text: rgbToHex(theme.text), muted: rgbToHex(theme.muted) }
    : { bg: base.bg, surface: base.surface, text: base.text, muted: base.muted };
  const accent = rgbToHex(theme.accent);
  const pairs = [
    { id: "text", label: "Text on Background", ratio: contrastRatio(colours.text, colours.bg) },
    { id: "muted", label: "Muted text on Surface", ratio: contrastRatio(colours.muted, colours.surface) },
    { id: "accent", label: "Button label on Accent", ratio: Math.max(contrastRatio(ACCENT_INK_DARK, accent), contrastRatio("#FFFFFF", accent)) }
  ];
  return {
    checks: pairs.map((pair) => ({ ...pair, value: `${pair.ratio.toFixed(1)}:1`, ...contrastVerdict(pair.ratio) })),
    note: custom ? "Checked against your palette" : `Checked against the ${resolved === "light" ? "Light" : "Dark"} theme`
  };
}

/* ---------- Updates ---------- */

export type UpdatesPhase = "unsupported" | "notChecked" | "checking" | "checkFailed" | "available" | "availableNoAsset" | "upToDate";

export interface UpdatesInput {
  platform: DesktopPlatform;
  arch: RuntimeArch;
  currentVersion: string;
  info?: AppUpdateInfo;
  download?: AppUpdateDownload;
  checking: boolean;
  /** Raw error of the last failed check in this window. */
  checkError?: unknown;
  /** A download request that failed before the download itself started. */
  downloadError?: unknown;
  now?: Date;
}

export interface UpdatesPresentation {
  phase: UpdatesPhase;
  badge: { text: string; tone: "accent" | "busy" | "ok" | "danger" | "outline"; dot: boolean };
  title: string;
  sub: string;
  titleDanger: boolean;
  /** The newer version, shown next to Installed. */
  latestVersion?: string;
  /** "shadow-ssh-2.3.0-windows-portable-x64.exe · 92 MB". */
  fileLine?: string;
  download: {
    state: "idle" | "downloading" | "downloaded" | "failed";
    /** Whole percent, 0–100. */
    percent: number;
    /** "85 of 92 MB". */
    bytesText: string;
    filePath?: string;
    failure?: { message: string; technical?: string };
  };
  /** Download / Download again is offered. */
  canDownload: boolean;
  downloadLabel: string;
  check: { label: string; disabled: boolean; title: string };
  /** Accent dot on the Updates nav link. */
  navDot: boolean;
}

const OFFLINE_PATTERN = /ERR_INTERNET_DISCONNECTED|ENETUNREACH|ENETDOWN|EAI_AGAIN|ENOTFOUND|ERR_NAME_NOT_RESOLVED|ERR_NETWORK_CHANGED|ERR_ADDRESS_UNREACHABLE|ECONNREFUSED|ECONNRESET|ERR_CONNECTION_|ETIMEDOUT|ERR_TIMED_OUT|timed out|socket hang up|fetch failed|net::ERR_/iu;
const CHECKSUM_PATTERN = /digest does not match|does not match release metadata size|checksum/iu;

/** True when a failed update check most likely means GitHub is unreachable. */
export function isOfflineError(error: unknown): boolean {
  return OFFLINE_PATTERN.test(errorText(error));
}

/** Download failures in plain words; a digest or size mismatch means the file can't be trusted. */
export function describeDownloadFailure(message: string | undefined): { message: string; technical?: string } {
  const raw = (message ?? "").trim();
  if (CHECKSUM_PATTERN.test(raw)) {
    return { message: "The file didn’t match the checksum published with the release, so it can’t be trusted. Try downloading it again.", technical: raw };
  }
  if (!raw) {
    return { message: "The download stopped before it finished. Try downloading it again." };
  }
  const described = describeError(raw, { target: "GitHub" });
  return { message: described.message, technical: described.technical ?? (described.message !== raw ? raw : undefined) };
}

/** "85 of 92 MB": the downloaded amount in the unit of the total. */
export function formatProgressBytes(downloaded: number, total: number | undefined): string {
  if (total === undefined || !Number.isFinite(total) || total <= 0) {
    return downloaded > 0 ? formatBytes(downloaded) : "";
  }
  const totalText = formatBytes(total);
  const unit = totalText.split(" ")[1] ?? "B";
  const factor: Record<string, number> = { B: 1, KB: 1e3, MB: 1e6, GB: 1e9, TB: 1e12 };
  const value = Math.round(Math.max(0, Math.min(downloaded, total)) / (factor[unit] ?? 1));
  return `${value} of ${totalText}`;
}

export function presentUpdates(input: UpdatesInput): UpdatesPresentation {
  const { info, checking } = input;
  const now = input.now ?? new Date();
  const asset = info?.available ? info.asset : undefined;
  const latestVersion = info?.available ? asset?.version ?? info.latestVersion : undefined;
  const reported = input.download ?? { state: "idle", downloadedBytes: 0 };
  const raw: AppUpdateDownload = reported.state === "idle" && input.downloadError !== undefined
    ? { ...reported, state: "error", message: errorText(input.downloadError) }
    : reported;
  const total = raw.totalBytes ?? asset?.size;
  const percent = raw.state === "downloaded" ? 100 : Math.max(0, Math.min(100, Math.round(raw.percent ?? (total ? (raw.downloadedBytes / total) * 100 : 0))));
  const downloadState = raw.state === "error" ? "failed" : raw.state;
  const download: UpdatesPresentation["download"] = {
    state: downloadState,
    percent,
    bytesText: formatProgressBytes(raw.state === "downloaded" && total ? total : raw.downloadedBytes, total),
    filePath: raw.state === "downloaded" ? raw.filePath : undefined,
    failure: raw.state === "error" ? describeDownloadFailure(raw.message) : undefined
  };
  const downloading = downloadState === "downloading";
  const sizeText = asset ? formatBytes(asset.size) : "";
  const check = {
    label: checking ? "Checking…" : input.checkError !== undefined ? "Try again" : "Check now",
    disabled: checking || downloading,
    title: downloading ? "Available when the download finishes" : "Look for a new version on GitHub"
  };
  const checked = info ? formatWhen(info.checkedAt, now) : "";
  const checkedSentence = checked ? `Checked ${checked}.` : "";

  if (input.platform !== "windows") {
    return {
      phase: "unsupported",
      badge: { text: "Windows only", tone: "outline", dot: false },
      title: "In-app updates are available on Windows",
      sub: "Download new versions from GitHub.",
      titleDanger: false,
      download: { ...download, state: "idle" },
      canDownload: false,
      downloadLabel: "",
      check,
      navDot: false
    };
  }

  let phase: UpdatesPhase;
  if (checking) {
    phase = "checking";
  } else if (input.checkError !== undefined) {
    phase = "checkFailed";
  } else if (!info) {
    phase = "notChecked";
  } else if (info.available && asset) {
    phase = "available";
  } else if (info.available) {
    phase = "availableNoAsset";
  } else {
    phase = "upToDate";
  }

  // The newer version stays on screen after a failed re-check: it still exists.
  const offerUpdate = Boolean(asset) && !checking;
  let title: string;
  let sub: string;
  let titleDanger = false;
  switch (phase) {
    case "checking":
      title = "Checking GitHub…";
      sub = "This usually takes a few seconds.";
      break;
    case "checkFailed":
      titleDanger = true;
      if (isOfflineError(input.checkError)) {
        title = "Can’t reach GitHub";
        sub = "Check your internet connection, then try again.";
      } else {
        title = "Couldn’t check for updates";
        sub = describeError(input.checkError, { target: "GitHub" }).message;
      }
      break;
    case "notChecked":
      title = "Not checked yet";
      sub = "Shadow SSH looks for updates only when you press Check now.";
      break;
    case "available":
      title = `Version ${latestVersion} is available for Windows ${asset!.arch}`;
      sub = checkedSentence;
      break;
    case "availableNoAsset":
      title = `Version ${latestVersion} is available`;
      sub = `It has no portable file for Windows ${input.arch === "unknown" ? "on this PC" : input.arch} yet, so it can’t be downloaded here. ${checkedSentence}`.trim();
      break;
    default:
      title = "You’re on the latest version";
      sub = `${input.currentVersion} is the newest release. ${checkedSentence}`.trim();
  }

  let badge: UpdatesPresentation["badge"];
  if (phase === "checking") {
    badge = { text: "Checking…", tone: "busy", dot: false };
  } else if (phase === "checkFailed") {
    badge = { text: "Check failed", tone: "danger", dot: true };
  } else if (phase === "notChecked") {
    badge = { text: "Not checked", tone: "outline", dot: true };
  } else if (phase === "upToDate") {
    badge = { text: "Up to date", tone: "ok", dot: true };
  } else if (offerUpdate && downloadState === "downloaded") {
    badge = { text: "Downloaded", tone: "ok", dot: true };
  } else if (offerUpdate && downloading) {
    badge = { text: "Downloading…", tone: "busy", dot: false };
  } else {
    badge = { text: `${latestVersion} available`, tone: "accent", dot: true };
  }

  const canDownload = offerUpdate && (downloadState === "idle" || downloadState === "failed");
  const sizeSuffix = sizeText ? ` · ${sizeText}` : "";
  return {
    phase,
    badge,
    title,
    sub,
    titleDanger,
    latestVersion: offerUpdate || phase === "availableNoAsset" ? latestVersion : undefined,
    fileLine: offerUpdate && asset ? `${asset.name}${sizeSuffix}` : undefined,
    download: offerUpdate ? download : { ...download, state: downloading ? "downloading" : "idle" },
    canDownload,
    downloadLabel: !canDownload ? "" : downloadState === "failed" ? `Download again${sizeSuffix}` : `Download ${latestVersion}${sizeSuffix}`,
    check,
    navDot: offerUpdate && downloadState !== "downloaded"
  };
}
