import { readFileSync } from "node:fs";
import path from "node:path";

/**
 * The package.json field electron-builder bakes into a packaged app
 * (scripts/electron-builder-with-local-dist.mjs). A packaged executable is
 * started later, from an environment that says nothing about how it was
 * built, so this field is what gives a "Shadow Dev" build its own identity.
 * bootstrap.cts reads it too.
 */
export const BUILD_CHANNEL_METADATA_FIELD = "shadowBuildChannel";

export type BuildChannel = "development" | "production";

/**
 * Packaged: the channel baked into package.json, production when it is
 * missing. Unpackaged (`npm run dev`, tests): SHADOW_SSH_BUILD_CHANNEL.
 */
export function resolveBuildChannel(input: { packaged: boolean; packageMetadata?: unknown; env: NodeJS.ProcessEnv }): BuildChannel {
  if (input.packaged) {
    const metadata = input.packageMetadata;
    return isRecord(metadata) && metadata[BUILD_CHANNEL_METADATA_FIELD] === "development" ? "development" : "production";
  }
  return input.env.SHADOW_SSH_BUILD_CHANNEL === "development" ? "development" : "production";
}

/** The app's own package.json (inside app.asar when packaged); undefined when it can't be read. */
export function readAppPackageMetadata(appPath: string, readFile: (filePath: string) => string = (filePath) => readFileSync(filePath, "utf8")): unknown {
  try {
    return JSON.parse(readFile(path.join(appPath, "package.json"))) as unknown;
  } catch {
    return undefined;
  }
}

export interface AppIdentity {
  /**
   * The name the OS keys this app's data by, kept from before the rename to
   * Shadow: it names the data folder and, through app.setName, the
   * "<name> Safe Storage" Keychain/keyring entry that encrypts saved secrets.
   * Changing it would orphan both. Mirrors bootstrap.cts.
   */
  systemName: string;
  /** The name people see: windows, tray, menus and notifications. */
  displayName: string;
}

export function appIdentity(channel: BuildChannel): AppIdentity {
  return channel === "development"
    ? { systemName: "Shadow SSH Dev", displayName: "Shadow Dev" }
    : { systemName: "Shadow SSH", displayName: "Shadow" };
}

/**
 * Developer and test switches a packaged build ignores. Anything able to set
 * an environment variable for the user would otherwise get a renderer loaded
 * from any URL with every IPC channel, an arbitrary "xray" executable, a
 * foreign service endpoint or token, or secrets encrypted under a key anyone
 * can derive - in a process that may run as administrator for TUN.
 *
 * SHADOW_SSH_USER_DATA_DIR is deliberately not on the list: it only moves the
 * data folder, which belongs to the user either way, and it is how a second,
 * isolated profile is run (tests, a side-by-side copy).
 */
export const PACKAGED_IGNORED_ENVIRONMENT_VARIABLES = [
  "VITE_DEV_SERVER_URL",
  "SHADOW_SSH_BUILD_CHANNEL",
  "SHADOW_SSH_XRAY_PATH",
  "SHADOW_SSH_SERVICE_ENDPOINT",
  "SHADOW_SSH_USE_NATIVE_PROCESS_SERVICE",
  "SHADOW_SSH_SERVICE_TOKEN",
  "SHADOW_SSH_ALLOW_INSECURE_SECRET_FALLBACK"
] as const;

/**
 * Deletes the ignored switches from `env` when packaged, so neither this
 * process nor a helper it starts can read them. Returns the names removed.
 */
export function removeDeveloperOverrides(env: NodeJS.ProcessEnv, packaged: boolean): string[] {
  if (!packaged) {
    return [];
  }
  const removed: string[] = [];
  for (const name of PACKAGED_IGNORED_ENVIRONMENT_VARIABLES) {
    if (env[name] !== undefined) {
      delete env[name];
      removed.push(name);
    }
  }
  return removed;
}

/** The deterministic development key may encrypt secrets only in an unpackaged run that asked for it. */
export function isInsecureSecretFallbackAllowed(packaged: boolean | undefined, env: NodeJS.ProcessEnv = process.env): boolean {
  return packaged !== true && env.SHADOW_SSH_ALLOW_INSECURE_SECRET_FALLBACK === "1";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
