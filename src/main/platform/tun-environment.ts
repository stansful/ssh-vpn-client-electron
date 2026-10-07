import { execFile } from "node:child_process";
import { stat } from "node:fs/promises";
import path from "node:path";
import { wintunSearchDirectories } from "../../service/tun-routing.js";
import { createPlatformTarget } from "./targets.js";

/** What the TUN dataplane needs from the machine, for the Routing view's checklist. */
export interface TunEnvironment {
  /** TUN capture exists on this platform (Windows only today). */
  supported: boolean;
  /** The process runs with administrator rights. */
  elevated: boolean;
  /** `wintun.dll` is in one of the folders the helper searches. */
  wintunFound: boolean;
  /** The folders searched for `wintun.dll`, in the helper's order. */
  searchedPaths: string[];
}

export interface TunEnvironmentOptions {
  platform: NodeJS.Platform;
  /** Folder of the executable the user started (`path.dirname(process.execPath)`). */
  appDirectory: string;
  /** The application data folder: the one the transports get as `userDataDirectory`. */
  dataDirectory: string;
  /**
   * The folder that holds `native/windows/<arch>/` - `process.resourcesPath`
   * when packaged, the project root in development. The helper looks beside
   * its own binary first.
   */
  resourcesPath?: string;
  /** Defaults to `process.arch`. */
  arch?: string;
  /** Defaults to `PORTABLE_EXECUTABLE_DIR`. */
  portableExecutableDirectory?: string;
  /** Injection seams for tests. */
  isElevated?: () => Promise<boolean>;
  fileExists?: (filePath: string) => Promise<boolean>;
}

const WINTUN_DLL = "wintun.dll";
const ELEVATION_CHECK_TIMEOUT_MS = 5_000;

/**
 * Mirrors the native helper's own search (`internal/tun/search.go`): beside
 * the service binary, then the folders the app hands it in
 * `SHADOW_SSH_WINTUN_DIRS`. Reporting any other list would send the user to
 * put the file somewhere the helper never looks.
 */
export async function detectTunEnvironment(options: TunEnvironmentOptions): Promise<TunEnvironment> {
  if (options.platform !== "win32") {
    return { supported: false, elevated: false, wintunFound: false, searchedPaths: [] };
  }
  const searchedPaths = windowsWintunSearchPaths(options);
  const fileExists = options.fileExists ?? isFile;
  const [elevated, found] = await Promise.all([
    (options.isElevated ?? isWindowsProcessElevated)().catch(() => false),
    Promise.all(searchedPaths.map((directory) => fileExists(path.join(directory, WINTUN_DLL)).catch(() => false)))
  ]);
  return { supported: true, elevated, wintunFound: found.some(Boolean), searchedPaths };
}

function windowsWintunSearchPaths(options: TunEnvironmentOptions): string[] {
  const directories: string[] = [];
  if (options.resourcesPath) {
    const target = createPlatformTarget("win32", (options.arch ?? process.arch) as NodeJS.Architecture);
    directories.push(path.dirname(path.join(options.resourcesPath, target.serviceRelativePath)));
  }
  directories.push(
    ...wintunSearchDirectories(options.dataDirectory, {
      portableExecutableDirectory: options.portableExecutableDirectory,
      executableDirectory: options.appDirectory
    })
  );
  // Windows paths are case-insensitive, and the helper skips repeats the same way.
  const seen = new Set<string>();
  return directories.filter((directory) => {
    const key = directory.toLowerCase();
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

async function isFile(filePath: string): Promise<boolean> {
  try {
    return (await stat(filePath)).isFile();
  } catch {
    return false;
  }
}

/** An elevation answer, and whether it is worth keeping for the process lifetime. */
export interface ElevationAnswer {
  elevated: boolean;
  /** False when a tool timed out or could not start, which says nothing either way. */
  definite: boolean;
}

export type QuietRunner = (file: string, args: string[]) => Promise<string>;

/**
 * Elevation cannot change while the process lives, so a definite answer is
 * kept. A timeout or a tool that could not start is not an answer: it reads
 * as "not elevated" this time and is asked again on the next refresh.
 */
export function createElevationCheck(detect: () => Promise<ElevationAnswer>): () => Promise<boolean> {
  let cached: Promise<boolean> | undefined;
  return () => {
    if (!cached) {
      const check: Promise<boolean> = detect()
        .catch((): ElevationAnswer => ({ elevated: false, definite: false }))
        .then((answer) => {
          if (!answer.definite && cached === check) {
            cached = undefined;
          }
          return answer.elevated;
        });
      cached = check;
    }
    return cached;
  };
}

/**
 * Whether this process runs elevated. Being signed in as an administrator is
 * not enough: under UAC that account's processes run at medium integrity
 * until started with "Run as administrator".
 */
export const isWindowsProcessElevated = createElevationCheck(() => detectWindowsElevation(runQuietly));

export async function detectWindowsElevation(run: QuietRunner): Promise<ElevationAnswer> {
  const system32 = path.win32.join(process.env.SystemRoot ?? "C:\\Windows", "System32");
  try {
    const output = await run(path.win32.join(system32, "whoami.exe"), ["/groups", "/fo", "csv", "/nh"]);
    return { elevated: isElevatedIntegrityLevel(output), definite: true };
  } catch {
    // `net session` needs administrator rights, so its exit code answers the
    // same question where whoami is unavailable. It also fails when the
    // Server service is disabled, which errs towards "not elevated".
    try {
      await run(path.win32.join(system32, "net.exe"), ["session"]);
      return { elevated: true, definite: true };
    } catch (error) {
      return { elevated: false, definite: exitedWithCode(error) };
    }
  }
}

/** The tool ran to the end and said no, as opposed to timing out or never starting. */
function exitedWithCode(error: unknown): boolean {
  const failure = error as { code?: unknown; killed?: boolean; signal?: unknown } | undefined;
  return typeof failure?.code === "number" && !failure.killed && !failure.signal;
}

/**
 * Reads the mandatory label from `whoami /groups`: High (S-1-16-12288) or
 * System (S-1-16-16384) integrity means elevated. SIDs are the same in every
 * Windows display language, unlike the group names around them.
 */
export function isElevatedIntegrityLevel(whoamiGroupsOutput: string): boolean {
  return /\bS-1-16-(?:12288|16384)\b/u.test(whoamiGroupsOutput);
}

function runQuietly(file: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true, timeout: ELEVATION_CHECK_TIMEOUT_MS, encoding: "utf8" }, (error, stdout) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(stdout);
    });
  });
}
