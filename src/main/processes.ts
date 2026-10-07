import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/** Bounds the IPC payload for the running-apps picker. */
export const MAX_LISTED_PROCESSES = 2_000;

export async function listActiveProcesses(): Promise<string[]> {
  if (process.platform === "win32") {
    return listWindowsProcesses();
  }

  return listPosixProcesses();
}

async function listWindowsProcesses(): Promise<string[]> {
  const { stdout } = await execFileAsync("tasklist", ["/fo", "csv", "/nh"], {
    windowsHide: true,
    timeout: 5000
  });
  return parseWindowsTasklist(stdout);
}

async function listPosixProcesses(): Promise<string[]> {
  const { stdout } = await execFileAsync("ps", ["-ax", "-o", "comm="], {
    timeout: 5000
  });
  return parsePosixProcessList(stdout);
}

/**
 * `tasklist /fo csv /nh` output to executable names. Only `.exe` images can
 * match a process rule, so "System", "Registry" and friends are left out.
 */
export function parseWindowsTasklist(stdout: string): string[] {
  return uniqueSorted(
    stdout
      .split(/\r?\n/)
      .map((line) => parseCsvFirstCell(line))
      .filter((name) => /\.exe$/iu.test(name))
  );
}

/**
 * `ps -o comm=` output to process names. macOS prints full paths, Linux prints
 * the bare command name, which may itself contain "/" (kernel threads such as
 * "kworker/0:1"); only a path is reduced to its last segment.
 */
export function parsePosixProcessList(stdout: string): string[] {
  return uniqueSorted(
    stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .map((line) => (line.startsWith("/") ? path.posix.basename(line) : line))
      .filter((name) => name.length > 0 && !name.includes("/"))
  );
}

function parseCsvFirstCell(line: string): string {
  const trimmed = line.trim();
  if (!trimmed) {
    return "";
  }

  if (trimmed.startsWith("\"")) {
    const end = trimmed.indexOf("\",", 1);
    return end >= 0 ? trimmed.slice(1, end) : trimmed.replace(/^"|"$/g, "");
  }

  return trimmed.split(",")[0] ?? "";
}

function uniqueSorted(values: string[]): string[] {
  return Array.from(new Set(values))
    .sort((a, b) => a.localeCompare(b))
    .slice(0, MAX_LISTED_PROCESSES);
}
