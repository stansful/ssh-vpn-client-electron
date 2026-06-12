import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

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

  return uniqueSorted(
    stdout
      .split(/\r?\n/)
      .map((line) => parseCsvFirstCell(line))
      .filter(Boolean)
  );
}

async function listPosixProcesses(): Promise<string[]> {
  const { stdout } = await execFileAsync("ps", ["-ax", "-o", "comm="], {
    timeout: 5000
  });

  return uniqueSorted(
    stdout
      .split(/\r?\n/)
      .map((line) => path.basename(line.trim()))
      .filter(Boolean)
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
  return Array.from(new Set(values)).sort((a, b) => a.localeCompare(b));
}
