import { execFile } from "node:child_process";

export const WINDOWS_POWERSHELL_STDIN_ARGS = [
  "-NoLogo",
  "-NoProfile",
  "-NonInteractive",
  "-ExecutionPolicy",
  "Bypass",
  "-Command",
  "-"
] as const;

export interface WindowsPowerShellRunOptions {
  timeoutMs: number;
  maxBufferBytes: number;
}

/**
 * Sends PowerShell source through stdin instead of the Windows process command
 * line, whose UTF-16 length is limited to 32,767 characters.
 */
export function runWindowsPowerShellScript(
  script: string,
  options: WindowsPowerShellRunOptions
): Promise<string> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error: Error | null, stdout = ""): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (error) {
        reject(error);
      } else {
        resolve(stdout);
      }
    };
    const child = execFile(
      "powershell.exe",
      [...WINDOWS_POWERSHELL_STDIN_ARGS],
      {
        encoding: "utf8",
        timeout: options.timeoutMs,
        maxBuffer: options.maxBufferBytes,
        windowsHide: true
      },
      (error, stdout) => finish(error, stdout)
    );
    if (!child.stdin) {
      child.kill();
      finish(new Error("PowerShell stdin is unavailable."));
      return;
    }
    child.stdin.once("error", (error) => {
      child.kill();
      finish(error);
    });
    // `powershell.exe -Command -` otherwise executes stdin one statement at a
    // time. One outer script block makes PowerShell 5.1 parse multiline
    // if/elseif and pipeline constructs as a complete program first.
    child.stdin.end(`& {\n${script}\n}\n`, "utf8");
  });
}
