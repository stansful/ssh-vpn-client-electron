import { beforeEach, describe, expect, it, vi } from "vitest";

const childProcess = vi.hoisted(() => ({ execFile: vi.fn() }));

vi.mock("node:child_process", () => ({ execFile: childProcess.execFile }));

import {
  runWindowsPowerShellScript,
  WINDOWS_POWERSHELL_STDIN_ARGS
} from "../src/core/network/windows-powershell.js";

describe("Windows PowerShell stdin runner", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("keeps an arbitrarily large script out of the Windows command line", async () => {
    const source = `$payload = '${"a".repeat(100_000)}'`;
    const stdin = {
      once: vi.fn().mockReturnThis(),
      end: vi.fn()
    };
    const child = { stdin, kill: vi.fn() };
    let callback: ((error: Error | null, stdout: string, stderr: string) => void) | undefined;
    childProcess.execFile.mockImplementation((_command, _args, _options, done) => {
      callback = done;
      return child;
    });

    const result = runWindowsPowerShellScript(source, { timeoutMs: 7000, maxBufferBytes: 1024 });

    expect(childProcess.execFile).toHaveBeenCalledWith(
      "powershell.exe",
      [...WINDOWS_POWERSHELL_STDIN_ARGS],
      expect.objectContaining({ timeout: 7000, maxBuffer: 1024, windowsHide: true }),
      expect.any(Function)
    );
    const commandArgs = childProcess.execFile.mock.calls[0]?.[1] as string[];
    expect(commandArgs.join(" ")).not.toContain(source.slice(0, 100));
    expect(stdin.end).toHaveBeenCalledWith(`& {\n${source}\n}\n`, "utf8");
    callback?.(null, "ok", "");
    await expect(result).resolves.toBe("ok");
  });
});
