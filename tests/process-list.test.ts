import { describe, expect, it } from "vitest";
import { MAX_LISTED_PROCESSES, parsePosixProcessList, parseWindowsTasklist } from "../src/main/processes.js";

describe("running process list", () => {
  it("keeps Windows executables only, unique and sorted", () => {
    const stdout = [
      '"System Idle Process","0","Services","0","8 K"',
      '"System","4","Services","0","144 K"',
      '"Registry","92","Services","0","52,124 K"',
      '"Telegram.exe","4120","Console","1","210,404 K"',
      '"chrome.exe","5012","Console","1","120,044 K"',
      '"chrome.exe","5013","Console","1","80,044 K"',
      ""
    ].join("\r\n");
    expect(parseWindowsTasklist(stdout)).toEqual(["chrome.exe", "Telegram.exe"]);
  });

  it("reduces macOS paths to names and leaves Linux kernel threads out", () => {
    const stdout = [
      "/Applications/Safari.app/Contents/MacOS/Safari",
      "/usr/sbin/sshd",
      "firefox",
      "kworker/0:1-events",
      "Web Content",
      "   ",
      "firefox"
    ].join("\n");
    expect(parsePosixProcessList(stdout)).toEqual(["firefox", "Safari", "sshd", "Web Content"]);
  });

  it("bounds the list", () => {
    const stdout = Array.from({ length: MAX_LISTED_PROCESSES + 50 }, (_, index) => `proc-${String(index).padStart(5, "0")}`).join("\n");
    expect(parsePosixProcessList(stdout)).toHaveLength(MAX_LISTED_PROCESSES);
  });
});
