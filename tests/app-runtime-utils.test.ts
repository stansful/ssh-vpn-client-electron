import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RotatingFileLog, readFileTail } from "../src/main/app/rotating-file-log.js";
import { acquireSingleInstanceLock } from "../src/main/app/single-instance.cjs";

describe("RotatingFileLog", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(cleanupDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it("serializes concurrent writes and rotates bounded files", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const filePath = path.join(directory, "main.log");
    const logger = new RotatingFileLog(filePath, { maxFileBytes: 160, maxReadBytes: 10_000, backupCount: 2 });

    await Promise.all(Array.from({ length: 80 }, (_, index) => logger.append(`entry-${String(index).padStart(2, "0")}`)));

    const files = (await readdir(directory)).filter((name) => name.startsWith("main.log"));
    expect(files.sort()).toEqual(["main.log", "main.log.1", "main.log.2"]);
    for (const file of files) {
      const info = await stat(path.join(directory, file));
      expect(info.size).toBeLessThanOrEqual(160);
      if (process.platform !== "win32") {
        expect(info.mode & 0o777).toBe(0o600);
      }
    }
    const content = await logger.readTail();
    expect(content).toContain("entry-79");
    expect(content).not.toContain("entry-00");
    await logger.close();
  });

  it("orders clear after queued appends and removes rotations", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const filePath = path.join(directory, "main.log");
    const logger = new RotatingFileLog(filePath, { maxFileBytes: 32, backupCount: 2 });

    const writes = Promise.all(Array.from({ length: 20 }, (_, index) => logger.append(`line-${index}`)));
    const cleared = logger.clear();
    await Promise.all([writes, cleared]);

    expect(await readFile(filePath, "utf8")).toBe("");
    expect(await readdir(directory)).toEqual(["main.log"]);
  });

  it("reads only complete lines from a bounded tail", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const filePath = path.join(directory, "main.log");
    const logger = new RotatingFileLog(filePath, { maxFileBytes: 1024, backupCount: 0 });
    await logger.append("first-line");
    await logger.append("second-line");

    const tail = await readFileTail(filePath, 14);
    expect(tail.bytesRead).toBe(14);
    expect(tail.content).toBe("second-line\n");
    await logger.close();
  });

  it("orders close with queued appends and lazily reopens afterward", async () => {
    const directory = await makeTempDir(cleanupDirs);
    const filePath = path.join(directory, "main.log");
    const logger = new RotatingFileLog(filePath, { maxFileBytes: 1024, backupCount: 1 });

    const first = logger.append("before-close");
    const closed = logger.close();
    const second = logger.append("after-close");
    await Promise.all([first, closed, second]);
    await logger.close();

    expect(await readFile(filePath, "utf8")).toBe("before-close\nafter-close\n");
  });
});

describe("single instance guard", () => {
  it("exits a secondary application immediately without starting it", () => {
    const exit = vi.fn();
    const acquired = acquireSingleInstanceLock({ requestSingleInstanceLock: () => false, exit }, { channel: "test" });

    expect(acquired).toBe(false);
    expect(exit).toHaveBeenCalledOnce();
    expect(exit).toHaveBeenCalledWith(0);
  });

  it("keeps the primary application running", () => {
    const exit = vi.fn();
    const acquired = acquireSingleInstanceLock({ requestSingleInstanceLock: () => true, exit });

    expect(acquired).toBe(true);
    expect(exit).not.toHaveBeenCalled();
  });
});

async function makeTempDir(cleanupDirs: string[]): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-runtime-"));
  cleanupDirs.push(directory);
  return directory;
}
