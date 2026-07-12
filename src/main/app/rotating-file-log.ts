import { chmod, mkdir, open, rename, rm, stat, writeFile } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";

export interface RotatingFileLogOptions {
  maxFileBytes?: number;
  maxReadBytes?: number;
  backupCount?: number;
  maxMessageCharacters?: number;
}

const DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024;
const DEFAULT_MAX_READ_BYTES = 1024 * 1024;
const DEFAULT_BACKUP_COUNT = 2;
const DEFAULT_MAX_MESSAGE_CHARACTERS = 64 * 1024;

/**
 * A small serialized file logger. All mutations share one queue so rotation,
 * clear, and concurrent appends cannot race with each other.
 */
export class RotatingFileLog {
  private readonly maxFileBytes: number;
  private readonly maxReadBytes: number;
  private readonly backupCount: number;
  private readonly maxMessageCharacters: number;
  private queue: Promise<void> = Promise.resolve();
  private currentSize: number | undefined;
  private directoryReady = false;
  private filePermissionsEnsured = false;
  private appendHandle: FileHandle | undefined;

  constructor(
    readonly filePath: string,
    options: RotatingFileLogOptions = {}
  ) {
    this.maxFileBytes = positiveInteger(options.maxFileBytes, DEFAULT_MAX_FILE_BYTES);
    this.maxReadBytes = positiveInteger(options.maxReadBytes, DEFAULT_MAX_READ_BYTES);
    this.backupCount = nonNegativeInteger(options.backupCount, DEFAULT_BACKUP_COUNT);
    this.maxMessageCharacters = positiveInteger(options.maxMessageCharacters, DEFAULT_MAX_MESSAGE_CHARACTERS);
  }

  append(message: string): Promise<void> {
    return this.enqueue(async () => {
      const normalized = normalizeMessage(message, this.maxMessageCharacters);
      const bytes = Buffer.from(`${normalized}\n`, "utf8");
      await this.ensureDirectory();
      if (this.currentSize === undefined) {
        this.currentSize = await fileSize(this.filePath);
      }
      if (this.currentSize > 0 && this.currentSize + bytes.length > this.maxFileBytes) {
        await this.rotate();
      }

      const handle = await this.getAppendHandle();
      try {
        await handle.writeFile(bytes);
      } catch (error) {
        await this.closeAppendHandle().catch(() => undefined);
        throw error;
      }
      this.currentSize += bytes.length;
    });
  }

  readTail(): Promise<string> {
    return this.enqueue(async () => {
      const chunks: string[] = [];
      let remaining = this.maxReadBytes;
      for (let index = 0; index <= this.backupCount && remaining > 0; index += 1) {
        const candidate = index === 0 ? this.filePath : `${this.filePath}.${index}`;
        const result = await readFileTail(candidate, remaining);
        if (!result.content) {
          continue;
        }
        chunks.unshift(result.content);
        remaining -= result.bytesRead;
      }
      return chunks.join(chunks.length > 1 ? "\n" : "");
    });
  }

  clear(): Promise<void> {
    return this.enqueue(async () => {
      await this.ensureDirectory();
      await this.closeAppendHandle();
      await writeFile(this.filePath, "", { encoding: "utf8", mode: 0o600 });
      await chmod(this.filePath, 0o600);
      await Promise.all(
        Array.from({ length: this.backupCount }, (_, index) => rm(`${this.filePath}.${index + 1}`, { force: true }))
      );
      this.currentSize = 0;
      this.filePermissionsEnsured = true;
    });
  }

  /** Flushes and releases the lazy append handle during application shutdown. */
  close(): Promise<void> {
    return this.enqueue(() => this.closeAppendHandle());
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.queue.then(operation);
    this.queue = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  private async rotate(): Promise<void> {
    await this.closeAppendHandle();
    if (this.backupCount === 0) {
      await writeFile(this.filePath, "", "utf8");
      this.currentSize = 0;
      this.filePermissionsEnsured = false;
      return;
    }

    for (let index = this.backupCount; index >= 2; index -= 1) {
      const source = `${this.filePath}.${index - 1}`;
      const destination = `${this.filePath}.${index}`;
      await rm(destination, { force: true });
      await renameIfPresent(source, destination);
    }
    await rm(`${this.filePath}.1`, { force: true });
    await renameIfPresent(this.filePath, `${this.filePath}.1`);
    this.currentSize = 0;
    this.filePermissionsEnsured = false;
  }

  private async getAppendHandle(): Promise<FileHandle> {
    if (this.appendHandle) {
      return this.appendHandle;
    }
    const handle = await open(this.filePath, "a", 0o600);
    try {
      if (!this.filePermissionsEnsured) {
        await handle.chmod(0o600);
        this.filePermissionsEnsured = true;
      }
      this.appendHandle = handle;
      return handle;
    } catch (error) {
      await handle.close().catch(() => undefined);
      throw error;
    }
  }

  private async closeAppendHandle(): Promise<void> {
    const handle = this.appendHandle;
    this.appendHandle = undefined;
    if (handle) {
      await handle.close();
    }
  }

  private async ensureDirectory(): Promise<void> {
    if (this.directoryReady) {
      return;
    }
    await mkdir(path.dirname(this.filePath), { recursive: true });
    await Promise.all(
      Array.from({ length: this.backupCount + 1 }, (_, index) =>
        chmodIfPresent(index === 0 ? this.filePath : `${this.filePath}.${index}`, 0o600)
      )
    );
    this.directoryReady = true;
  }
}

export async function readFileTail(filePath: string, maxBytes = DEFAULT_MAX_READ_BYTES): Promise<{ content: string; bytesRead: number }> {
  let handle;
  try {
    handle = await open(filePath, "r");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { content: "", bytesRead: 0 };
    }
    throw error;
  }

  try {
    const info = await handle.stat();
    const bytesRead = Math.min(info.size, positiveInteger(maxBytes, DEFAULT_MAX_READ_BYTES));
    if (bytesRead === 0) {
      return { content: "", bytesRead: 0 };
    }
    const start = info.size - bytesRead;
    const buffer = Buffer.allocUnsafe(bytesRead);
    const result = await handle.read(buffer, 0, bytesRead, start);
    let content = buffer.subarray(0, result.bytesRead).toString("utf8");
    if (start > 0) {
      const firstNewline = content.indexOf("\n");
      content = firstNewline >= 0 ? content.slice(firstNewline + 1) : "";
    }
    return { content, bytesRead: result.bytesRead };
  } finally {
    await handle.close();
  }
}

async function fileSize(filePath: string): Promise<number> {
  try {
    return (await stat(filePath)).size;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return 0;
    }
    throw error;
  }
}

async function renameIfPresent(source: string, destination: string): Promise<void> {
  try {
    await rename(source, destination);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }
}

async function chmodIfPresent(filePath: string, mode: number): Promise<void> {
  try {
    await chmod(filePath, mode);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }
}

function normalizeMessage(value: string, maxCharacters: number): string {
  const flattened = value.replace(/[\r\n]+/gu, " ");
  return flattened.length <= maxCharacters ? flattened : `${flattened.slice(0, maxCharacters - 1)}…`;
}

function positiveInteger(value: number | undefined, fallback: number): number {
  return Number.isInteger(value) && Number(value) > 0 ? Number(value) : fallback;
}

function nonNegativeInteger(value: number | undefined, fallback: number): number {
  return Number.isInteger(value) && Number(value) >= 0 ? Number(value) : fallback;
}
