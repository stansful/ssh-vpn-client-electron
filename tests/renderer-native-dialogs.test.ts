import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const RENDERER_SOURCE_ROOT = "src/renderer";
const BLOCKING_NATIVE_DIALOG = /\bwindow\s*\.\s*(?:alert|confirm|prompt)\s*\(/u;

describe("renderer dialogs", () => {
  it("does not use blocking browser dialogs that can poison Electron input focus", () => {
    const offenders = sourceFiles(RENDERER_SOURCE_ROOT).filter((filePath) =>
      BLOCKING_NATIVE_DIALOG.test(readFileSync(filePath, "utf8"))
    );

    expect(offenders).toEqual([]);
  });
});

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const filePath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      return sourceFiles(filePath);
    }
    return /\.tsx?$/u.test(entry.name) ? [filePath] : [];
  });
}
