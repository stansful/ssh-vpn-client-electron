import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import packageJson from "../package.json";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ensureScript = path.join(repoRoot, "scripts", "ensure-xray-runtime.mjs");
const checksumsFile = path.join(repoRoot, "scripts", "xray-checksums.json");
const fixtures: string[] = [];
/** The fixture binary as the script names it, relative to the root and with this platform's separators. */
const fixtureBinary = path.join("resources", "xray", "linux", "x64", "xray");

afterEach(() => {
  while (fixtures.length > 0) {
    rmSync(fixtures.pop()!, { recursive: true, force: true });
  }
});

function sha256(contents: Buffer | string): string {
  return createHash("sha256").update(contents).digest("hex");
}

function fixtureRoot(binary: string | undefined, recorded: Record<string, string>): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "xray-gate-"));
  fixtures.push(root);
  mkdirSync(path.join(root, "scripts"), { recursive: true });
  writeFileSync(
    path.join(root, "scripts", "xray-checksums.json"),
    JSON.stringify({ version: "v0.0.1", archives: {}, executables: recorded })
  );
  if (binary !== undefined) {
    const directory = path.join(root, "resources", "xray", "linux", "x64");
    mkdirSync(directory, { recursive: true });
    writeFileSync(path.join(directory, "xray"), binary);
  }
  return root;
}

function runEnsure(args: string[], root?: string): { status: number | null; output: string } {
  const env = { ...process.env };
  if (root) {
    env.SHADOW_SSH_PROJECT_ROOT = root;
  } else {
    delete env.SHADOW_SSH_PROJECT_ROOT;
  }
  const result = spawnSync(process.execPath, [ensureScript, ...args], { env, encoding: "utf8" });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

// The Xray binaries are committed and shipped as they are, so a recorded hash
// is the only thing that says the release carries the pinned upstream build.
describe("xray runtime gate", () => {
  it("pins the download to the release whose checksums are recorded", () => {
    const checksums = JSON.parse(readFileSync(checksumsFile, "utf8"));
    const downloader = readFileSync(path.join(repoRoot, "scripts", "download-xray-runtime.mjs"), "utf8");

    expect(checksums.version).toMatch(/^v\d+\.\d+\.\d+$/u);
    expect(downloader).toContain(`const pinnedVersion = "${checksums.version}";`);
    expect(downloader).toContain("Xray-core/releases/tags/${pinnedVersion}");
    expect(downloader).not.toMatch(/Xray-core\/releases\/latest/u);
    expect(downloader).toContain("SHA-256 mismatch");
    expect(downloader).toContain("--trust-download");
    expect(Object.keys(checksums.executables).sort()).toEqual(
      ["linux/arm64", "linux/x64", "macos/arm64", "macos/x64", "windows/arm64", "windows/x64"]
    );
    expect(Object.keys(checksums.archives)).toHaveLength(6);
    for (const digest of [...Object.values(checksums.executables), ...Object.values(checksums.archives)]) {
      expect(digest).toMatch(/^[0-9a-f]{64}$/u);
    }
  });

  it("accepts the committed binaries", () => {
    const { status, output } = runEnsure(["--all"]);
    expect(status, output).toBe(0);
    expect(output).toContain("Xray runtime OK: windows/x64");
    expect(output).toContain("Xray runtime OK: linux/arm64");
  });

  it("accepts a binary that matches its recorded hash", () => {
    const { status, output } = runEnsure(["--target", "linux/x64"], fixtureRoot("xray", { "linux/x64": sha256("xray") }));
    expect(status, output).toBe(0);
    expect(output).toContain("Xray runtime OK: linux/x64 (v0.0.1)");
  });

  it("rejects a replaced binary", () => {
    const { status, output } = runEnsure(["--target", "linux/x64"], fixtureRoot("not xray", { "linux/x64": sha256("xray") }));
    expect(status).not.toBe(0);
    expect(output).toContain(`${fixtureBinary} does not match the recorded SHA-256`);
    expect(output).toContain("npm run xray:download-all");
  });

  it("rejects a binary with no recorded hash", () => {
    const { status, output } = runEnsure(["--target", "linux/x64"], fixtureRoot("xray", {}));
    expect(status).not.toBe(0);
    expect(output).toContain(`${fixtureBinary} has no recorded SHA-256`);
  });

  it("still reports a missing binary first", () => {
    const { status, output } = runEnsure(["--target", "linux/x64"], fixtureRoot(undefined, { "linux/x64": sha256("xray") }));
    expect(status).not.toBe(0);
    expect(output).toContain("Xray runtime is missing");
  });

  it("is checked before every package build", () => {
    expect(packageJson.scripts["xray:ensure"]).toBe("node scripts/ensure-xray-runtime.mjs");
    expect(packageJson.scripts["package:prepare"]).toMatch(/^npm run xray:ensure -- --all && /u);
  });
});
