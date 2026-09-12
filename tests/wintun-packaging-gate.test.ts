import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import packageJson from "../package.json";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ensureScript = path.join(repoRoot, "scripts", "ensure-wintun.mjs");
const PE_MACHINE = { x64: 0x8664, arm64: 0xaa64 } as const;
const fixtures: string[] = [];

afterEach(() => {
  while (fixtures.length > 0) {
    rmSync(fixtures.pop()!, { recursive: true, force: true });
  }
});

/** The smallest file that still answers "which architecture is this?". */
function peStub(machine: number): Buffer {
  const buffer = Buffer.alloc(0x80);
  buffer.write("MZ", 0, "latin1");
  buffer.writeUInt32LE(0x40, 0x3c);
  buffer.write("PE\0\0", 0x40, "latin1");
  buffer.writeUInt16LE(machine, 0x44);
  return buffer;
}

function fixtureRoot(dlls: Partial<Record<"x64" | "arm64", Buffer>>): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "wintun-gate-"));
  fixtures.push(root);
  for (const [arch, contents] of Object.entries(dlls)) {
    const directory = path.join(root, "native", "windows", arch);
    mkdirSync(directory, { recursive: true });
    writeFileSync(path.join(directory, "wintun.dll"), contents!);
  }
  return root;
}

function runEnsure(root: string): { status: number | null; output: string } {
  const result = spawnSync(process.execPath, [ensureScript], {
    env: { ...process.env, SHADOW_SSH_PROJECT_ROOT: root },
    encoding: "utf8"
  });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

// A Windows build without the DLL is not visibly broken - it connects and
// falls back to the proxy path - so nothing but a hard failure keeps a release
// from shipping with no UDP and no process rules for proxy-unaware apps.
describe("wintun packaging gate", () => {
  it("fails when the DLL is missing, and names the command that fixes it", () => {
    const { status, output } = runEnsure(fixtureRoot({}));
    expect(status).not.toBe(0);
    expect(output).toContain("native/windows/x64/wintun.dll is missing");
    expect(output).toContain("npm run wintun:download");
    expect(output).toContain("UDP never enters the tunnel");
  });

  it("passes when both architectures are present and correct", () => {
    const { status, output } = runEnsure(
      fixtureRoot({ x64: peStub(PE_MACHINE.x64), arm64: peStub(PE_MACHINE.arm64) })
    );
    expect(status).toBe(0);
    expect(output).toContain("Wintun OK: windows/x64");
    expect(output).toContain("Wintun OK: windows/arm64");
  });

  // A DLL of the wrong architecture loads nowhere, and copying the amd64 one
  // into both folders is the easy mistake to make by hand.
  it("rejects a DLL built for the other architecture", () => {
    const { status, output } = runEnsure(
      fixtureRoot({ x64: peStub(PE_MACHINE.x64), arm64: peStub(PE_MACHINE.x64) })
    );
    expect(status).not.toBe(0);
    expect(output).toContain("native/windows/arm64/wintun.dll is PE machine 0x8664");
  });

  it("rejects an empty placeholder", () => {
    const { status, output } = runEnsure(
      fixtureRoot({ x64: Buffer.alloc(0), arm64: peStub(PE_MACHINE.arm64) })
    );
    expect(status).not.toBe(0);
    expect(output).toContain("native/windows/x64/wintun.dll is empty");
  });

  it("is wired into packaging, not left to a console warning", () => {
    expect(packageJson.scripts["wintun:download"]).toBe("node scripts/download-wintun.mjs");
    expect(packageJson.scripts["wintun:ensure"]).toBe("node scripts/ensure-wintun.mjs");

    // Every Windows bundle goes through this script, so the check cannot be
    // bypassed by packing one target directly.
    const packagingGate = readFileSync(path.join(repoRoot, "scripts", "electron-builder-with-local-dist.mjs"), "utf8");
    expect(packagingGate).toContain('platformFlag === "--win"');
    expect(packagingGate).toContain("wintun.dll");
    expect(packagingGate).toContain("npm run wintun:download");

    // And the built bundle is checked for it, not just the source tree.
    const artifactVerifier = readFileSync(path.join(repoRoot, "scripts", "verify-production-artifacts.mjs"), "utf8");
    expect(artifactVerifier).toContain('"wintun.dll"');
  });

  // A third-party signed binary must never be installed unverified.
  it("keeps a checksum file that the downloader verifies against", () => {
    const checksums = JSON.parse(readFileSync(path.join(repoRoot, "scripts", "wintun-checksums.json"), "utf8"));
    expect(checksums.archives).toBeTypeOf("object");
    const downloader = readFileSync(path.join(repoRoot, "scripts", "download-wintun.mjs"), "utf8");
    expect(downloader).toContain("SHA-256 mismatch");
    expect(downloader).toContain("--trust-download");
  });
});
