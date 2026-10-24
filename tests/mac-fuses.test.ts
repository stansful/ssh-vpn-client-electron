import path from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it, vi } from "vitest";
import packageJson from "../package.json";

// The macOS fuses are flipped in the afterPack hook, with only Electron
// Framework re-signed: a bundle re-signed whole changes its Keychain identity
// with every release, and macOS asks for "Shadow SSH Safe Storage" again
// after each update.

interface MacFusesModule {
  MAC_FUSE_FRAMEWORK: string;
  flipMacFusesKeepingSignature(
    context: unknown,
    seams?: { run?: (command: string, args: string[]) => { status: number | null; stderr?: string; error?: Error }; platform?: string }
  ): Promise<void>;
}

const macFuses = (await import(pathToFileURL(path.resolve("scripts/mac-fuses.mjs")).href)) as MacFusesModule;

function packContext(electronPlatformName: string, electronFuses: Record<string, unknown> = packageJson.build.electronFuses) {
  const flipped: unknown[] = [];
  return {
    flipped,
    context: {
      electronPlatformName,
      appOutDir: "/out/mac-arm64",
      packager: {
        config: { electronFuses },
        appInfo: { productFilename: "Shadow" },
        generateFuseConfig: vi.fn(async (fuses: Record<string, unknown>) => ({ version: "1", ...fuses })),
        addElectronFuses: vi.fn(async (_context: unknown, config: unknown) => {
          flipped.push(config);
        })
      }
    }
  };
}

describe("macOS fuses", () => {
  it("flips the fuses and re-signs only Electron Framework, never the whole bundle", async () => {
    const { context, flipped } = packContext("darwin");
    const run = vi.fn(() => ({ status: 0 }));
    await macFuses.flipMacFusesKeepingSignature(context, { run, platform: "darwin" });

    expect(flipped).toEqual([expect.objectContaining({ runAsNode: false, resetAdHocDarwinSignature: false })]);
    expect(run).toHaveBeenCalledTimes(2);
    const [command, args] = run.mock.calls[1] as unknown as [string, string[]];
    expect(command).toBe("codesign");
    expect(args).toContain("--sign");
    expect(args).not.toContain("--deep");
    expect(args.at(-1)).toBe(path.join("/out/mac-arm64", "Shadow.app", macFuses.MAC_FUSE_FRAMEWORK));
  });

  it("flips the fuses of an unsigned (x64) Electron Framework without signing it", async () => {
    const { context, flipped } = packContext("darwin");
    const framework = path.join("/out/mac-arm64", "Shadow.app", macFuses.MAC_FUSE_FRAMEWORK);
    const run = vi.fn(() => ({ status: 1, stderr: `${framework}: code object is not signed at all` }));
    await macFuses.flipMacFusesKeepingSignature(context, { run, platform: "darwin" });

    expect(flipped).toHaveLength(1);
    expect(run).toHaveBeenCalledTimes(1);
    const [, args] = run.mock.calls[0] as unknown as [string, string[]];
    expect(args).not.toContain("--sign");
  });

  it("leaves Windows and Linux to electron-builder", async () => {
    for (const platform of ["win32", "linux"]) {
      const { context, flipped } = packContext(platform);
      const run = vi.fn(() => ({ status: 0 }));
      await macFuses.flipMacFusesKeepingSignature(context, { run, platform: "darwin" });
      expect(flipped).toEqual([]);
      expect(run).not.toHaveBeenCalled();
    }
  });

  it("refuses a whole-bundle re-signature, and a failed codesign", async () => {
    await expect(
      macFuses.flipMacFusesKeepingSignature(packContext("darwin", { ...packageJson.build.electronFuses, resetAdHocDarwinSignature: true }).context, {
        run: () => ({ status: 0 }),
        platform: "darwin"
      })
    ).rejects.toThrow(/resetAdHocDarwinSignature must be false/u);
    await expect(
      macFuses.flipMacFusesKeepingSignature(packContext("darwin").context, { run: () => ({ status: 1, stderr: "no identity" }), platform: "darwin" })
    ).rejects.toThrow(/no identity/u);
  });

  it("is the afterPack hook, after the runtime is pruned", () => {
    expect(packageJson.build.afterPack).toBe("./scripts/after-pack.mjs");
    expect(packageJson.build.electronFuses.resetAdHocDarwinSignature).toBe(false);
  });
});
