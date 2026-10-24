import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { IPC_CHANNELS } from "../src/shared/ipc.js";

const source = readFileSync("src/preload/preload.cts", "utf8");

describe("sandboxed preload bridge", () => {
  it("writes out exactly the shared IPC channels", () => {
    const block = source.match(/const IPC_CHANNELS: typeof SharedIpcChannels = \{([\s\S]*?)\n\};/u)?.[1];
    expect(block, "the channel table").toBeDefined();
    const channels = Object.fromEntries(
      [...(block ?? "").matchAll(/^\s*(\w+): "([^"]+)",?$/gmu)].map((match) => [match[1], match[2]])
    );
    expect(channels).toEqual({ ...IPC_CHANNELS });
  });

  it("loads nothing but electron at runtime", () => {
    const runtimeImports = [...source.matchAll(/^import (?!type )[^;]*? from "([^"]+)";$/gmu)].map((match) => match[1]);
    expect(runtimeImports).toEqual(["electron"]);
    expect(source).not.toMatch(/\brequire\(/u);
    expect(source).not.toMatch(/\bimport\(/u);
  });

  it("exposes one bridge object to the page", () => {
    expect(source).toContain('contextBridge.exposeInMainWorld("shadowSsh", api);');
    for (const name of Object.keys(IPC_CHANNELS).filter((key) => key !== "serviceEvent")) {
      expect(source, name).toContain(`ipcRenderer.invoke(IPC_CHANNELS.${name}`);
    }
  });
});
