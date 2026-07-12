import { EventEmitter } from "node:events";
import type { Server } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { RoutingRule } from "../src/shared/types.js";

type ExecCallback = (error: NodeJS.ErrnoException | null, stdout: string, stderr: string) => void;

const childProcessMocks = vi.hoisted(() => ({
  execFile: vi.fn<(
    command: string,
    args: string[],
    options: { timeout?: number; maxBuffer?: number; windowsHide?: boolean },
    callback: ExecCallback
  ) => void>()
}));

vi.mock("node:child_process", () => ({ execFile: childProcessMocks.execFile }));

import { WindowsSystemProxyManager } from "../src/core/network/windows-system-proxy.js";

const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
let registry = new Map<string, string>();
let failCommand: ((command: string, args: string[]) => boolean) | undefined;

describe("WindowsSystemProxyManager lifecycle", () => {
  beforeEach(() => {
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    registry = new Map([
      ["ProxyEnable", "0"],
      ["ProxyServer", "corp.proxy:8080"],
      ["ProxyOverride", "<local>"],
      ["AutoConfigURL", "https://corp.example/proxy.pac"],
      ["AutoDetect", "1"]
    ]);
    failCommand = undefined;
    childProcessMocks.execFile.mockReset();
    childProcessMocks.execFile.mockImplementation(runFakeWindowsCommand);
  });

  afterAll(() => {
    if (originalPlatform) {
      Object.defineProperty(process, "platform", originalPlatform);
    }
  });

  it("keeps the PAC alive when restoring registry state fails", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-restore-"));
    const fakeServer = new FakePacServer();
    const manager = createManager(directory, fakeServer);
    try {
      await manager.apply(pacRequest());
      const pacUrl = registry.get("AutoConfigURL");
      expect(pacUrl).toMatch(/^http:\/\/127\.0\.0\.1:/u);

      failCommand = (_command, args) => isRegAdd(args, "ProxyEnable", "0");
      await expect(manager.restore()).rejects.toThrow(/reg\.exe/u);
      expect(fakeServer.listening).toBe(true);

      failCommand = undefined;
      await manager.restore();
    } finally {
      failCommand = undefined;
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("keeps the old PAC alive until a static proxy switch succeeds", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-switch-"));
    const fakeServer = new FakePacServer();
    const manager = createManager(directory, fakeServer);
    try {
      await manager.apply(pacRequest());
      expect(registry.get("AutoConfigURL")).toMatch(/^http:\/\/127\.0\.0\.1:/u);
      failCommand = (_command, args) => isRegAdd(args, "ProxyEnable", "1");

      await expect(manager.apply(staticRequest())).rejects.toThrow(/reg\.exe/u);
      expect(fakeServer.listening).toBe(true);

      failCommand = undefined;
      await manager.apply(staticRequest());
      expect(registry.get("ProxyEnable")).toBe("1");
      expect(registry.has("AutoConfigURL")).toBe(false);
    } finally {
      failCommand = undefined;
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("keeps the recovery journal when deleting an app-owned value fails", async () => {
    registry.delete("ProxyServer");
    registry.delete("AutoConfigURL");
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-delete-"));
    const manager = new WindowsSystemProxyManager({ pacDirectory: directory });
    const journalPath = path.join(directory, "windows-proxy-snapshot.json");
    try {
      await manager.apply(staticRequest());
      failCommand = (_command, args) => isRegDelete(args, "ProxyServer");

      await expect(manager.restore()).rejects.toThrow(/reg\.exe/u);
      expect(await readFile(journalPath, "utf8")).toContain("proxyEnable");
      expect(registry.get("ProxyServer")).toContain("127.0.0.1:1080");

      failCommand = undefined;
      await manager.restore();
      expect(registry.has("ProxyServer")).toBe(false);
    } finally {
      failCommand = undefined;
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("restores the snapshot after a post-listen PAC server error", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-error-"));
    const fakeServer = new FakePacServer();
    const manager = createManager(directory, fakeServer);
    try {
      await manager.apply(pacRequest());
      fakeServer.emit("error", new Error("listener failed"));

      await vi.waitFor(() => {
        expect(registry.get("AutoConfigURL")).toBe("https://corp.example/proxy.pac");
        expect(fakeServer.listening).toBe(false);
      });
    } finally {
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("bounds every Windows helper process and does not mutate WinHTTP", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-command-"));
    const manager = new WindowsSystemProxyManager({ pacDirectory: directory });
    try {
      await manager.apply(staticRequest());
      expect(childProcessMocks.execFile).toHaveBeenCalled();
      for (const [command, , options] of childProcessMocks.execFile.mock.calls) {
        expect(options).toMatchObject({ timeout: 15_000, maxBuffer: 1024 * 1024, windowsHide: true });
        expect(command.toLowerCase()).not.toContain("netsh");
      }
    } finally {
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects non-loopback or invalid system proxy endpoints before registry changes", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-endpoint-"));
    const manager = new WindowsSystemProxyManager({ pacDirectory: directory });
    try {
      await expect(manager.apply({ ...staticRequest(), socksHost: "proxy.example" })).rejects.toThrow(/loopback/u);
      await expect(manager.apply({ ...staticRequest(), socksPort: 0 })).rejects.toThrow(/port/u);
      expect(childProcessMocks.execFile).not.toHaveBeenCalled();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("refuses a malformed recovery journal instead of deleting user proxy values", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-journal-"));
    await writeFile(
      path.join(directory, "windows-proxy-snapshot.json"),
      JSON.stringify({ journalVersion: 1, proxyEnable: "not-a-dword" }),
      "utf8"
    );
    const manager = new WindowsSystemProxyManager({ pacDirectory: directory });
    try {
      await expect(manager.apply(staticRequest())).rejects.toThrow(/DWORD/u);
      expect(childProcessMocks.execFile).not.toHaveBeenCalled();
      expect(registry.get("ProxyServer")).toBe("corp.proxy:8080");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

function runFakeWindowsCommand(
  command: string,
  args: string[],
  _options: { timeout?: number; maxBuffer?: number; windowsHide?: boolean },
  callback: ExecCallback
): void {
  if (failCommand?.(command, args)) {
    callback(Object.assign(new Error("simulated access denied"), { code: "EACCES" }), "", "Access is denied.");
    return;
  }
  if (command.toLowerCase() === "powershell.exe") {
    callback(null, "", "");
    return;
  }
  if (command.toLowerCase() !== "reg.exe") {
    callback(Object.assign(new Error(`unexpected command ${command}`), { code: "EFAIL" }), "", "Unexpected command.");
    return;
  }

  const action = args[0]?.toLowerCase();
  const valueIndex = args.indexOf("/v");
  const valueName = valueIndex >= 0 ? args[valueIndex + 1] : undefined;
  if (action === "query" && !valueName) {
    callback(null, "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\n", "");
    return;
  }
  if (action === "query" && valueName) {
    const value = registry.get(valueName);
    if (value === undefined) {
      callback(Object.assign(new Error("value not found"), { code: "ENOENT" }), "", "Value not found.");
      return;
    }
    const type = valueName === "ProxyEnable" || valueName === "AutoDetect" ? "REG_DWORD" : "REG_SZ";
    callback(null, `    ${valueName}    ${type}    ${value}\n`, "");
    return;
  }
  if (action === "add" && valueName) {
    const dataIndex = args.indexOf("/d");
    registry.set(valueName, args[dataIndex + 1] ?? "");
    callback(null, "The operation completed successfully.\n", "");
    return;
  }
  if (action === "delete" && valueName) {
    registry.delete(valueName);
    callback(null, "The operation completed successfully.\n", "");
    return;
  }
  callback(Object.assign(new Error("unsupported fake reg command"), { code: "EFAIL" }), "", "Unsupported command.");
}

function isRegAdd(args: string[], name: string, value: string): boolean {
  return args[0]?.toLowerCase() === "add" && valueAfter(args, "/v") === name && valueAfter(args, "/d") === value;
}

function isRegDelete(args: string[], name: string): boolean {
  return args[0]?.toLowerCase() === "delete" && valueAfter(args, "/v") === name;
}

function valueAfter(args: string[], marker: string): string | undefined {
  const index = args.indexOf(marker);
  return index >= 0 ? args[index + 1] : undefined;
}

function pacRequest() {
  return {
    mode: "selected-rules" as const,
    rules: [routingRule()],
    socksHost: "127.0.0.1",
    socksPort: 1080,
    proxyProtocol: "mixed" as const
  };
}

function staticRequest() {
  return {
    mode: "proxy-all" as const,
    rules: [] as RoutingRule[],
    socksHost: "127.0.0.1",
    socksPort: 1080,
    proxyProtocol: "mixed" as const
  };
}

function routingRule(): RoutingRule {
  return {
    id: "rule",
    type: "domain",
    value: "example.com",
    enabled: true,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z"
  };
}

function createManager(directory: string, server: FakePacServer): WindowsSystemProxyManager {
  return new WindowsSystemProxyManager({
    pacDirectory: directory,
    pacServerFactory: () => server as unknown as Server
  });
}

class FakePacServer extends EventEmitter {
  listening = false;
  readonly port = 31_080;

  listen(_port: number, _host: string, callback: () => void): this {
    this.listening = true;
    callback();
    return this;
  }

  address(): { address: string; family: string; port: number } | null {
    return this.listening ? { address: "127.0.0.1", family: "IPv4", port: this.port } : null;
  }

  close(callback?: (error?: Error) => void): this {
    this.listening = false;
    callback?.();
    return this;
  }

  closeAllConnections(): void {}

  closeIdleConnections(): void {}
}
