import { EventEmitter } from "node:events";
import type { IncomingMessage, RequestListener, Server, ServerResponse } from "node:http";
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

  it("versions changed PAC content without restarting its listener", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-version-"));
    const fakeServer = new FakePacServer();
    const manager = createManager(directory, fakeServer);
    try {
      await manager.apply(pacRequest());
      const firstUrl = registry.get("AutoConfigURL");
      expect(firstUrl).toMatch(/\?v=[0-9a-f]{64}$/u);
      if (!firstUrl) {
        throw new Error("Versioned PAC URL was not registered.");
      }
      const firstPac = fakeServer.request(firstUrl);
      const firstProxyModeWrites = childProcessMocks.execFile.mock.calls.filter(
        ([command, args]) => command.toLowerCase() === "reg.exe" && isRegAdd(args, "ProxyEnable", "0")
      ).length;
      const commandCount = childProcessMocks.execFile.mock.calls.length;

      await manager.apply(pacRequest());
      expect(registry.get("AutoConfigURL")).toBe(firstUrl);
      expect(childProcessMocks.execFile).toHaveBeenCalledTimes(commandCount);
      expect(fakeServer.listenCalls).toBe(1);

      await manager.apply({ ...pacRequest(), rules: [routingRule("changed.example")] });
      const secondUrl = registry.get("AutoConfigURL");
      expect(secondUrl).toMatch(/\?v=[0-9a-f]{64}$/u);
      if (!firstUrl || !secondUrl) {
        throw new Error("Versioned PAC URL was not registered.");
      }

      const first = new URL(firstUrl);
      const second = new URL(secondUrl);
      expect(`${second.origin}${second.pathname}`).toBe(`${first.origin}${first.pathname}`);
      expect(second.searchParams.get("v")).not.toBe(first.searchParams.get("v"));
      expect(fakeServer.request(firstUrl)).toEqual(firstPac);
      expect(fakeServer.request(secondUrl).body).toContain("changed.example");
      expect(fakeServer.listenCalls).toBe(1);
      expect(fakeServer.closeCalls).toBe(0);
      expect(fakeServer.listening).toBe(true);
      expect(childProcessMocks.execFile.mock.calls.filter(
        ([command, args]) => command.toLowerCase() === "reg.exe" && isRegAdd(args, "ProxyEnable", "0")
      )).toHaveLength(firstProxyModeWrites);
    } finally {
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rotates the PAC endpoint for process-routing compatibility", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-process-rotation-"));
    const firstServer = new FakePacServer(31_080);
    const secondServer = new FakePacServer(31_081);
    const manager = createRotatingManager(directory, [firstServer, secondServer]);
    const request = { ...pacRequest(), forcePacEndpointRotation: true };
    try {
      await manager.apply(request);
      const firstUrl = registry.get("AutoConfigURL");
      await manager.apply({ ...request, rules: [routingRule("live-process-update.example")] });
      const secondUrl = registry.get("AutoConfigURL");

      expect(firstUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/shadow-ssh-routing\.pac$/u);
      expect(secondUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/shadow-ssh-routing\.pac$/u);
      expect(secondUrl).not.toBe(firstUrl);
      if (!firstUrl || !secondUrl) {
        throw new Error("Rotated PAC URL was not registered.");
      }
      expect(new URL(secondUrl).pathname).toBe(new URL(firstUrl).pathname);
      expect(new URL(secondUrl).port).not.toBe(new URL(firstUrl).port);
      expect(new URL(secondUrl).search).toBe("");
      expect(firstServer.listenCalls).toBe(1);
      expect(firstServer.closeCalls).toBe(0);
      expect(firstServer.listening).toBe(true);
      expect(firstServer.request(firstUrl).body).toContain("live-process-update.example");
      expect(secondServer.listenCalls).toBe(1);
      expect(secondServer.closeCalls).toBe(0);
      expect(childProcessMocks.execFile.mock.calls.filter(
        ([command, args]) => command.toLowerCase() === "reg.exe" && isRegAdd(args, "ProxyEnable", "0")
      )).toHaveLength(2);
    } finally {
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("keeps the previous process PAC endpoint when publishing the rotated URL fails", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-process-rollback-"));
    const firstServer = new FakePacServer(31_082);
    const secondServer = new FakePacServer(31_083);
    const thirdServer = new FakePacServer(31_087);
    const manager = createRotatingManager(directory, [firstServer, secondServer, thirdServer]);
    const request = { ...pacRequest(), forcePacEndpointRotation: true };
    try {
      await manager.apply(request);
      const firstUrl = registry.get("AutoConfigURL");
      if (!firstUrl) {
        throw new Error("Initial process PAC URL was not registered.");
      }
      await manager.apply({ ...request, rules: [routingRule("published.example")] });
      const secondUrl = registry.get("AutoConfigURL");
      if (!secondUrl) {
        throw new Error("Updated process PAC URL was not registered.");
      }
      const firstResponse = firstServer.request(firstUrl);
      const secondResponse = secondServer.request(secondUrl);
      expect(firstResponse.body).toContain("published.example");
      expect(secondResponse.body).toContain("published.example");
      failCommand = (command, args) =>
        command.toLowerCase() === "reg.exe" &&
        args[0]?.toLowerCase() === "add" &&
        valueAfter(args, "/v") === "AutoConfigURL";

      await expect(
        manager.apply({ ...request, rules: [routingRule("unpublished.example")] })
      ).rejects.toThrow(/reg\.exe/u);

      expect(registry.get("AutoConfigURL")).toBe(secondUrl);
      expect(firstServer.listening).toBe(true);
      expect(firstServer.request(firstUrl)).toEqual(firstResponse);
      expect(secondServer.listening).toBe(true);
      expect(secondServer.request(secondUrl)).toEqual(secondResponse);
      expect(thirdServer.listening).toBe(false);
      expect(thirdServer.closeCalls).toBe(1);
    } finally {
      failCommand = undefined;
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("keeps both process PAC endpoints alive until a failed WinINet notification is retried", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-process-notify-retry-"));
    const firstServer = new FakePacServer(31_084);
    const secondServer = new FakePacServer(31_085);
    const thirdServer = new FakePacServer(31_086);
    const manager = createRotatingManager(directory, [firstServer, secondServer, thirdServer]);
    const request = { ...pacRequest(), forcePacEndpointRotation: true };
    try {
      await manager.apply(request);
      const firstUrl = registry.get("AutoConfigURL");
      if (!firstUrl) {
        throw new Error("Initial process PAC URL was not registered.");
      }

      failCommand = (command) => command.toLowerCase() === "powershell.exe";
      await expect(manager.apply(request)).rejects.toThrow(/powershell\.exe/u);
      const failedNotificationUrl = registry.get("AutoConfigURL");
      if (!failedNotificationUrl) {
        throw new Error("Rotated process PAC URL was not registered.");
      }

      expect(failedNotificationUrl).not.toBe(firstUrl);
      expect(firstServer.listening).toBe(true);
      expect(secondServer.listening).toBe(true);
      expect(firstServer.request(firstUrl).statusCode).toBe(200);
      expect(secondServer.request(failedNotificationUrl).statusCode).toBe(200);

      await expect(
        manager.apply({ ...request, rules: [routingRule("newer-process-ip.example")] })
      ).rejects.toThrow(/powershell\.exe/u);
      expect(thirdServer.listenCalls).toBe(0);
      expect(firstServer.listening).toBe(true);
      expect(secondServer.listening).toBe(true);

      failCommand = undefined;
      await manager.apply({ ...request, rules: [routingRule("newer-process-ip.example")] });

      expect(firstServer.listening).toBe(true);
      expect(secondServer.listening).toBe(true);
      expect(thirdServer.listening).toBe(true);
      expect(firstServer.closeCalls).toBe(0);
      expect(secondServer.closeCalls).toBe(0);
      expect(secondServer.listenCalls).toBe(1);
      expect(thirdServer.listenCalls).toBe(1);
      expect(registry.get("AutoConfigURL")).not.toBe(failedNotificationUrl);
      const finalUrl = registry.get("AutoConfigURL");
      if (!finalUrl) {
        throw new Error("Final process PAC URL was not registered.");
      }
      expect(thirdServer.request(finalUrl).body).toContain("newer-process-ip.example");
      expect(firstServer.request(firstUrl).body).toContain("newer-process-ip.example");
      expect(secondServer.request(failedNotificationUrl).body).toContain("newer-process-ip.example");
    } finally {
      failCommand = undefined;
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("bounds retained process PAC endpoints and closes every endpoint on restore", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-process-retention-"));
    const servers = Array.from({ length: 6 }, (_, index) => new FakePacServer(31_090 + index));
    const manager = createRotatingManager(directory, servers);
    const request = { ...pacRequest(), forcePacEndpointRotation: true };
    const urls: string[] = [];
    try {
      for (let revision = 0; revision < servers.length; revision += 1) {
        await manager.apply({ ...request, rules: [routingRule(`process-revision-${revision}.example`)] });
        const url = registry.get("AutoConfigURL");
        if (!url) {
          throw new Error("Rotated process PAC URL was not registered.");
        }
        urls.push(url);
      }

      expect(servers[0].listening).toBe(false);
      expect(servers[0].closeCalls).toBe(1);
      for (let index = 1; index < servers.length; index += 1) {
        expect(servers[index].listening).toBe(true);
        expect(servers[index].closeCalls).toBe(0);
        expect(servers[index].request(urls[index]).body).toContain("process-revision-5.example");
      }

      await manager.restore();

      for (const server of servers) {
        expect(server.listening).toBe(false);
        expect(server.closeCalls).toBe(1);
      }
    } finally {
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("keeps the registered PAC version immutable when publishing a revision fails", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-transaction-"));
    const fakeServer = new FakePacServer();
    const manager = createManager(directory, fakeServer);
    try {
      await manager.apply(pacRequest());
      const registeredUrl = registry.get("AutoConfigURL");
      if (!registeredUrl) {
        throw new Error("Versioned PAC URL was not registered.");
      }
      const originalResponse = fakeServer.request(registeredUrl);
      expect(originalResponse.statusCode).toBe(200);
      expect(originalResponse.body).toContain("example.com");

      failCommand = (command, args) =>
        command.toLowerCase() === "reg.exe" &&
        args[0]?.toLowerCase() === "add" &&
        valueAfter(args, "/v") === "AutoConfigURL";
      await expect(manager.apply({ ...pacRequest(), rules: [routingRule("changed.example")] })).rejects.toThrow(/reg\.exe/u);

      expect(registry.get("AutoConfigURL")).toBe(registeredUrl);
      expect(fakeServer.request(registeredUrl)).toEqual(originalResponse);

      failCommand = undefined;
      await manager.apply({ ...pacRequest(), rules: [routingRule("changed.example")] });
      const recoveredUrl = registry.get("AutoConfigURL");
      expect(recoveredUrl).not.toBe(registeredUrl);
      if (!recoveredUrl) {
        throw new Error("Recovered PAC URL was not registered.");
      }
      expect(fakeServer.request(recoveredUrl).body).toContain("changed.example");
    } finally {
      failCommand = undefined;
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("retains every PAC version produced by the initial discovery burst", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-retention-"));
    const fakeServer = new FakePacServer();
    const manager = createManager(directory, fakeServer);
    try {
      await manager.apply(pacRequest());
      const initialUrl = registry.get("AutoConfigURL");
      if (!initialUrl) {
        throw new Error("Initial PAC URL was not registered.");
      }
      const initialResponse = fakeServer.request(initialUrl);

      for (let revision = 1; revision <= 4; revision += 1) {
        await manager.apply({ ...pacRequest(), rules: [routingRule(`revision-${revision}.example`)] });
      }

      expect(fakeServer.request(initialUrl)).toEqual(initialResponse);
      expect(fakeServer.request(initialUrl).statusCode).toBe(200);

      for (let revision = 5; revision <= 9; revision += 1) {
        await manager.apply({ ...pacRequest(), rules: [routingRule(`revision-${revision}.example`)] });
      }
      const staleResponse = fakeServer.request(initialUrl);
      expect(staleResponse.statusCode).toBe(200);
      expect(staleResponse.body).toContain("revision-9.example");
    } finally {
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("falls back to current PAC content after switching a process endpoint to stable versioned routing", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-process-to-stable-"));
    const fakeServer = new FakePacServer();
    const manager = createManager(directory, fakeServer);
    try {
      await manager.apply({ ...pacRequest(), forcePacEndpointRotation: true });
      await manager.apply({ ...pacRequest(), rules: [routingRule("stable-zero.example")] });
      const firstStableUrl = registry.get("AutoConfigURL");
      if (!firstStableUrl) {
        throw new Error("Initial stable PAC URL was not registered.");
      }
      expect(firstStableUrl).toContain("?v=");

      for (let revision = 1; revision <= 10; revision += 1) {
        await manager.apply({ ...pacRequest(), rules: [routingRule(`stable-${revision}.example`)] });
      }

      const staleResponse = fakeServer.request(firstStableUrl);
      expect(staleResponse.statusCode).toBe(200);
      expect(staleResponse.body).toContain("stable-10.example");
      expect(staleResponse.body).not.toContain("stable-zero.example");
    } finally {
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("fully reasserts PAC mode after a partial static-proxy mutation", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-dirty-"));
    const fakeServer = new FakePacServer();
    const manager = createManager(directory, fakeServer);
    try {
      await manager.apply(pacRequest());
      failCommand = (command, args) => command.toLowerCase() === "reg.exe" && isRegDelete(args, "AutoConfigURL");

      await expect(manager.apply(staticRequest())).rejects.toThrow(/reg\.exe/u);
      expect(registry.get("ProxyEnable")).toBe("1");
      expect(registry.get("ProxyServer")).toContain("127.0.0.1:1080");

      failCommand = undefined;
      await manager.apply(pacRequest());

      expect(registry.get("ProxyEnable")).toBe("0");
      expect(registry.has("ProxyServer")).toBe(false);
      expect(registry.get("AutoDetect")).toBe("0");
      expect(registry.get("AutoConfigURL")).toMatch(/^http:\/\/127\.0\.0\.1:/u);
    } finally {
      failCommand = undefined;
      await manager.restore().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("retains the PAC URL written to registry when WinINet notification fails", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-notify-failure-"));
    const fakeServer = new FakePacServer();
    const manager = createManager(directory, fakeServer);
    try {
      await manager.apply(pacRequest());
      failCommand = (command) => command.toLowerCase() === "powershell.exe";

      await expect(manager.apply({ ...pacRequest(), rules: [routingRule("written.example")] })).rejects.toThrow(/powershell\.exe/u);
      const writtenUrl = registry.get("AutoConfigURL");
      if (!writtenUrl) {
        throw new Error("PAC URL was not written before notification failed.");
      }
      const writtenResponse = fakeServer.request(writtenUrl);
      expect(writtenResponse.body).toContain("written.example");

      failCommand = (command, args) =>
        command.toLowerCase() === "reg.exe" &&
        args[0]?.toLowerCase() === "add" &&
        valueAfter(args, "/v") === "AutoConfigURL";
      for (let revision = 1; revision <= 10; revision += 1) {
        await expect(
          manager.apply({ ...pacRequest(), rules: [routingRule(`failed-${revision}.example`)] })
        ).rejects.toThrow(/reg\.exe/u);
      }

      expect(registry.get("AutoConfigURL")).toBe(writtenUrl);
      expect(fakeServer.request(writtenUrl)).toEqual(writtenResponse);
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

  it.each([
    "<local>",
    "*;<local>;legacy-corporate.example"
  ])("clears inherited ProxyOverride %s during static proxy-all and restores it exactly", async (proxyOverride) => {
    registry.set("ProxyOverride", proxyOverride);
    const directory = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-static-override-"));
    const manager = new WindowsSystemProxyManager({ pacDirectory: directory });
    try {
      await manager.apply(staticRequest());

      expect(registry.get("ProxyEnable")).toBe("1");
      expect(registry.get("ProxyServer")).toBe(
        "http=127.0.0.1:1080;https=127.0.0.1:1080;socks=127.0.0.1:1080"
      );
      expect(registry.has("ProxyOverride")).toBe(false);

      await manager.restore();

      expect(registry.get("ProxyOverride")).toBe(proxyOverride);
      expect(registry.get("ProxyServer")).toBe("corp.proxy:8080");
      expect(registry.get("AutoConfigURL")).toBe("https://corp.example/proxy.pac");
    } finally {
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
      const powerShellCommands = childProcessMocks.execFile.mock.calls
        .filter(([command]) => command.toLowerCase() === "powershell.exe")
        .flatMap(([, args]) => args);
      expect(powerShellCommands.join(" ")).toContain("InternetSetOption([IntPtr]::Zero, 95");
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

  it("retries crash-journal persistence before mutating proxy state", async () => {
    const parent = await mkdtemp(path.join(os.tmpdir(), "shadow-ssh-pac-journal-retry-"));
    const directory = path.join(parent, "routing");
    await writeFile(directory, "blocks directory creation", "utf8");
    const manager = new WindowsSystemProxyManager({ pacDirectory: directory });
    try {
      await expect(manager.apply(staticRequest())).rejects.toThrow();
      expect(registry.get("ProxyServer")).toBe("corp.proxy:8080");

      await rm(directory, { force: true });
      await manager.apply(staticRequest());

      expect(await readFile(path.join(directory, "windows-proxy-snapshot.json"), "utf8")).toContain("journalVersion");
      expect(registry.get("ProxyServer")).toContain("127.0.0.1:1080");
    } finally {
      await manager.restore().catch(() => undefined);
      await rm(parent, { recursive: true, force: true });
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

function routingRule(value = "example.com"): RoutingRule {
  return {
    id: "rule",
    type: "domain",
    value,
    enabled: true,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z"
  };
}

function createManager(directory: string, server: FakePacServer): WindowsSystemProxyManager {
  return new WindowsSystemProxyManager({
    pacDirectory: directory,
    pacServerFactory: (listener) => {
      server.setRequestListener(listener);
      return server as unknown as Server;
    }
  });
}

function createRotatingManager(directory: string, servers: FakePacServer[]): WindowsSystemProxyManager {
  let nextServer = 0;
  return new WindowsSystemProxyManager({
    pacDirectory: directory,
    pacServerFactory: (listener) => {
      const server = servers[nextServer];
      nextServer += 1;
      if (!server) {
        throw new Error("No fake PAC server is available for endpoint rotation.");
      }
      server.setRequestListener(listener);
      return server as unknown as Server;
    }
  });
}

class FakePacServer extends EventEmitter {
  listening = false;
  listenCalls = 0;
  closeCalls = 0;
  private requestListener: RequestListener | undefined;

  constructor(readonly port = 31_080) {
    super();
  }

  setRequestListener(listener: RequestListener): void {
    this.requestListener = listener;
  }

  request(url: string): { statusCode: number; body: string } {
    if (!this.requestListener) {
      throw new Error("PAC request listener is unavailable.");
    }
    let statusCode = 200;
    let body = "";
    const response = {
      writeHead(code: number) {
        statusCode = code;
        return response;
      },
      end(chunk?: string) {
        body += chunk ?? "";
        return response;
      }
    };
    const parsed = new URL(url);
    this.requestListener(
      { url: `${parsed.pathname}${parsed.search}` } as IncomingMessage,
      response as unknown as ServerResponse
    );
    return { statusCode, body };
  }

  listen(_port: number, _host: string, callback: () => void): this {
    this.listenCalls += 1;
    this.listening = true;
    callback();
    return this;
  }

  address(): { address: string; family: string; port: number } | null {
    return this.listening ? { address: "127.0.0.1", family: "IPv4", port: this.port } : null;
  }

  close(callback?: (error?: Error) => void): this {
    this.closeCalls += 1;
    this.listening = false;
    callback?.();
    return this;
  }

  closeAllConnections(): void {}

  closeIdleConnections(): void {}
}
