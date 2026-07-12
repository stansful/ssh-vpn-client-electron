import { EventEmitter } from "node:events";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { describe, expect, it } from "vitest";
import { createDefaultRuntimeStatus } from "../src/shared/defaults.js";
import { encodeWireMessage, type NativeServiceCapabilities } from "../src/service/local-ipc-protocol.js";
import { NativeProcessServiceBridge } from "../src/service/native-process-client.js";

describe("NativeProcessServiceBridge shutdown", () => {
  it("allows deferred native cleanup after a rejected shutdown response before killing", async () => {
    const child = new FakeChildProcess();
    const Constructor = NativeProcessServiceBridge as unknown as new (
      child: ChildProcessWithoutNullStreams,
      status: ReturnType<typeof createDefaultRuntimeStatus>
    ) => NativeProcessServiceBridge;
    const bridge = new Constructor(
      child as unknown as ChildProcessWithoutNullStreams,
      createDefaultRuntimeStatus({
        platform: "linux",
        arch: "x64",
        serviceExecutableName: "shadow-ssh-service",
        serviceRelativePath: "native/linux/x64/shadow-ssh-service",
        supportsPrivilegedService: false
      })
    );
    (bridge as unknown as { send(): Promise<never> }).send = async () => {
      throw new Error("first routing cleanup failed");
    };

    const firstDispose = bridge.dispose();
    const secondDispose = bridge.dispose();
    expect(secondDispose).toBe(firstDispose);
    await firstDispose;

    expect(child.stdin.ended).toBe(true);
    expect(child.exitCode).toBe(0);
    expect(child.killCalls).toBe(0);
  });

  it("fails closed if a runtime event contradicts the capability handshake", () => {
    const child = new FakeChildProcess();
    const status = createDefaultRuntimeStatus({
      platform: "windows",
      arch: "x64",
      serviceExecutableName: "shadow-ssh-service.exe",
      serviceRelativePath: "native/windows/x64/shadow-ssh-service.exe",
      supportsPrivilegedService: true
    });
    const Constructor = NativeProcessServiceBridge as unknown as new (
      child: ChildProcessWithoutNullStreams,
      runtimeStatus: ReturnType<typeof createDefaultRuntimeStatus>
    ) => NativeProcessServiceBridge;
    const bridge = new Constructor(child as unknown as ChildProcessWithoutNullStreams, status);
    (bridge as unknown as { capabilities: NativeServiceCapabilities }).capabilities = {
      target: status.platformTarget,
      ipc: "stdio",
      namedPipeAcl: false,
      unixSocketMode: false,
      serviceControlManager: false,
      wfpInterception: false,
      tunDevice: false,
      routeManipulation: false,
      processConnectionAttribution: false,
      dnsVisibility: false,
      ipv6RouteEnforcement: false,
      udpForwarding: false,
      sshCoreLinked: false
    };

    child.stdout.emit("data", Buffer.from(encodeWireMessage({
      kind: "event",
      event: {
        type: "status-changed",
        status: { ...status, state: "Connected", realTunnelAvailable: true }
      }
    })));

    expect(child.killCalls).toBe(1);
    expect(bridge.getStatus()).toMatchObject({ state: "Error", realTunnelAvailable: false });
  });
});

class FakeChildProcess extends EventEmitter {
  readonly stdout = new EventEmitter();
  readonly stderr = new EventEmitter();
  readonly stdin = new FakeInput(() => this.exitNaturally());
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  killed = false;
  killCalls = 0;

  kill(): boolean {
    this.killCalls += 1;
    this.killed = true;
    return true;
  }

  private exitNaturally(): void {
    setImmediate(() => {
      this.exitCode = 0;
      this.emit("exit", 0, null);
    });
  }
}

class FakeInput extends EventEmitter {
  ended = false;

  constructor(private readonly onEnd: () => void) {
    super();
  }

  end(): this {
    this.ended = true;
    this.onEnd();
    return this;
  }
}
