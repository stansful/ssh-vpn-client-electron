import { createDefaultRuntimeStatus, createDefaultStore } from "../src/shared/defaults.js";
import type { AppSnapshot, RuntimeStatus } from "../src/shared/types.js";

/** A complete, empty snapshot for renderer unit tests. */
export function createTestSnapshot(overrides: Partial<AppSnapshot> = {}): AppSnapshot {
  return {
    store: createDefaultStore(),
    runtime: createTestRuntime(),
    activeTransport: "ssh",
    diagnostics: [],
    attention: [],
    terminal: [],
    logFilePaths: [],
    tunnelCheckRunning: false,
    storageHealth: { state: "ok" },
    tunStatus: {
      supported: false,
      enabled: false,
      elevated: false,
      wintunFound: false,
      searchedPaths: [],
      active: false,
      appliesOnNextConnect: false
    },
    environment: {
      version: "2.2.0",
      platform: "windows",
      arch: "x64",
      dataDirectory: "C:\\Users\\test\\AppData\\Roaming\\Shadow SSH",
      logDirectory: "C:\\Users\\test\\AppData\\Roaming\\Shadow SSH\\logs",
      secretsBackend: "Windows DPAPI",
      isDevBuild: true
    },
    ...overrides
  };
}

export function createTestRuntime(overrides: Partial<RuntimeStatus> = {}): RuntimeStatus {
  return {
    ...createDefaultRuntimeStatus({
      platform: "windows",
      arch: "x64",
      serviceExecutableName: "shadow-ssh-service.exe",
      serviceRelativePath: "native/windows/x64/shadow-ssh-service.exe",
      supportsPrivilegedService: true
    }),
    transport: "live-ssh",
    realTunnelAvailable: true,
    message: "Disconnected.",
    ...overrides
  };
}
