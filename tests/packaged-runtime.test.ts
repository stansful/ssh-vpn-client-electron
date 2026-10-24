import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  appIdentity,
  BUILD_CHANNEL_METADATA_FIELD,
  isInsecureSecretFallbackAllowed,
  PACKAGED_IGNORED_ENVIRONMENT_VARIABLES,
  readAppPackageMetadata,
  removeDeveloperOverrides,
  resolveBuildChannel
} from "../src/main/app/packaged-runtime.js";

describe("build channel", () => {
  it("takes a packaged build's channel from its package.json, never from the environment", () => {
    const env = { SHADOW_SSH_BUILD_CHANNEL: "development" };
    expect(resolveBuildChannel({ packaged: true, packageMetadata: { shadowBuildChannel: "development" }, env: {} })).toBe("development");
    expect(resolveBuildChannel({ packaged: true, packageMetadata: { shadowBuildChannel: "production" }, env })).toBe("production");
    expect(resolveBuildChannel({ packaged: true, packageMetadata: { name: "shadow-ssh-desktop" }, env })).toBe("production");
    expect(resolveBuildChannel({ packaged: true, packageMetadata: undefined, env })).toBe("production");
  });

  it("keeps the environment switch for unpackaged runs", () => {
    expect(resolveBuildChannel({ packaged: false, env: { SHADOW_SSH_BUILD_CHANNEL: "development" } })).toBe("development");
    expect(resolveBuildChannel({ packaged: false, packageMetadata: { shadowBuildChannel: "development" }, env: {} })).toBe("production");
  });

  it("gives the dev channel its own data folder, keychain entry and lock name", () => {
    expect(appIdentity("development")).toEqual({ systemName: "Shadow SSH Dev", displayName: "Shadow Dev" });
    expect(appIdentity("production")).toEqual({ systemName: "Shadow SSH", displayName: "Shadow" });
  });

  it("reads package.json from the app path and tolerates a missing or broken one", () => {
    const read = (filePath: string): string => {
      expect(filePath).toBe(path.join("/app/resources/app.asar", "package.json"));
      return JSON.stringify({ shadowBuildChannel: "development" });
    };
    expect(readAppPackageMetadata("/app/resources/app.asar", read)).toEqual({ shadowBuildChannel: "development" });
    expect(readAppPackageMetadata("/missing", () => {
      throw new Error("ENOENT");
    })).toBeUndefined();
    expect(readAppPackageMetadata("/broken", () => "{")).toBeUndefined();
  });

  it("is baked in by the packaging script and read the same way by the CommonJS bootstrap", () => {
    const wrapper = readFileSync("scripts/electron-builder-with-local-dist.mjs", "utf8");
    expect(wrapper).toContain(`--config.extraMetadata.${BUILD_CHANNEL_METADATA_FIELD}=`);
    expect(wrapper).toContain('isShadowDevBuild ? "development" : "production"');
    const bootstrap = readFileSync("src/main/bootstrap.cts", "utf8");
    expect(bootstrap).toContain(`metadata.${BUILD_CHANNEL_METADATA_FIELD} === "development"`);
    expect(bootstrap).toContain("app.isPackaged");
  });

  it("runs `npm run dev` as the regular app unless the dev channel is asked for", () => {
    // Unpackaged, only the environment names the channel. `npm run dev` leaves
    // it unset, so it keeps the existing "Shadow SSH" data folder and
    // safe-storage key; setting the variable by hand still switches it.
    const manifest = JSON.parse(readFileSync("package.json", "utf8")) as { scripts: Record<string, string> };
    const electronRun = manifest.scripts.dev.split("&&").find((part) => /\belectron \./u.test(part)) ?? "";
    expect(electronRun).toContain("electron .");
    expect(electronRun).not.toContain("SHADOW_SSH_BUILD_CHANNEL");
    expect(resolveBuildChannel({ packaged: false, env: {} })).toBe("production");
    expect(appIdentity(resolveBuildChannel({ packaged: false, env: {} })).systemName).toBe("Shadow SSH");
    expect(resolveBuildChannel({ packaged: false, env: { SHADOW_SSH_BUILD_CHANNEL: "development" } })).toBe("development");
  });
});

describe("developer overrides", () => {
  it("removes every developer switch from a packaged build's environment", () => {
    const env: NodeJS.ProcessEnv = {
      PATH: "/usr/bin",
      SHADOW_SSH_USER_DATA_DIR: "/profiles/second",
      VITE_DEV_SERVER_URL: "http://evil.example/",
      SHADOW_SSH_XRAY_PATH: "/tmp/not-xray",
      SHADOW_SSH_SERVICE_ENDPOINT: "\\\\.\\pipe\\evil",
      SHADOW_SSH_USE_NATIVE_PROCESS_SERVICE: "1",
      SHADOW_SSH_SERVICE_TOKEN: "token",
      SHADOW_SSH_ALLOW_INSECURE_SECRET_FALLBACK: "1",
      SHADOW_SSH_BUILD_CHANNEL: "development"
    };

    const removed = removeDeveloperOverrides(env, true);

    expect(removed.sort()).toEqual([...PACKAGED_IGNORED_ENVIRONMENT_VARIABLES].sort());
    expect(env).toEqual({ PATH: "/usr/bin", SHADOW_SSH_USER_DATA_DIR: "/profiles/second" });
  });

  it("leaves an unpackaged run's environment alone", () => {
    const env: NodeJS.ProcessEnv = { VITE_DEV_SERVER_URL: "http://127.0.0.1:5173", SHADOW_SSH_XRAY_PATH: "/opt/xray" };
    expect(removeDeveloperOverrides(env, false)).toEqual([]);
    expect(env).toEqual({ VITE_DEV_SERVER_URL: "http://127.0.0.1:5173", SHADOW_SSH_XRAY_PATH: "/opt/xray" });
    expect(removeDeveloperOverrides({}, true)).toEqual([]);
  });

  it("allows the insecure secret fallback only to an unpackaged run that asks for it", () => {
    expect(isInsecureSecretFallbackAllowed(false, { SHADOW_SSH_ALLOW_INSECURE_SECRET_FALLBACK: "1" })).toBe(true);
    expect(isInsecureSecretFallbackAllowed(undefined, { SHADOW_SSH_ALLOW_INSECURE_SECRET_FALLBACK: "1" })).toBe(true);
    expect(isInsecureSecretFallbackAllowed(true, { SHADOW_SSH_ALLOW_INSECURE_SECRET_FALLBACK: "1" })).toBe(false);
    expect(isInsecureSecretFallbackAllowed(false, {})).toBe(false);
  });
});
