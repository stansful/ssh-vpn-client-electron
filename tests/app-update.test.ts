import { describe, expect, it } from "vitest";
import { compareSemver, normalizeVersion, selectWindowsPortableAsset } from "../src/core/update/github-app-update.js";

describe("portable app update metadata", () => {
  it("selects the matching Windows portable asset by version and architecture", () => {
    const asset = selectWindowsPortableAsset(
      {
        tag_name: "0.2.0",
        assets: [
          {
            name: "shadow-ssh-0.2.0-windows-portable-arm64.exe",
            size: 10,
            digest: "sha256:abc",
            browser_download_url: "https://github.com/stansful/ssh-vpn-client-electron/releases/download/0.2.0/shadow-ssh-0.2.0-windows-portable-arm64.exe"
          },
          {
            name: "shadow-ssh-0.2.0-windows-portable-x64.exe",
            size: 20,
            digest: "sha256:def",
            browser_download_url: "https://github.com/stansful/ssh-vpn-client-electron/releases/download/0.2.0/shadow-ssh-0.2.0-windows-portable-x64.exe"
          }
        ]
      },
      "0.2.0",
      "x64"
    );

    expect(asset).toMatchObject({
      name: "shadow-ssh-0.2.0-windows-portable-x64.exe",
      arch: "x64",
      size: 20,
      digest: "sha256:def"
    });
  });

  it("normalizes strict SemVer tags and compares versions", () => {
    expect(normalizeVersion("v1.2.3")).toBe("1.2.3");
    expect(normalizeVersion("1.2")).toBeUndefined();
    expect(compareSemver("1.3.0", "1.2.9")).toBeGreaterThan(0);
    expect(compareSemver("1.2.0", "1.2.0")).toBe(0);
  });
});
