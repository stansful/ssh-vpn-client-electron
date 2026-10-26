import { readdirSync, readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { updateAssetFileName } from "../src/core/update/github-app-update.js";
import type { AppUpdateFormat } from "../src/shared/types.js";

const buildScript = readFileSync("scripts/build-release.sh", "utf8");
const releaseWorkflow = readFileSync(".github/workflows/release.yml", "utf8");
const ciWorkflow = readFileSync(".github/workflows/ci.yml", "utf8");
const releaseState = readFileSync(".github/scripts/release-state.sh", "utf8");
const FORMATS: AppUpdateFormat[] = ["windows-portable", "macos-dmg", "linux-appimage", "linux-deb"];

/** ASSET_SUFFIXES="…" of scripts/build-release.sh. */
function builtSuffixes(): string[] {
  const match = /^ASSET_SUFFIXES="([^"]*)"$/mu.exec(buildScript);
  return match ? match[1].split(/\s+/u).filter(Boolean) : [];
}

/** The folded ASSET_SUFFIXES: >- block of release.yml's env. */
function publishedSuffixes(): string[] {
  const lines = releaseWorkflow.split("\n");
  const start = lines.indexOf("  ASSET_SUFFIXES: >-");
  if (start < 0) {
    return [];
  }
  const block: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (!line.startsWith("    ")) {
      break;
    }
    block.push(...line.trim().split(/\s+/u));
  }
  return block;
}

// What a release publishes is decided in three places: the build checks its
// output, release.yml uploads and checks the draft, the in-app updater picks a
// file by name. A file one of them does not know is a release nobody can update to.
describe("release assets", () => {
  it("build-release.sh builds what release.yml publishes", () => {
    expect(builtSuffixes()).toHaveLength(8);
    expect(publishedSuffixes()).toEqual(builtSuffixes());
  });

  it("every published file is a name the in-app updater downloads, and every name it downloads is published", () => {
    const version = "9.8.7";
    const updaterNames = FORMATS.flatMap((format) =>
      (["x64", "arm64"] as const).map((arch) => updateAssetFileName(version, format, arch))
    ).sort();
    const built = builtSuffixes().map((suffix) => `shadow-ssh-${version}-${suffix}`).sort();
    expect(built).toEqual(updaterNames);
  });

  it("verify-production-artifacts expects the same eight distributables", () => {
    const plan = spawnSync(process.execPath, ["scripts/lib/verify-production-artifacts.mjs", "--plan"], { encoding: "utf8" });
    expect(plan.status, plan.stderr).toBe(0);
    const version = JSON.parse(readFileSync("package.json", "utf8")).version as string;
    for (const suffix of builtSuffixes()) {
      expect(plan.stdout).toContain(`shadow-ssh-${version}-${suffix}`);
    }
  });

  it("build-release.sh refuses files above the updater's 160 MiB", () => {
    expect(buildScript).toMatch(/^MAX_ASSET_BYTES=167772160$/mu);
    expect(167772160).toBe(160 * 1024 * 1024);
    expect(readFileSync("src/core/update/github-app-update.ts", "utf8")).toContain(
      "const MAX_UPDATE_DOWNLOAD_BYTES = 160 * 1024 * 1024;"
    );
  });
});

describe("release workflows", () => {
  it("release.yml builds with scripts/build-release.sh after the whole CI", () => {
    expect(releaseWorkflow).toMatch(/^ {8}run: scripts\/build-release\.sh$/mu);
    expect(releaseWorkflow).toContain("    uses: ./.github/workflows/ci.yml");
    expect(releaseWorkflow).toMatch(/^ {4}needs: \[gate, quality\]$/mu);
    const commands = releaseWorkflow.split("\n").filter((line) => !/^\s*#/u.test(line));
    expect(commands.filter((line) => line.includes("build:prod"))).toEqual([]);
  });

  it("a push to master runs release.yml only, ci.yml runs for the other branches and pull requests", () => {
    expect(releaseWorkflow).toMatch(/^ {4}branches: \[master\]$/mu);
    expect(ciWorkflow).toMatch(/^ {4}branches-ignore: \[master\]$/mu);
    expect(ciWorkflow).toMatch(/^ {2}workflow_call:$/mu);
    expect(ciWorkflow).toMatch(/^ {2}pull_request:$/mu);
  });

  it("the release and its tag are the plain version X.Y.Z", () => {
    expect(releaseWorkflow).toContain('-f tag_name="$VERSION"');
    expect(releaseWorkflow).not.toMatch(/"v\$VERSION"|tag_name="v/u);
  });

  // The release list lags behind a draft created a moment ago: the publish job
  // takes the draft's id from the create call and never looks the draft up there.
  it("publish works with the id the API returns for the new draft", () => {
    expect(releaseWorkflow).toContain('id=$(gh api -X POST "repos/$GH_REPO/releases"');
    expect(releaseWorkflow).toContain("-F draft=true --jq .id)");
    expect(releaseWorkflow).not.toMatch(/gh release (create|upload)|^ *id=\$\(gh api --paginate/mu);
  });

  // `git ls-remote` given a pattern leaves out an annotated tag's peeled line:
  // the publish job would read the tag object, not the commit release-state.sh accepted.
  it("release.yml checks the tag's commit the way release-state.sh reads it", () => {
    expect(releaseWorkflow).toContain("refs=$(git ls-remote --tags origin) && break");
    expect(releaseWorkflow).toContain('tag_sha=$(tag_commit "$VERSION" <<<"$refs")');
    expect(releaseState).toContain('tag_sha="$(tag_commit "$VERSION" <<<"$refs")"');
    expect(releaseState).toContain('refs="$(git -C "$ROOT" ls-remote --tags origin)"');
    expect(`${releaseWorkflow}\n${releaseState}`).not.toMatch(/ls-remote[^|\n]*refs\/tags/u);
  });

  it("CI lints the release scripts and runs their tests under bash 5 and macOS's bash 3.2", () => {
    expect(ciWorkflow).toContain("scripts/*.sh scripts/lib/*.sh .github/scripts/*.sh tests/release/*.sh");
    expect(ciWorkflow.match(/^ {8}run: tests\/release\/run\.sh$/gmu)).toHaveLength(2);
    expect(ciWorkflow).toContain("TEST_BASH: /bin/bash");
  });

  // macOS's bash 3.2 in a UTF-8 locale reads the first byte of «» as part of a
  // name: "«$v»" is the variable "v\xC2", unbound under set -u. ${v} is safe.
  it("no shell variable runs into a non-ASCII character", () => {
    const dirs = ["scripts", "scripts/lib", ".github/scripts", ".github/workflows", "tests/release"];
    const offenders = dirs.flatMap((dir) =>
      readdirSync(dir)
        .filter((name) => /\.(sh|ya?ml)$/u.test(name))
        .flatMap((name) =>
          readFileSync(`${dir}/${name}`, "utf8")
            .split("\n")
            .flatMap((line, index) => (/\$[A-Za-z_]\w*[^\p{ASCII}]/u.test(line) ? [`${dir}/${name}:${index + 1}`] : []))
        )
    );
    expect(offenders).toEqual([]);
  });

  it("the release scripts and their tests are executable", () => {
    const files = [
      "scripts/make-release.sh",
      "scripts/build-release.sh",
      ".github/scripts/release-state.sh",
      ".github/scripts/release-notes.sh",
      "tests/release/run.sh",
      "tests/release/make-release_test.sh",
      "tests/release/build-release_test.sh",
      "tests/release/release-state_test.sh",
      "tests/release/release-notes_test.sh"
    ];
    for (const file of files) {
      expect(statSync(file).mode & 0o111, file).not.toBe(0);
    }
  });
});
