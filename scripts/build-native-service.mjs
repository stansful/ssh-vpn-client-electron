import { access, mkdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const serviceDir = path.join(root, "native", "service-go");
const goCacheDir = path.join(root, ".cache", "go-build");
const targets = [
  { goos: "windows", goarch: "amd64", out: path.join(root, "native", "windows", "x64", "shadow-ssh-service.exe") },
  { goos: "windows", goarch: "arm64", out: path.join(root, "native", "windows", "arm64", "shadow-ssh-service.exe") },
  { goos: "darwin", goarch: "amd64", out: path.join(root, "native", "macos", "x64", "shadow-ssh-service") },
  { goos: "darwin", goarch: "arm64", out: path.join(root, "native", "macos", "arm64", "shadow-ssh-service") },
  { goos: "linux", goarch: "amd64", out: path.join(root, "native", "linux", "x64", "shadow-ssh-service") },
  { goos: "linux", goarch: "arm64", out: path.join(root, "native", "linux", "arm64", "shadow-ssh-service") }
];

await mkdir(goCacheDir, { recursive: true });

for (const target of targets) {
  await mkdir(path.dirname(target.out), { recursive: true });
  await run("go", ["build", "-trimpath", "-ldflags", "-s -w", "-o", target.out, "./cmd/shadow-ssh-service"], {
    cwd: serviceDir,
    env: createGoEnv({
      CGO_ENABLED: "0",
      GOOS: target.goos,
      GOARCH: target.goarch
    })
  });
  console.log(`built ${path.relative(root, target.out)}`);
}

await warnAboutMissingWintun();

/**
 * The portable target unpacks into a fresh %TEMP% directory at every launch, so
 * `wintun.dll` has to be in the tree *before* packaging - a user cannot add it
 * to the packaged resources afterwards. Saying so here is the last moment
 * anyone can act on it cheaply.
 */
async function warnAboutMissingWintun() {
  const missing = [];
  for (const arch of ["x64", "arm64"]) {
    const dll = path.join(root, "native", "windows", arch, "wintun.dll");
    try {
      await access(dll);
    } catch {
      missing.push(path.relative(root, dll));
    }
  }
  if (missing.length === 0) {
    return;
  }
  console.warn(
    `\nwarning: TUN routing will be unavailable in this build - wintun.dll is missing:\n` +
      missing.map((entry) => `  ${entry}`).join("\n") +
      `\nDownload it from https://www.wintun.net/ and place it there before packaging.\n` +
      `Users of the built app can also drop it beside the portable .exe or in the app data folder.\n`
  );
}

function createGoEnv(extra = {}) {
  const env = { ...process.env };
  delete env.GOROOT;
  delete env.GOTOOLDIR;
  return { ...env, GOCACHE: goCacheDir, ...extra };
}

function run(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} ${args.join(" ")} exited with ${code}`));
      }
    });
  });
}
