import { mkdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const serviceDir = path.join(root, "native", "service-go");
const targets = [
  { goos: "windows", goarch: "amd64", out: path.join(root, "native", "windows", "x64", "shadow-ssh-service.exe") },
  { goos: "windows", goarch: "arm64", out: path.join(root, "native", "windows", "arm64", "shadow-ssh-service.exe") },
  { goos: "darwin", goarch: "amd64", out: path.join(root, "native", "macos", "x64", "shadow-ssh-service") },
  { goos: "darwin", goarch: "arm64", out: path.join(root, "native", "macos", "arm64", "shadow-ssh-service") },
  { goos: "linux", goarch: "amd64", out: path.join(root, "native", "linux", "x64", "shadow-ssh-service") },
  { goos: "linux", goarch: "arm64", out: path.join(root, "native", "linux", "arm64", "shadow-ssh-service") }
];

for (const target of targets) {
  await mkdir(path.dirname(target.out), { recursive: true });
  await run("go", ["build", "-trimpath", "-ldflags", "-s -w", "-o", target.out, "./cmd/shadow-ssh-service"], {
    cwd: serviceDir,
    env: {
      ...process.env,
      CGO_ENABLED: "0",
      GOOS: target.goos,
      GOARCH: target.goarch
    }
  });
  console.log(`built ${path.relative(root, target.out)}`);
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
