import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const serviceDir = path.join(root, "native", "service-go");
const goCacheDir = path.join(root, ".cache", "go-build");

await mkdir(goCacheDir, { recursive: true });

await run("go", ["test", "./..."], { cwd: serviceDir, env: createGoEnv() });

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
