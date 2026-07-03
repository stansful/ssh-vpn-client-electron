import { type ChildProcessByStdio } from "node:child_process";
import net from "node:net";
import type { Readable } from "node:stream";

export type XrayProcess = ChildProcessByStdio<null, Readable, Readable>;

export async function reserveLocalTcpPort(): Promise<{ host: string; port: number }> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  if (typeof address !== "object" || !address) {
    throw new Error("Unable to reserve a local TCP port for Xray.");
  }
  return { host: "127.0.0.1", port: address.port };
}

export function waitForProcessStartup(processHandle: XrayProcess): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, 700);
    timer.unref();

    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };
    const onExit = (code: number | null, signal: NodeJS.Signals | null): void => {
      cleanup();
      reject(new Error(`Xray runtime exited during startup${code === null ? "" : ` with code ${code}`}${signal ? ` signal ${signal}` : ""}.`));
    };
    const cleanup = (): void => {
      clearTimeout(timer);
      processHandle.off("error", onError);
      processHandle.off("exit", onExit);
    };

    processHandle.once("error", onError);
    processHandle.once("exit", onExit);
  });
}

export async function terminateProcess(processHandle: XrayProcess): Promise<void> {
  if (processHandle.exitCode !== null || processHandle.signalCode !== null) {
    return;
  }
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      processHandle.kill("SIGKILL");
    }, 1500);
    timer.unref();
    processHandle.once("close", () => {
      clearTimeout(timer);
      resolve();
    });
    processHandle.kill("SIGTERM");
  });
}
