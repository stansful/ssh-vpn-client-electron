import type net from "node:net";

export interface SocketWriteOptions {
  timeoutMs?: number;
}

export function configureLowLatencySocket(socket: net.Socket): void {
  socket.setNoDelay(true);
  socket.setKeepAlive(true, 30_000);
}

export function isSocketWritable(socket: net.Socket): boolean {
  return !socket.destroyed && socket.writable && !socket.writableEnded;
}

export async function writeSocketWithBackpressure(socket: net.Socket, data: Buffer, options: SocketWriteOptions = {}): Promise<void> {
  if (data.length === 0) {
    return;
  }
  if (!isSocketWritable(socket)) {
    throw new Error("Socket is not writable.");
  }

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const timeoutMs = options.timeoutMs ?? 120_000;
    const timer = timeoutMs > 0
      ? setTimeout(() => finish(new Error("Socket write timed out.")), timeoutMs)
      : undefined;
    timer?.unref();

    const cleanup = (): void => {
      if (timer) {
        clearTimeout(timer);
      }
      socket.off("drain", onDrain);
      socket.off("error", onError);
      socket.off("close", onClose);
    };
    const finish = (error?: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    };
    const onDrain = (): void => finish();
    const onError = (error: Error): void => finish(error);
    const onClose = (): void => finish(new Error("Socket closed while writing proxied data."));

    socket.once("error", onError);
    socket.once("close", onClose);
    const accepted = socket.write(data);
    if (accepted) {
      finish();
    } else {
      socket.once("drain", onDrain);
    }
  });
}
