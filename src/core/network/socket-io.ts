import type net from "node:net";

export interface SocketWriteOptions {
  timeoutMs?: number;
}

export interface SocketTuningOptions {
  keepAlive?: boolean;
  keepAliveInitialDelayMs?: number;
}

// One busy download can still consume the complete SSH receive window, while
// many stalled local consumers cannot retain hundreds of MiB in aggregate.
export const DEFAULT_PROXY_CONNECTION_QUEUE_BYTES = 16 * 1024 * 1024;
export const DEFAULT_PROXY_TOTAL_QUEUE_BYTES = 64 * 1024 * 1024;

export function configureLowLatencySocket(socket: net.Socket, options: SocketTuningOptions = {}): void {
  socket.setNoDelay(true);
  // Loopback proxy sockets do not benefit from kernel keepalive probes: both
  // endpoints live in the same OS and already have an application idle
  // deadline. For the remote SSH socket keep probes, but start them late enough
  // that they do not duplicate the protocol keepalive on every short idle.
  const keepAlive = options.keepAlive ?? true;
  socket.setKeepAlive(keepAlive, keepAlive ? options.keepAliveInitialDelayMs ?? 120_000 : 0);
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
    try {
      const accepted = socket.write(data);
      if (accepted) {
        finish();
      } else {
        socket.once("drain", onDrain);
      }
    } catch (error) {
      finish(error instanceof Error ? error : new Error(String(error)));
    }
  });
}
