export type FetchImplementation = (input: string, init?: RequestInit) => Promise<Response>;

export interface FetchTextWithLimitOptions {
  fetchImpl?: FetchImplementation;
  url: string;
  headers?: Record<string, string>;
  maxBytes: number;
  timeoutMs: number;
  failureMessagePrefix: string;
  limitMessage: string;
  timeoutMessage: string;
}

/** Fetches bounded text without buffering an untrusted response before enforcing its limit. */
export async function fetchTextWithLimit(options: FetchTextWithLimitOptions): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(new Error(options.timeoutMessage)),
    normalizePositiveNumber(options.timeoutMs, 15_000)
  );
  timeout.unref();

  try {
    const response = await (options.fetchImpl ?? globalThis.fetch)(options.url, {
      signal: controller.signal,
      // These calls explicitly refresh user-managed lists. Avoid writing a
      // second Chromium/undici cache copy before the bounded payload is stored.
      headers: {
        ...options.headers,
        "Cache-Control": "no-store",
        Pragma: "no-cache"
      }
    });
    if (!response.ok) {
      throw new Error(`${options.failureMessagePrefix}: ${response.status} ${response.statusText}`);
    }
    return await readResponseTextWithLimit(response, options.maxBytes, options.limitMessage);
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error(options.timeoutMessage, { cause: error });
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

export async function readResponseTextWithLimit(response: Response, maxBytes: number, limitMessage: string): Promise<string> {
  const limit = normalizePositiveNumber(maxBytes, 1);
  const contentLength = parseContentLength(response.headers.get("content-length"));
  if (contentLength !== undefined && contentLength > limit) {
    await response.body?.cancel(limitMessage).catch(() => undefined);
    throw new Error(limitMessage);
  }
  if (!response.body) {
    return "";
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  let totalBytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    if (!value || value.byteLength === 0) {
      continue;
    }
    totalBytes += value.byteLength;
    if (totalBytes > limit) {
      await reader.cancel(limitMessage).catch(() => undefined);
      throw new Error(limitMessage);
    }
    chunks.push(decoder.decode(value, { stream: true }));
  }
  chunks.push(decoder.decode());
  return chunks.join("");
}

function parseContentLength(value: string | null): number | undefined {
  if (!value) {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined;
}

function normalizePositiveNumber(value: number, fallback: number): number {
  return Number.isFinite(value) && value > 0 ? value : fallback;
}
