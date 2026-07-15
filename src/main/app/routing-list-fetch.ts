import { fetchTextWithLimit, type FetchImplementation } from "../../shared/http-fetch.js";

export interface RoutingListFetchOptions {
  fetchImpl?: FetchImplementation;
  maxBytes?: number;
  timeoutMs?: number;
}

export const DEFAULT_ROUTING_LIST_MAX_BYTES = 2 * 1024 * 1024;
export const DEFAULT_ROUTING_LIST_TIMEOUT_MS = 15_000;

/**
 * Routing lists are control-plane data. Node's fetch is deliberately the
 * default so the request cannot loop through the system PAC/proxy that the
 * downloaded list itself is used to configure.
 */
export function fetchRoutingListText(url: string, options: RoutingListFetchOptions = {}): Promise<string> {
  return fetchTextWithLimit({
    fetchImpl: options.fetchImpl ?? globalThis.fetch,
    url,
    headers: { "User-Agent": "shadow-ssh-desktop-routing-list" },
    maxBytes: options.maxBytes ?? DEFAULT_ROUTING_LIST_MAX_BYTES,
    timeoutMs: options.timeoutMs ?? DEFAULT_ROUTING_LIST_TIMEOUT_MS,
    failureMessagePrefix: "Routing list download failed",
    limitMessage: "Routing list is larger than the allowed limit.",
    timeoutMessage: "Routing list download timed out."
  });
}
