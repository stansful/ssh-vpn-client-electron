import { GITHUB_REPOSITORY_URL, ROUTING_DOMAIN_LIST_SOURCE_URL } from "../../shared/links.js";

const EXACT_URLS = [GITHUB_REPOSITORY_URL, ROUTING_DOMAIN_LIST_SOURCE_URL].map((allowed) => new URL(allowed));
const REPOSITORY = new URL(GITHUB_REPOSITORY_URL);
const RELEASES_PATH = `${REPOSITORY.pathname.replace(/\/$/u, "")}/releases`;

/**
 * The only pages the renderer may open in the browser: the repository, the
 * domain list source, and this repository's release pages (Settings →
 * Updates links the exact release). Returns the normalized URL or throws.
 */
export function assertAllowedExternalUrl(value: string): string {
  const url = new URL(value);
  const requestedPath = url.pathname.replace(/\/$/u, "");
  const isReleasePage =
    url.hostname === REPOSITORY.hostname && (requestedPath === RELEASES_PATH || requestedPath.startsWith(`${RELEASES_PATH}/`));
  const allowed =
    url.protocol === "https:" &&
    !url.username &&
    !url.password &&
    (isReleasePage ||
      EXACT_URLS.some((candidate) => url.hostname === candidate.hostname && requestedPath === candidate.pathname.replace(/\/$/u, "")));
  if (!allowed) {
    throw new Error("External URL is not allowed.");
  }
  return url.toString();
}
